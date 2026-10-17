import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Miniflare } from 'miniflare';

let mf;
let db;
let worker;
const migration = await readFile(new URL('../backend/migrations/0001_relay.sql', import.meta.url), 'utf8');
const workerSource = await readFile(new URL('../.local/worker.mjs', import.meta.url), 'utf8');

before(async () => {
  mf = new Miniflare({
    workers: [{
      config: {
        name: 'relay',
        compatibilityDate: '2026-10-17',
        manifest: {
          mainModule: 'worker.mjs',
          modules: { 'worker.mjs': { type: 'esm', contents: workerSource } },
        },
        env: { DB: { type: 'd1', name: 'test-db', id: 'test-db' } },
      },
      dev: { rootPath: process.cwd() },
    }],
  });
  db = await mf.getD1Database('DB');
  const statements = migration
    .replace(/^\s*--.*$/gm, '')
    .replace(/^\s*PRAGMA foreign_keys = ON;\s*$/gm, '')
    .split(';').map((statement) => statement.trim()).filter(Boolean);
  const triggerIndex = statements.findIndex((statement) => statement.startsWith('CREATE TRIGGER'));
  if (triggerIndex !== -1) {
    statements.splice(triggerIndex, statements.length - triggerIndex, statements.slice(triggerIndex).join(';') + ';');
  }
  for (const statement of statements) await db.prepare(statement).run();
  worker = await mf.getWorker();
});

after(async () => {
  await mf?.dispose();
});

async function makeDevice({ expiresAt = Math.floor(Date.now() / 1000) + 3600, revoked = false } = {}) {
  const id = randomUUID();
  const token = randomBytes(32).toString('base64url');
  const tokenHash = createHash('sha256').update(token).digest('hex');
  await db.prepare('INSERT INTO devices (id, token_hash, expires_at, revoked) VALUES (?, ?, ?, ?)')
    .bind(id, tokenHash, expiresAt, revoked ? 1 : 0).run();
  return { id, token };
}

async function makeGroup(deviceIds = []) {
  const id = randomUUID();
  await db.prepare('INSERT INTO groups (id) VALUES (?)').bind(id).run();
  for (const deviceId of deviceIds) {
    await db.prepare('INSERT INTO group_members (group_id, device_id) VALUES (?, ?)')
      .bind(id, deviceId).run();
  }
  return id;
}

async function fixture(options) {
  const device = await makeDevice(options);
  const groupId = await makeGroup([device.id]);
  return { ...device, groupId };
}

function groupUrl(groupId, query = '') {
  return 'http://relay.test/v1/groups/' + groupId + '/events' + query;
}

function authRequest(url, token, init = {}) {
  const headers = new Headers(init.headers);
  if (token) headers.set('authorization', 'Bearer ' + token);
  return new Request(url, { ...init, headers });
}

const bodyOf = (response) => response.json();

async function postEvent({ groupId, token, eventId = randomUUID(), expectedRevision = 0, ciphertext = 'Y2lwaGVydGV4dA==', extra = {}, rawBody, contentType = 'application/json', contentLength }) {
  const headers = new Headers();
  if (contentType !== null) headers.set('content-type', contentType);
  if (contentLength !== undefined) headers.set('content-length', String(contentLength));
  const body = rawBody ?? JSON.stringify({ eventId, expectedRevision, ciphertext, ...extra });
  return worker.fetch(authRequest(groupUrl(groupId), token, { method: 'POST', headers, body }));
}

test('GET /health is public and returns the DEV status payload', async () => {
  const response = await worker.fetch(new Request('http://relay.test/health'));
  assert.equal(response.status, 200);
  assert.deepEqual(await bodyOf(response), {
    service: 'squadtime-relay', status: 'ok', stage: 'dev', protocolVersion: 1,
  });
});

test('missing, malformed, expired, and revoked bearer credentials are rejected', async () => {
  const valid = await fixture();
  const expired = await fixture({ expiresAt: Math.floor(Date.now() / 1000) - 1 });
  const revoked = await fixture({ revoked: true });
  const responses = await Promise.all([
    worker.fetch(new Request(groupUrl(valid.groupId))),
    worker.fetch(authRequest(groupUrl(valid.groupId), 'malformed')),
    worker.fetch(authRequest(groupUrl(expired.groupId), expired.token)),
    worker.fetch(authRequest(groupUrl(revoked.groupId), revoked.token)),
  ]);
  for (const response of responses) {
    assert.equal(response.status, 401);
    assert.deepEqual(await bodyOf(response), { error: 'unauthorized' });
  }
});

test('unknown groups and groups without membership both return forbidden', async () => {
  const device = await makeDevice();
  const knownGroup = await makeGroup();
  const unknownGroup = randomUUID();
  for (const id of [knownGroup, unknownGroup]) {
    const response = await worker.fetch(authRequest(groupUrl(id), device.token));
    assert.equal(response.status, 403);
    assert.deepEqual(await bodyOf(response), { error: 'forbidden' });
  }
});

test('POST appends opaque ciphertext and GET returns it; an identical retry is idempotent', async () => {
  const { groupId, token, id: deviceId } = await fixture();
  const eventId = randomUUID();
  const ciphertext = 'Y2lwaGVydGV4dA==';
  const created = await postEvent({ groupId, token, eventId, ciphertext });
  assert.equal(created.status, 201);
  const createdBody = await bodyOf(created);
  assert.deepEqual(createdBody, { eventId, revision: 1 });

  const retry = await postEvent({ groupId, token, eventId, ciphertext, expectedRevision: 99 });
  assert.equal(retry.status, 200);
  assert.deepEqual(await bodyOf(retry), createdBody);

  const response = await worker.fetch(authRequest(groupUrl(groupId), token));
  assert.equal(response.status, 200);
  const page = await bodyOf(response);
  assert.equal(page.events.length, 1);
  assert.deepEqual(page.events[0], {
    eventId, senderDeviceId: deviceId, revision: 1, ciphertext,
    createdAt: page.events[0].createdAt,
    expiresAt: page.events[0].createdAt + 7 * 24 * 60 * 60,
  });
  assert.deepEqual(
    { nextAfter: page.nextAfter, headRevision: page.headRevision, hasMore: page.hasMore },
    { nextAfter: 1, headRevision: 1, hasMore: false },
  );
});

test('retrying an expired but unpruned event requires resynchronization', async () => {
  const { groupId, token } = await fixture();
  const eventId = randomUUID();
  const ciphertext = 'Y2lwaGVydGV4dA==';
  assert.equal((await postEvent({ groupId, token, eventId, ciphertext })).status, 201);
  await db.prepare('UPDATE events SET expires_at = ? WHERE group_id = ? AND event_id = ?')
    .bind(Math.floor(Date.now() / 1000) - 1, groupId, eventId).run();

  const retry = await postEvent({ groupId, token, eventId, ciphertext, expectedRevision: 0 });
  assert.equal(retry.status, 410);
  assert.deepEqual(await bodyOf(retry), { error: 'resync_required' });
});

test('reusing event ID with changed ciphertext or sender returns event_conflict', async () => {
  const first = await fixture();
  const second = await makeDevice();
  await db.prepare('INSERT INTO group_members (group_id, device_id) VALUES (?, ?)')
    .bind(first.groupId, second.id).run();
  const eventId = randomUUID();
  assert.equal((await postEvent({ groupId: first.groupId, token: first.token, eventId })).status, 201);

  const changedCiphertext = await postEvent({
    groupId: first.groupId, token: first.token, eventId, ciphertext: 'b3RoZXI=',
  });
  const changedSender = await postEvent({
    groupId: first.groupId, token: second.token, eventId, ciphertext: 'Y2lwaGVydGV4dA==',
  });
  for (const response of [changedCiphertext, changedSender]) {
    assert.equal(response.status, 409);
    assert.deepEqual(await bodyOf(response), { error: 'event_conflict' });
  }
});

test('stale revision conflicts and concurrent appends cannot share a revision', async () => {
  const { groupId, token } = await fixture();
  assert.equal((await postEvent({ groupId, token })).status, 201);
  const stale = await postEvent({ groupId, token, expectedRevision: 0, ciphertext: 'b3RoZXI=' });
  assert.equal(stale.status, 409);
  assert.deepEqual(await bodyOf(stale), { error: 'revision_conflict' });

  const results = await Promise.all([
    postEvent({ groupId, token, expectedRevision: 1, ciphertext: 'dGhyZWU=' }),
    postEvent({ groupId, token, expectedRevision: 1, ciphertext: 'Zm91cg==' }),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [201, 409]);
  assert.deepEqual(await bodyOf(results.find((r) => r.status === 409)), { error: 'revision_conflict' });
});

test('invalid JSON, unknown properties, invalid UUIDs, and noncanonical Base64 return 400', async () => {
  const { groupId, token } = await fixture();
  const responses = await Promise.all([
    postEvent({ groupId, token, rawBody: '{' }),
    postEvent({ groupId, token, extra: { ignored: true } }),
    postEvent({ groupId, token, eventId: 'not-a-uuid' }),
    postEvent({ groupId, token, ciphertext: 'Y2lwaGVydGV4dA=!' }),
    postEvent({ groupId, token, ciphertext: 'YR==' }),
  ]);
  for (const response of responses) {
    assert.equal(response.status, 400);
    assert.deepEqual(await bodyOf(response), { error: 'invalid_request' });
  }
});

test('invalid cursors and invalid group paths have stable error shapes', async () => {
  const { groupId, token } = await fixture();
  for (const cursor of ['-1', '01', '9007199254740992', '1']) {
    const response = await worker.fetch(authRequest(groupUrl(groupId, '?after=' + cursor), token));
    assert.equal(response.status, 400);
    assert.deepEqual(await bodyOf(response), { error: 'invalid_cursor' });
  }
  const malformed = await worker.fetch(authRequest(groupUrl('not-a-uuid'), token));
  assert.equal(malformed.status, 404);
  assert.deepEqual(await bodyOf(malformed), { error: 'not_found' });
});

test('unsupported media type and oversized bodies return 415 and 413', async () => {
  const { groupId, token } = await fixture();
  const media = await postEvent({ groupId, token, contentType: 'text/plain' });
  assert.equal(media.status, 415);
  assert.deepEqual(await bodyOf(media), { error: 'unsupported_media_type' });

  const oversized = await postEvent({ groupId, token, rawBody: ' '.repeat(96 * 1024 + 1) });
  assert.equal(oversized.status, 413);
  assert.deepEqual(await bodyOf(oversized), { error: 'payload_too_large' });
});

test('event history is paginated in pages of at most 100', async () => {
  const { groupId, token, id: deviceId } = await fixture();
  const timestamp = Math.floor(Date.now() / 1000);
  const sql = 'INSERT INTO events (group_id, event_id, sender_device_id, revision, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?, \'YQ==\', ?, ?)';
  const statements = Array.from({ length: 101 }, (_, index) => db.prepare(sql).bind(
    groupId, randomUUID(), deviceId, index + 1, timestamp, timestamp + 3600,
  ));
  await db.batch(statements.slice(0, 100));
  await db.batch(statements.slice(100));

  const firstResponse = await worker.fetch(authRequest(groupUrl(groupId), token));
  assert.equal(firstResponse.status, 200);
  const first = await bodyOf(firstResponse);
  assert.equal(first.events.length, 100);
  assert.equal(first.nextAfter, 100);
  assert.equal(first.headRevision, 101);
  assert.equal(first.hasMore, true);

  const secondResponse = await worker.fetch(authRequest(groupUrl(groupId, '?after=100'), token));
  assert.equal(secondResponse.status, 200);
  const second = await bodyOf(secondResponse);
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0].revision, 101);
  assert.equal(second.nextAfter, 101);
  assert.equal(second.hasMore, false);
});

test('expired history returns resync_required and scheduled cleanup deletes expired rows', async () => {
  const { groupId, token, id: deviceId } = await fixture();
  const past = Math.floor(Date.now() / 1000) - 10;
  await db.prepare('INSERT INTO events (group_id, event_id, sender_device_id, revision, ciphertext, created_at, expires_at) VALUES (?, ?, ?, 1, \'YQ==\', ?, ?)')
    .bind(groupId, randomUUID(), deviceId, past - 100, past).run();

  const response = await worker.fetch(authRequest(groupUrl(groupId), token));
  assert.equal(response.status, 410);
  assert.deepEqual(await bodyOf(response), { error: 'resync_required' });
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM events WHERE group_id = ?').bind(groupId).first()).n, 1);

  await worker.scheduled({ scheduledTime: Date.now(), cron: '0 * * * *' });
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM events WHERE group_id = ?').bind(groupId).first()).n, 0);
});

test('removing a device from a group denies subsequent reads and appends', async () => {
  const { groupId, token, id } = await fixture();
  await postEvent({ groupId, token });
  await db.prepare('DELETE FROM group_members WHERE group_id = ? AND device_id = ?').bind(groupId, id).run();

  const get = await worker.fetch(authRequest(groupUrl(groupId), token));
  const post = await postEvent({ groupId, token });
  for (const response of [get, post]) {
    assert.equal(response.status, 403);
    assert.deepEqual(await bodyOf(response), { error: 'forbidden' });
  }
});
