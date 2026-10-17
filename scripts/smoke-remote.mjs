import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';

const configPath = '.local/wrangler.json';
const config = JSON.parse(readFileSync(configPath, 'utf8'));
assert.equal(config.name, 'squadtime-api-dev');
assert.equal(config.d1_databases[0].database_name, 'squadtime-dev');
assert.match(config.account_id, /^[a-f0-9]{32}$/);
const base = new URL(process.env.SQUADTIME_DEV_URL ?? '');
assert.equal(base.protocol, 'https:');
assert.match(base.hostname, /^squadtime-api-dev\.[a-z0-9-]+\.workers\.dev$/);
assert.equal(base.username + base.password + base.search + base.hash, '');
const group = randomUUID();
const devices = Array.from({ length: 3 }, () => ({ id: randomUUID(), token: randomBytes(32).toString('base64url') }));
const expiry = Math.floor(Date.now() / 1000) + 900;
function sql(statement) {
  const path = `.local/smoke-${randomUUID()}.sql`;
  writeFileSync(path, statement, { mode: 0o600, flag: 'wx' });
  try {
    execFileSync(process.execPath, ['node_modules/wrangler/bin/wrangler.js', 'd1', 'execute', 'DB', '--remote', '--config', configPath, '--file', path, '--json'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
  } catch { throw new Error('DEV database command failed; output withheld to avoid disclosure.'); }
  finally { unlinkSync(path); }
}
const endpoint = new URL(`/v1/groups/${group}/events`, base);
function request(device, body) {
  return fetch(endpoint, { method: body ? 'POST' : 'GET',
    headers: { ...(device ? { Authorization: `Bearer ${device.token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000) });
}
let peer;
try {
  assert.equal((await fetch(new URL('/health', base), { signal: AbortSignal.timeout(15000) })).status, 200);
  assert.equal((await request()).status, 401);
  sql(devices.map(d => `INSERT INTO devices(id,token_hash,expires_at) VALUES('${d.id}','${createHash('sha256').update(d.token).digest('hex')}',${expiry});`).join('\n')
    + `\nINSERT INTO groups(id) VALUES('${group}');\n`
    + devices.slice(0, 2).map(d => `INSERT INTO group_members(group_id,device_id) VALUES('${group}','${d.id}');`).join('\n'));
  assert.equal((await request(devices[2])).status, 403);
  peer = spawn('crypto/mls-spike/target/debug/examples/relay_roundtrip', [], { stdio: ['pipe', 'pipe', 'pipe'] });
  const ended = once(peer, 'exit');
  const lines = createInterface({ input: peer.stdout });
  const iterator = lines[Symbol.asyncIterator]();
  const first = await iterator.next();
  assert.equal(first.done, false, 'MLS peer must emit encrypted envelope');
  assert.match(first.value, /^(?:[a-f0-9]{2})+$/);
  const ciphertext = Buffer.from(first.value, 'hex').toString('base64');
  const event = { eventId: randomUUID(), expectedRevision: 0, ciphertext };
  assert.equal((await request(devices[0], event)).status, 201);
  assert.equal((await request(devices[0], event)).status, 200);
  const response = await request(devices[1]);
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].ciphertext, ciphertext);
  assert.equal(result.events[0].senderDeviceId, devices[0].id);
  peer.stdin.end(Buffer.from(result.events[0].ciphertext, 'base64').toString('hex') + '\n');
  const verified = await iterator.next();
  assert.equal(verified.value, 'verified');
  const [exitCode] = await ended;
  assert.equal(exitCode, 0);
  sql(`UPDATE devices SET revoked = 1 WHERE id = '${devices[1].id}';`);
  assert.equal((await request(devices[1])).status, 401);
  console.log('PASS: live health, auth denial, membership isolation, real MLS relay roundtrip, idempotency and device revocation.');
} finally {
  peer?.kill();
  sql(`DELETE FROM events WHERE group_id = '${group}'; DELETE FROM groups WHERE id = '${group}'; DELETE FROM devices WHERE id IN (${devices.map(d => `'${d.id}'`).join(',')});`);
  console.log('Removed ephemeral DEV test records.');
}
