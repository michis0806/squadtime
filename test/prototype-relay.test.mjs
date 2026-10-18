import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { createPrototypeRelay } from '../scripts/prototype-relay.mjs';

const id = 'a'.repeat(64), other = 'b'.repeat(64);
const body = text => JSON.stringify({ outbox: Buffer.from(text).toString('base64') });
async function setup(t, options) {
  const server = createPrototypeRelay(options);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    get: (kind, session = id) => fetch(`${base}/v1/sessions/${session}/${kind}`),
    put: (kind, content = body(kind), session = id, headers = {}) => fetch(`${base}/v1/sessions/${session}/${kind}`,
      { method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body: content }),
    base,
  };
}

test('prototype relay preserves exact immutable envelopes and phase order', async t => {
  const api = await setup(t);
  assert.equal((await api.get('invitation')).status, 404);
  assert.equal((await api.put('request')).status, 404);
  assert.equal((await api.put('invitation')).status, 201);
  assert.equal((await api.put('welcome')).status, 409);
  assert.equal((await api.put('invitation')).status, 200);
  assert.equal((await api.put('invitation', body('changed'))).status, 409);
  assert.deepEqual(await (await api.get('invitation')).json(), JSON.parse(body('invitation')));
  for (const kind of ['request', 'welcome', 'receipt']) assert.equal((await api.put(kind)).status, 201);
  assert.equal((await api.get('welcome', other)).status, 404);
});

test('prototype relay expires data without extending lifetime on retries', async t => {
  let time = 1000; const api = await setup(t, { now: () => time, ttlMs: 100 });
  assert.equal((await api.put('invitation')).status, 201);
  time = 1099;
  assert.equal((await api.put('invitation')).status, 200);
  time = 1100;
  assert.equal((await api.get('invitation')).status, 404);
  assert.equal((await api.put('request')).status, 404);
});

test('prototype relay bounds memory, rejects malformed writes and browser access', async t => {
  const api = await setup(t, { maxSessions: 1 });
  for (const malformed of ['{}', '[]', '{"outbox":"abc"}', '{"outbox":""}', '{"outbox":"YQ==","state":"x"}']) {
    assert.equal((await api.put('invitation', malformed)).status, 400);
  }
  assert.equal((await api.put('invitation', body('a'), id, { Origin: 'https://example.test' })).status, 403);
  assert.equal((await api.put('invitation', body('a'), id, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await api.put('invitation', 'x'.repeat(181 * 1024))).status, 413);
  assert.equal((await api.put('invitation')).status, 201);
  assert.equal((await api.put('invitation', body('other'), other)).status, 503);
  assert.equal((await fetch(`${api.base}/v1/sessions/${id}/invitation?extra=1`)).status, 404);
  assert.equal((await fetch(`${api.base}/health`)).status, 200);
});
