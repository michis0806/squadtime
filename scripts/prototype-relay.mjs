// Disposable LAN test relay. No credentials, private state or request logging.
import http from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_BODY = 180 * 1024;
const MAX_DECODED = 128 * 1024;
const KINDS = ['invitation', 'request', 'welcome', 'receipt'];
export function createPrototypeRelay({ now = Date.now, ttlMs = 30 * 60 * 1000, maxSessions = 64 } = {}) {
  const sessions = new Map();
  const clients = new Map();
  function sweep() {
    const time = now();
    for (const [key, value] of sessions) if (value.expiresAt <= time) sessions.delete(key);
    for (const [key, value] of clients) if (value.since + 60_000 <= time) clients.delete(key);
  }
  function reply(res, status, value) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff' });
    res.end(JSON.stringify(value));
  }
  const server = http.createServer(async (req, res) => {
    sweep();
    // Native callers do not send Origin. Reject browser cross-origin writes/reads.
    if (req.headers.origin) return reply(res, 403, { error: 'browser_access_denied' });
    const address = req.socket.remoteAddress ?? 'unknown';
    let bucket = clients.get(address);
    if (!bucket) {
      if (clients.size >= 256) return reply(res, 503, { error: 'capacity' });
      bucket = { since: now(), count: 0 }; clients.set(address, bucket);
    }
    if (++bucket.count > 180) return reply(res, 429, { error: 'rate_limited' });
    if (req.method === 'GET' && req.url === '/health') {
      return reply(res, 200, { service: 'squadtime-local-prototype', version: 1 });
    }
    const match = /^\/v1\/sessions\/([a-f0-9]{64})\/(invitation|request|welcome|receipt)$/.exec(req.url ?? '');
    if (!match) return reply(res, 404, { error: 'not_found' });
    const [, id, kind] = match;
    if (req.method === 'GET') {
      const record = sessions.get(id);
      return record?.items.has(kind)
        ? reply(res, 200, { outbox: record.items.get(kind) })
        : reply(res, 404, { error: 'not_found' });
    }
    if (req.method !== 'PUT') return reply(res, 405, { error: 'method_not_allowed' });
    if ((req.headers['content-type'] ?? '').split(';')[0].trim() !== 'application/json') {
      return reply(res, 415, { error: 'json_required' });
    }
    if (req.headers['content-encoding']) return reply(res, 415, { error: 'encoding_not_supported' });
    if (Number(req.headers['content-length'] ?? 0) > MAX_BODY) return reply(res, 413, { error: 'too_large' });
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY) { reply(res, 413, { error: 'too_large' }); return; }
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      const text = bytes.toString('utf8');
      if (!Buffer.from(text).equals(bytes)) return reply(res, 400, { error: 'invalid_payload' });
      const payload = JSON.parse(text);
      if (!payload || Array.isArray(payload) || Object.keys(payload).length !== 1 ||
        typeof payload.outbox !== 'string' || payload.outbox.length === 0) {
        return reply(res, 400, { error: 'invalid_payload' });
      }
      const decoded = Buffer.from(payload.outbox, 'base64');
      if (!decoded.length || decoded.length > MAX_DECODED || decoded.toString('base64') !== payload.outbox) {
        return reply(res, 400, { error: 'invalid_payload' });
      }
      // This is opaque transport, never a cryptographic approval authority.
      // Recheck time/capacity after awaiting the body to avoid expiry races.
      sweep();
      let record = sessions.get(id);
      if (!record) {
        if (kind !== 'invitation') return reply(res, 404, { error: 'not_found' });
        if (sessions.size >= maxSessions) return reply(res, 503, { error: 'capacity' });
        record = { expiresAt: now() + ttlMs, items: new Map() }; sessions.set(id, record);
      }
      if (record.items.has(kind)) return record.items.get(kind) === payload.outbox
        ? reply(res, 200, { stored: true }) : reply(res, 409, { error: 'conflict' });
      const index = KINDS.indexOf(kind);
      if (index > 0 && !record.items.has(KINDS[index - 1])) return reply(res, 409, { error: 'phase_missing' });
      record.items.set(kind, payload.outbox);
      return reply(res, 201, { stored: true });
    } catch {
      if (!res.headersSent) reply(res, 400, { error: 'invalid_payload' });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  const timer = setInterval(sweep, 30_000); timer.unref();
  server.on('close', () => { clearInterval(timer); sessions.clear(); clients.clear(); });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.SQUADTIME_PROTOTYPE_PORT ?? 8789);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid test port');
  const server = createPrototypeRelay();
  server.listen(port, '0.0.0.0', () => {
    console.log(`Squadtime local test relay listening on port ${port}. Memory-only; synthetic data only.`);
  });
  server.on('error', () => { console.error('Local test relay could not start.'); process.exitCode = 1; });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
}
