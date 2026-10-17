/** Opaque DEV relay. Authorization is not end-to-end identity verification. */
interface EventRow {
  eventId: string; senderDeviceId: string; revision: number;
  ciphertext: string; createdAt: number; expiresAt: number;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BODY = 96 * 1024;
const TTL = 7 * 24 * 60 * 60;
const PAGE = 100;
const now = () => Math.floor(Date.now() / 1000);
const json = (body: unknown, status = 200) => Response.json(body, {
  status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
});
const fail = (code: string, status: number) => json({ error: code }, status);
class RequestError extends Error {
  constructor(readonly code: string, readonly status: number) { super(code); }
}
async function readBody(request: Request): Promise<unknown> {
  if (request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json')
    throw new RequestError('unsupported_media_type', 415);
  const declared = request.headers.get('content-length');
  if (declared && Number(declared) > MAX_BODY) throw new RequestError('payload_too_large', 413);
  const reader = request.body?.getReader();
  if (!reader) throw new RequestError('invalid_request', 400);
  const chunks: Uint8Array[] = []; let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_BODY) { await reader.cancel(); throw new RequestError('payload_too_large', 413); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)); }
  catch { throw new RequestError('invalid_request', 400); }
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function validCiphertext(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 4 || value.length > 65536 || value.length % 4 !== 0) return false;
  try { return btoa(atob(value)) === value; } catch { return false; }
}
async function tokenHash(request: Request): Promise<string | null> {
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.get('authorization') ?? '');
  if (!match?.[1]) return null;
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(match[1]));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}
const eventFields = `event_id AS eventId, sender_device_id AS senderDeviceId,
  revision, ciphertext, created_at AS createdAt, expires_at AS expiresAt`;
async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/health') return request.method === 'GET'
    ? json({ service: 'squadtime-relay', status: 'ok', stage: 'dev', protocolVersion: 1 })
    : fail('method_not_allowed', 405);
  const match = /^\/v1\/groups\/([^/]+)\/events$/.exec(url.pathname);
  if (!match?.[1] || !UUID.test(match[1])) return fail('not_found', 404);
  if (request.method !== 'GET' && request.method !== 'POST') return fail('method_not_allowed', 405);
  const groupId = match[1], hash = await tokenHash(request), timestamp = now();
  if (!hash) return fail('unauthorized', 401);
  const device = await env.DB.prepare('SELECT id FROM devices WHERE token_hash = ? AND revoked = 0 AND expires_at > ?')
    .bind(hash, timestamp).first<{ id: string }>();
  if (!device) return fail('unauthorized', 401);
  const group = await env.DB.prepare(`SELECT g.revision FROM groups g JOIN group_members m ON m.group_id = g.id
    WHERE g.id = ? AND m.device_id = ?`).bind(groupId, device.id).first<{ revision: number }>();
  if (!group) return fail('forbidden', 403);
  if (request.method === 'GET') {
    const raw = url.searchParams.get('after') ?? '0';
    const after = Number(raw);
    if (!/^(0|[1-9][0-9]*)$/.test(raw) || !Number.isSafeInteger(after) || after > group.revision)
      return fail('invalid_cursor', 400);
    // Recheck authorization in the same statement that returns encrypted data.
    const result = await env.DB.prepare(`SELECT ${eventFields} FROM events
      WHERE group_id = ? AND revision > ? AND revision <= ? AND expires_at > ?
      AND EXISTS (SELECT 1 FROM group_members m JOIN devices d ON d.id = m.device_id
        WHERE m.group_id = ? AND d.token_hash = ? AND d.revoked = 0 AND d.expires_at > ?)
      ORDER BY revision LIMIT ?`).bind(groupId, after, group.revision, timestamp, groupId, hash, timestamp, PAGE + 1).all<EventRow>();
    const rows = result.results;
    if (after < group.revision && (!rows[0] || rows[0].revision !== after + 1)) return fail('resync_required', 410);
    for (let i = 1; i < rows.length; i++) {
      if (rows[i]!.revision !== rows[i - 1]!.revision + 1) return fail('resync_required', 410);
    }
    if (rows.length <= PAGE && (rows.at(-1)?.revision ?? after) !== group.revision) return fail('resync_required', 410);
    const events = rows.slice(0, PAGE);
    return json({ events, nextAfter: events.at(-1)?.revision ?? after, headRevision: group.revision, hasMore: rows.length > PAGE });
  }
  const body = await readBody(request);
  if (!isRecord(body) || Object.keys(body).length !== 3 || typeof body.eventId !== 'string' || !UUID.test(body.eventId)
    || typeof body.expectedRevision !== 'number' || !Number.isSafeInteger(body.expectedRevision) || body.expectedRevision < 0
    || !validCiphertext(body.ciphertext)) return fail('invalid_request', 400);
  const existing = () => env.DB.prepare(`SELECT ${eventFields} FROM events WHERE group_id = ? AND event_id = ?
    AND EXISTS (SELECT 1 FROM group_members m JOIN devices d ON d.id = m.device_id
      WHERE m.group_id = ? AND d.token_hash = ? AND d.revoked = 0 AND d.expires_at > ?)` )
    .bind(groupId, body.eventId, groupId, hash, now()).first<EventRow>();
  const retryResponse = (row: EventRow) => row.expiresAt <= now() ? fail('resync_required', 410)
    : row.senderDeviceId === device.id && row.ciphertext === body.ciphertext
      ? json({ eventId: row.eventId, revision: row.revision }) : fail('event_conflict', 409);
  const prior = await existing();
  if (prior) return retryResponse(prior);
  const acceptedAt = now();
  // INSERT + trigger are atomic. A stale revision cannot insert; races cannot overwrite.
  try {
    const result = await env.DB.prepare(`INSERT INTO events
      (group_id, event_id, sender_device_id, revision, ciphertext, created_at, expires_at)
      SELECT g.id, ?, ?, g.revision + 1, ?, ?, ? FROM groups g
      WHERE g.id = ? AND g.revision = ? AND EXISTS (
        SELECT 1 FROM group_members m JOIN devices d ON d.id = m.device_id
        WHERE m.group_id = g.id AND d.id = ? AND d.token_hash = ? AND d.revoked = 0 AND d.expires_at > ?)
      RETURNING revision`).bind(body.eventId, device.id, body.ciphertext, acceptedAt, acceptedAt + TTL,
      groupId, body.expectedRevision, device.id, hash, acceptedAt).first<{ revision: number }>();
    if (result) return json({ eventId: body.eventId, revision: result.revision }, 201);
  } catch (error) {
    // D1 can race on the idempotency key; never return database error text to clients.
    const raced = await existing();
    if (raced) return retryResponse(raced);
    throw error;
  }
  const raced = await existing();
  if (raced) return retryResponse(raced);
  const stillActive = await env.DB.prepare('SELECT id FROM devices WHERE token_hash = ? AND revoked = 0 AND expires_at > ?')
    .bind(hash, now()).first();
  if (!stillActive) return fail('unauthorized', 401);
  const stillMember = await env.DB.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND device_id = ?')
    .bind(groupId, device.id).first();
  return stillMember ? fail('revision_conflict', 409) : fail('forbidden', 403);
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try { return await handle(request, env); }
    catch (error) { return error instanceof RequestError ? fail(error.code, error.status) : fail('internal_error', 500); }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await env.DB.prepare('DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE expires_at <= ? LIMIT 1000)')
      .bind(now()).run();
  },
} satisfies ExportedHandler<Env>;
