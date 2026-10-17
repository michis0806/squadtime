// Independent Node verifier for public native test exports; not an onboarding service.
import assert from 'node:assert/strict';
import { createPublicKey, createHash, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
export function verifyFixture(fixture) {
  const { request: r, approval: a, trustedApproverPublicKey: trusted, now } = fixture;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const publicKey = hex => {
    assert.match(hex, /^04[0-9a-f]{128}$/);
    const raw = Buffer.from(hex, 'hex');
    return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
      x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33).toString('base64url') } });
  };
  const signature = hex => {
    assert.match(hex, /^(?:[0-9a-f]{2}){8,72}$/);
    return Buffer.from(hex, 'hex');
  };
  assert.equal(r.version, 1); assert.equal(a.version, 1);
  assert.match(r.requestId, uuid); assert.match(r.deviceId, uuid);
  assert.match(r.challenge, /^[0-9a-f]{64}$/);
  for (const value of [r.issuedAt, r.expiresAt, now]) assert.ok(Number.isSafeInteger(value) && value >= 0);
  assert.ok(r.issuedAt <= now && now < r.expiresAt && r.expiresAt - r.issuedAt <= 300);
  const rt = Buffer.from(`squadtime-pairing-request-v1\n${r.requestId}\n${r.deviceId}\n${r.challenge}\n${r.publicKey}\n${r.issuedAt}\n${r.expiresAt}\n`, 'utf8');
  assert.ok(verify('sha256', rt, publicKey(r.publicKey), signature(r.signature)), 'request signature');
  assert.equal(a.requestId, r.requestId);
  assert.equal(a.requestDigest, createHash('sha256').update(rt).digest('hex'));
  assert.equal(a.approverPublicKey, trusted);
  const at = Buffer.from(`squadtime-pairing-approval-v1\n${a.requestId}\n${a.requestDigest}\n${a.approverPublicKey}\n`, 'utf8');
  assert.ok(verify('sha256', at, publicKey(trusted), signature(a.signature)), 'approval signature');
  if (fixture.requestTranscriptHex !== undefined) assert.equal(fixture.requestTranscriptHex, rt.toString('hex'));
  if (fixture.approvalTranscriptHex !== undefined) assert.equal(fixture.approvalTranscriptHex, at.toString('hex'));
  return true;
}
if (process.argv[1]?.endsWith('/verify-pairing-fixture.mjs')) {
  try {
    verifyFixture(JSON.parse(readFileSync(process.argv[2] ?? 'native/fixtures/pairing-v1.json', 'utf8')));
    console.log('PASS: public pairing transcripts, signatures, time and pinned approver.');
  } catch { console.error('FAIL: public pairing fixture rejected.'); process.exitCode = 1; }
}
