// Independent public transcript verifier. This does not parse MLS or authorize users.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fields = ['pendingId', 'groupId', 'keyPackage', 'request', 'approval',
  'requestSignature', 'approvalSignature', 'devicePublicKey', 'trustedApproverPublicKey', 'now'];
const hash = value => createHash('sha256').update(value).digest('hex');
const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
export function base64(value, maximum, exact) {
  assert.equal(typeof value, 'string');
  assert.ok(value.length > 0 && value.length <= Math.ceil(maximum / 3) * 4);
  const bytes = Buffer.from(value, 'base64');
  assert.equal(bytes.toString('base64'), value);
  assert.ok(bytes.length <= maximum);
  if (exact !== undefined) assert.equal(bytes.length, exact);
  return bytes;
}
export function publicKey(value) {
  const raw = base64(value, 65, 65);
  assert.equal(raw[0], 4);
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33).toString('base64url') } });
}
export function signature(value) {
  const bytes = base64(value, 72);
  assert.ok(bytes.length >= 8 && bytes[0] === 0x30 && bytes[1] === bytes.length - 2);
  let offset = 2;
  for (let i = 0; i < 2; i++) {
    assert.equal(bytes[offset++], 2);
    const length = bytes[offset++];
    assert.ok(length >= 1 && length <= 33 && offset + length <= bytes.length);
    assert.equal(bytes[offset] & 0x80, 0);
    assert.ok(length === 1 || bytes[offset] !== 0 || (bytes[offset + 1] & 0x80) !== 0);
    const scalar = BigInt(`0x${bytes.subarray(offset, offset + length).toString('hex')}`);
    assert.ok(scalar > 0n && scalar < order);
    offset += length;
  }
  assert.equal(offset, bytes.length);
  return bytes;
}
function decimal(value) {
  assert.match(value, /^(0|[1-9][0-9]*)$/);
  const number = Number(value);
  assert.ok(Number.isSafeInteger(number) && number >= 0);
  return number;
}

export function verifyEnrollmentFixture(fixture) {
  assert.deepEqual(Object.keys(fixture).sort(), [...fields].sort());
  const f = fixture;
  base64(f.pendingId, 32, 32);
  base64(f.groupId, 256);
  const keyPackage = base64(f.keyPackage, 1024 * 1024);
  assert.notEqual(f.devicePublicKey, f.trustedApproverPublicKey);
  const request = base64(f.request, 4096);
  const approval = base64(f.approval, 2048);
  const r = request.toString('utf8').split('\n');
  const a = approval.toString('utf8').split('\n');
  assert.equal(r.length, 11);
  assert.equal(a.length, 5);
  assert.equal(r[0], 'squadtime-mls-device-request-v1');
  assert.equal(r[1], f.pendingId);
  assert.equal(r[2], f.groupId);
  assert.equal(r[3], hash(keyPackage));
  assert.match(r[4], /^[0-9a-f]{64}$/);
  assert.match(r[5], /^[0-9a-f]{64}$/);
  assert.notEqual(r[4], r[5]);
  assert.equal(r[6], f.devicePublicKey);
  assert.equal(r[7], f.trustedApproverPublicKey);
  const issuedAt = decimal(r[8]);
  const expiresAt = decimal(r[9]);
  assert.equal(r[10], '');
  assert.ok(expiresAt - issuedAt === 300);
  assert.ok(Number.isSafeInteger(f.now) && f.now >= issuedAt && f.now < expiresAt);
  assert.equal(a[0], 'squadtime-mls-device-approval-v1');
  assert.equal(a[1], f.pendingId);
  assert.equal(a[2], hash(request));
  assert.equal(a[3], f.trustedApproverPublicKey);
  assert.equal(a[4], '');
  assert.ok(verify('sha256', request, publicKey(f.devicePublicKey), signature(f.requestSignature)), 'request signature');
  assert.ok(verify('sha256', approval, publicKey(f.trustedApproverPublicKey), signature(f.approvalSignature)), 'approval signature');
  return true;
}

if (process.argv[1]?.endsWith('/verify-enrollment-fixture.mjs')) {
  try {
    verifyEnrollmentFixture(JSON.parse(readFileSync(process.argv[2] ?? 'native/fixtures/enrollment-v1.json', 'utf8')));
    console.log('PASS: public enrollment binding, signatures, time and pinned approver.');
  } catch {
    console.error('FAIL: public enrollment fixture rejected.');
    process.exitCode = 1;
  }
}
