// Public-only independent transcript verification, not an MLS decoder or trust bootstrap.
import assert from 'node:assert/strict';
import { createHash, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { base64, publicKey, signature } from './verify-enrollment-fixture.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const transcript = lines => Buffer.from(`${lines.join('\n')}\n`, 'utf8');
function exact(value, fields) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), fields.sort());
}
function wire(value, fields) {
  const bytes = base64(value, 128 * 1024);
  const text = bytes.toString('utf8');
  assert.ok(Buffer.from(text, 'utf8').equals(bytes));
  const json = JSON.parse(text);
  exact(json, fields);
  assert.equal(json.version, 1);
  return json;
}
function clock(value) { assert.ok(Number.isSafeInteger(value) && value >= 0); }

export function verifyAdmissionFixture(f) {
  exact(f, ['invitation', 'request', 'welcome', 'trustedAdminPublicKey', 'trustedDevicePublicKey', 'admissionNow']);
  clock(f.admissionNow);
  const i = wire(f.invitation, ['version', 'invitationId', 'groupId', 'adminIdentity', 'adminPublicKey', 'issuedAt', 'expiresAt', 'signature']);
  base64(i.invitationId, 32, 32);
  base64(i.groupId, 256);
  const adminIdentity = base64(i.adminIdentity, 4096);
  assert.equal(i.adminPublicKey, f.trustedAdminPublicKey);
  clock(i.issuedAt); clock(i.expiresAt);
  assert.equal(i.expiresAt - i.issuedAt, 300);
  assert.ok(i.issuedAt <= f.admissionNow && f.admissionNow < i.expiresAt);
  const it = transcript(['squadtime-mls-invitation-v1', i.invitationId, i.groupId,
    hash(adminIdentity), i.adminPublicKey, i.issuedAt, i.expiresAt]);
  assert.ok(verify('sha256', it, publicKey(f.trustedAdminPublicKey), signature(i.signature)), 'invitation signature');

  const r = wire(f.request, ['version', 'requestId', 'invitation', 'keyPackage', 'joinerIdentity', 'devicePublicKey', 'issuedAt', 'expiresAt', 'signature']);
  base64(r.requestId, 32, 32);
  assert.equal(r.invitation, f.invitation);
  const keyPackage = base64(r.keyPackage, 32 * 1024);
  const joinerIdentity = base64(r.joinerIdentity, 4096);
  assert.notEqual(hash(joinerIdentity), hash(adminIdentity));
  assert.equal(r.devicePublicKey, f.trustedDevicePublicKey);
  assert.notEqual(r.devicePublicKey, f.trustedAdminPublicKey);
  clock(r.issuedAt); clock(r.expiresAt);
  assert.equal(r.expiresAt, i.expiresAt);
  assert.ok(i.issuedAt <= r.issuedAt && r.issuedAt <= f.admissionNow);
  const invitationDigest = hash(base64(f.invitation, 128 * 1024));
  const rt = transcript(['squadtime-mls-admission-request-v1', r.requestId, invitationDigest,
    i.groupId, hash(keyPackage), hash(joinerIdentity), hash(adminIdentity), r.devicePublicKey,
    i.adminPublicKey, r.issuedAt, r.expiresAt]);
  assert.ok(verify('sha256', rt, publicKey(f.trustedDevicePublicKey), signature(r.signature)), 'request signature');

  const w = wire(f.welcome, ['version', 'request', 'approvalSignature', 'welcome', 'probe']);
  assert.equal(w.request, f.request);
  base64(w.welcome, 64 * 1024);
  base64(w.probe, 1024 * 1024);
  const at = transcript(['squadtime-mls-admission-approval-v1', r.requestId, hash(rt),
    invitationDigest, i.groupId, hash(adminIdentity), r.devicePublicKey, i.adminPublicKey, r.expiresAt]);
  assert.ok(verify('sha256', at, publicKey(f.trustedAdminPublicKey), signature(w.approvalSignature)), 'approval signature');
  // MLS authenticates the Welcome and probe themselves; this verifier checks public signatures only.
  return true;
}

if (process.argv[1]?.endsWith('/verify-admission-fixture.mjs')) {
  try {
    verifyAdmissionFixture(JSON.parse(readFileSync(process.argv[2] ?? 'native/fixtures/admission-v1.json', 'utf8')));
    console.log('PASS: independent admission invitation, request, approval and explicit trust pins.');
  } catch { console.error('FAIL: public admission fixture rejected.'); process.exitCode = 1; }
}
