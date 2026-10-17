import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyAdmissionFixture } from '../scripts/verify-admission-fixture.mjs';

const fixture = JSON.parse(readFileSync(new URL('../native/fixtures/admission-v1.json', import.meta.url), 'utf8'));
const edit = (value, change) => {
  const decoded = JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
  change(decoded);
  return Buffer.from(JSON.stringify(decoded)).toString('base64');
};

test('independent OpenSSL verifier accepts the cross-client native admission', () => {
  assert.equal(verifyAdmissionFixture(fixture), true);
});

test('admission rejects key substitution, changed signed context, envelope nesting and expiry', () => {
  const mutations = [
    f => { f.trustedAdminPublicKey = f.trustedDevicePublicKey; },
    f => { f.trustedDevicePublicKey = f.trustedAdminPublicKey; },
    f => { f.invitation = edit(f.invitation, i => { i.groupId = Buffer.from('other-group').toString('base64'); }); },
    f => { f.invitation = edit(f.invitation, i => { i.adminIdentity = Buffer.from('other-admin').toString('base64'); }); },
    f => { f.request = edit(f.request, r => { r.keyPackage = Buffer.from('other-package').toString('base64'); }); },
    f => { f.request = edit(f.request, r => { r.joinerIdentity = Buffer.from('other-joiner').toString('base64'); }); },
    f => { f.request = edit(f.request, r => { r.devicePublicKey = f.trustedAdminPublicKey; }); },
    f => { f.request = edit(f.request, r => { r.invitation += '\n'; }); },
    f => { f.welcome = edit(f.welcome, w => { w.request = f.invitation; }); },
    f => { f.welcome = edit(f.welcome, w => { w.approvalSignature = Buffer.alloc(64).toString('base64'); }); },
    f => { f.invitation = edit(f.invitation, i => { i.unexpected = true; }); },
    f => { f.admissionNow = JSON.parse(Buffer.from(f.invitation, 'base64')).expiresAt; },
    f => { f.admissionNow = JSON.parse(Buffer.from(f.invitation, 'base64')).issuedAt - 1; },
    f => { f.invitation += '\n'; },
    f => { f.extra = 'rejected'; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(fixture);
    mutate(changed);
    assert.throws(() => verifyAdmissionFixture(changed));
  }
});
