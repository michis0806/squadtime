import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyEnrollmentFixture } from '../scripts/verify-enrollment-fixture.mjs';

const fixture = JSON.parse(readFileSync(new URL('../native/fixtures/enrollment-v1.json', import.meta.url), 'utf8'));

test('independent OpenSSL verifier accepts the native MLS enrollment transcript', () => {
  assert.equal(verifyEnrollmentFixture(fixture), true);
});

test('enrollment binding rejects substituted keys, group, package, signatures and time', () => {
  const replace = (value, index, text) => {
    const lines = Buffer.from(value, 'base64').toString('utf8').split('\n');
    lines[index] = text;
    return Buffer.from(lines.join('\n')).toString('base64');
  };
  const mutations = [
    f => { f.pendingId = Buffer.alloc(32).toString('base64'); },
    f => { f.groupId = Buffer.from('different-group').toString('base64'); },
    f => { f.keyPackage = Buffer.from('different-key-package').toString('base64'); },
    f => { f.devicePublicKey = f.trustedApproverPublicKey; },
    f => { f.trustedApproverPublicKey = f.devicePublicKey; },
    f => { f.request = replace(f.request, 4, '00'.repeat(32)); },
    f => { f.request = replace(f.request, 5, '00'.repeat(32)); },
    f => { f.request = replace(f.request, 0, 'squadtime-pairing-request-v1'); },
    f => { f.approval = replace(f.approval, 2, '00'.repeat(32)); },
    f => { f.approval = replace(f.approval, 0, 'squadtime-pairing-approval-v1'); },
    f => { f.requestSignature = Buffer.concat([Buffer.from(f.requestSignature, 'base64'), Buffer.from([0])]).toString('base64'); },
    f => { f.approvalSignature = f.requestSignature; },
    f => { f.keyPackage += '\n'; },
    f => { f.request = replace(f.request, 8, '01700000000'); },
    f => { f.now = Number(Buffer.from(f.request, 'base64').toString('utf8').split('\n')[9]); },
    f => { f.now = Number(Buffer.from(f.request, 'base64').toString('utf8').split('\n')[8]) - 1; },
    f => { f.now = Number.NaN; },
    f => { f.unexpectedField = 'rejected'; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(fixture);
    mutate(changed);
    assert.throws(() => verifyEnrollmentFixture(changed));
  }
});
