import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyFixture } from '../scripts/verify-pairing-fixture.mjs';

const fixture = JSON.parse(readFileSync(new URL('../native/fixtures/pairing-v1.json', import.meta.url), 'utf8'));

test('independent OpenSSL verifier accepts the shared native wire vector', () => {
  assert.equal(verifyFixture(fixture), true);
});

test('native wire vector rejects tampering, wrong trust pin and expired approval', () => {
  const mutations = [
    f => { f.request.challenge = '00'.repeat(32); },
    f => { f.request.publicKey = f.approval.approverPublicKey; },
    f => { f.approval.requestDigest = '00'.repeat(32); },
    f => { f.approval.requestId = '00000000-0000-0000-0000-000000000000'; },
    f => { f.trustedApproverPublicKey = f.request.publicKey; },
    f => { f.request.signature += '00'; },
    f => { f.approval.signature += '00'; },
    f => { f.now = f.request.expiresAt; },
    f => { f.now = f.request.issuedAt - 1; },
    f => { f.request.expiresAt = f.request.issuedAt + 301; },
    f => { f.request.version = 2; },
    f => { f.approval.version = 2; },
  ];
  for (const mutate of mutations) {
    const altered = structuredClone(fixture);
    mutate(altered);
    assert.throws(() => verifyFixture(altered));
  }
});
