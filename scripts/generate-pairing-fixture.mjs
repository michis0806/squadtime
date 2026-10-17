// Test-only public vector. Private keys are generated in memory and never exported.
import { generateKeyPairSync, randomBytes, randomUUID, sign, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
const key = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function publicHex(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('hex');
}
const device = key(), approver = key();
const request = { version: 1, requestId: randomUUID(), deviceId: randomUUID(),
  challenge: randomBytes(32).toString('hex'), publicKey: publicHex(device.publicKey),
  issuedAt: 1700000000, expiresAt: 1700000300 };
const requestTranscript = Buffer.from(`squadtime-pairing-request-v1\n${request.requestId}\n${request.deviceId}\n${request.challenge}\n${request.publicKey}\n${request.issuedAt}\n${request.expiresAt}\n`, 'utf8');
request.signature = sign('sha256', requestTranscript, device.privateKey).toString('hex');
const approval = { version: 1, requestId: request.requestId,
  requestDigest: createHash('sha256').update(requestTranscript).digest('hex'),
  approverPublicKey: publicHex(approver.publicKey) };
const approvalTranscript = Buffer.from(`squadtime-pairing-approval-v1\n${approval.requestId}\n${approval.requestDigest}\n${approval.approverPublicKey}\n`, 'utf8');
approval.signature = sign('sha256', approvalTranscript, approver.privateKey).toString('hex');
mkdirSync('native/fixtures', { recursive: true });
writeFileSync('native/fixtures/pairing-v1.json', JSON.stringify({ request, approval,
  trustedApproverPublicKey: approval.approverPublicKey, now: 1700000001,
  requestTranscriptHex: requestTranscript.toString('hex'), approvalTranscriptHex: approvalTranscript.toString('hex') }, null, 2) + '\n');
console.log('Generated public-only expired synthetic pairing vector; private keys were never exported.');
