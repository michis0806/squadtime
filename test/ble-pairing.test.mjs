import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createECDH, createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const ascii = (s) => Buffer.from(s, 'ascii');
const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const mac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts)).digest();
const hex = (s) => Buffer.from(s, 'hex');
const fixture = JSON.parse(readFileSync(new URL('../native/fixtures/ble-pairing-v1.json', import.meta.url)));

// Only these two deliberately small, synthetic scalars are constructed locally.
// No private key or derived secret key is serialized into the public fixture.
function syntheticPeer(scalar) {
  const ecdh = createECDH('prime256v1');
  const input = Buffer.alloc(32); input[31] = scalar;
  ecdh.setPrivateKey(input); input.fill(0);
  return ecdh;
}

function reference() {
  const owner = syntheticPeer(1), joiner = syntheticPeer(2);
  const sid = hex(fixture.sidHex), no = hex(fixture.ownerNonceHex), nj = hex(fixture.joinerNonceHex);
  const po = owner.getPublicKey(undefined, 'uncompressed');
  const pj = joiner.getPublicKey(undefined, 'uncompressed');
  const commit = (role, point, nonce) => hash(ascii('squadtime-ble-commit-v1\n'), sid, Buffer.from([role]), point, nonce);
  const co = commit(0, po, no), cj = commit(1, pj, nj);
  const th = hash(ascii('squadtime-ble-transcript-v1\n'), sid, co, cj, po, no, pj, nj);
  const z = owner.computeSecret(pj);
  assert.ok(timingSafeEqual(z, joiner.computeSecret(po)), 'both native-style ECDH roles agree');
  const keys = Buffer.from(hkdfSync('sha256', z, th, ascii('squadtime-ble-keys-v1\n'), 160));
  z.fill(0);
  const confirm = (role) => mac(keys.subarray(32 + role * 32, 64 + role * 32), ascii('squadtime-ble-confirm-v1\n'), th, Buffer.from([role]));
  const seal = (role, plaintext) => {
    const body = Buffer.from(plaintext, 'utf8');
    const header = Buffer.alloc(28);
    header[0] = 0x10; sid.copy(header, 1); header[17] = role;
    header.writeBigUInt64BE(0n, 18); header.writeUInt16BE(body.length + 16, 26);
    const cipher = createCipheriv('aes-256-gcm', keys.subarray(96 + role * 32, 128 + role * 32), Buffer.alloc(12));
    cipher.setAAD(Buffer.concat([ascii('squadtime-ble-data-v1\n'), th, header]));
    const ciphertext = Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([header, ciphertext]);
  };
  const open = (role, frame) => {
    assert.ok(frame.length >= 45 && frame.length <= 2092);
    assert.equal(frame[0], 0x10); assert.deepEqual(frame.subarray(1, 17), sid);
    assert.equal(frame[17], role); assert.equal(frame.readBigUInt64BE(18), 0n);
    assert.equal(frame.readUInt16BE(26), frame.length - 28);
    const decipher = createDecipheriv('aes-256-gcm', keys.subarray(96 + role * 32, 128 + role * 32), Buffer.alloc(12));
    decipher.setAAD(Buffer.concat([ascii('squadtime-ble-data-v1\n'), th, frame.subarray(0, 28)]));
    decipher.setAuthTag(frame.subarray(-16));
    return Buffer.concat([decipher.update(frame.subarray(28, -16)), decipher.final()]);
  };
  return { sid, no, nj, po, pj, co, cj, th, commit, confirm, seal, open, dispose: () => keys.fill(0),
    sas: String(mac(keys.subarray(0, 32), ascii('squadtime-ble-sas-v1\n'), th).readUInt32BE(0) % 1_000_000).padStart(6, '0') };
}

test('BLE v1 public reference values agree with independent Node primitives', () => {
  const r = reference();
  try {
    for (const [name, value] of Object.entries({ ownerPublicKeyHex: r.po, joinerPublicKeyHex: r.pj,
      ownerCommitmentHex: r.co, joinerCommitmentHex: r.cj, transcriptHashHex: r.th,
      ownerConfirmMacHex: r.confirm(0), joinerConfirmMacHex: r.confirm(1),
      ownerFrameHex: r.seal(0, fixture.ownerPlaintext), joinerFrameHex: r.seal(1, fixture.joinerPlaintext) })) {
      assert.equal(value.toString('hex'), fixture[name], name);
    }
    assert.equal(r.sas, fixture.sas);
    assert.equal(r.open(0, hex(fixture.ownerFrameHex)).toString('utf8'), fixture.ownerPlaintext);
    assert.equal(r.open(1, hex(fixture.joinerFrameHex)).toString('utf8'), fixture.joinerPlaintext);
  } finally { r.dispose(); }
});

test('BLE commitments bind exact points, nonces, session and role', () => {
  const r = reference();
  try {
    const nonce = Buffer.from(r.no); nonce[0] ^= 1;
    assert.notDeepEqual(r.commit(0, r.po, nonce), r.co);
    assert.notDeepEqual(r.commit(0, r.pj, r.no), r.co);
    assert.notDeepEqual(r.commit(1, r.po, r.no), r.co);
    const sid = Buffer.from(r.sid); sid[0] ^= 1;
    assert.notDeepEqual(hash(ascii('squadtime-ble-commit-v1\n'), sid, Buffer.from([0]), r.po, r.no), r.co);
    assert.equal(timingSafeEqual(r.confirm(0), r.confirm(1)), false, 'a local MAC cannot pass as peer approval');
    assert.throws(() => syntheticPeer(1).computeSecret(Buffer.alloc(65)), /invalid|public|point/i);
  } finally { r.dispose(); }
});

test('BLE AES-GCM rejects modified ciphertext/tag, session, direction, counter and length', () => {
  const r = reference();
  try {
    for (const offset of [0, 1, 17, 25, 27, 28, hex(fixture.ownerFrameHex).length - 1]) {
      const modified = hex(fixture.ownerFrameHex); modified[offset] ^= 1;
      assert.throws(() => r.open(0, modified), `altered byte ${offset}`);
    }
    assert.throws(() => r.open(1, hex(fixture.ownerFrameHex)), 'direction reflection');
    assert.throws(() => r.open(0, hex(fixture.joinerFrameHex)), 'opposite direction frame');
    assert.throws(() => r.open(0, Buffer.concat([hex(fixture.ownerFrameHex), Buffer.from([0])])), 'trailing data');
    assert.throws(() => r.open(0, hex(fixture.ownerFrameHex).subarray(0, -1)), 'truncated tag');
  } finally { r.dispose(); }
});
