import CryptoKit
import Foundation

struct BLEDerivedMaterial {
    let transcriptHash: Data
    let keys: [SymmetricKey]
    let sas: String
}

/// Pure platform-crypto operations shared with the public reference-vector tests.
enum BLEPairingCrypto {
    static func commitment(sid: Data, role: BLEPairingRole, point: Data, nonce: Data) -> Data {
        Data(SHA256.hash(data: Data("squadtime-ble-commit-v1\n".utf8) + sid + Data([role.rawValue]) + point + nonce))
    }
    static func derive(role: BLEPairingRole, key: P256.KeyAgreement.PrivateKey, nonce: Data, peerPoint: Data, peerNonce: Data, sid: Data, ownCommit: Data, peerCommit: Data) throws -> BLEDerivedMaterial {
        guard sid.count == 16, nonce.count == 32, peerNonce.count == 32, peerNonce != nonce,
              peerPoint.count == 65, peerPoint.first == 4, peerPoint != key.publicKey.x963Representation,
              ownCommit.count == 32, peerCommit.count == 32 else { throw PrototypeFailure.invalid }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPoint)
        let peerRole: BLEPairingRole = role == .owner ? .joiner : .owner
        guard commitment(sid: sid, role: role, point: key.publicKey.x963Representation, nonce: nonce) == ownCommit,
              commitment(sid: sid, role: peerRole, point: peerPoint, nonce: peerNonce) == peerCommit else { throw PrototypeFailure.invalid }
        let point = key.publicKey.x963Representation
        var transcript = Data("squadtime-ble-transcript-v1\n".utf8)
        transcript.append(sid)
        transcript.append(role == .owner ? ownCommit : peerCommit)
        transcript.append(role == .joiner ? ownCommit : peerCommit)
        transcript.append(role == .owner ? point : peerPoint)
        transcript.append(role == .owner ? nonce : peerNonce)
        transcript.append(role == .joiner ? point : peerPoint)
        transcript.append(role == .joiner ? nonce : peerNonce)
        let hash = Data(SHA256.hash(data: transcript))
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        let material = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: hash, sharedInfo: Data("squadtime-ble-keys-v1\n".utf8), outputByteCount: 160)
        var bytes = material.withUnsafeBytes { Data($0) }; defer { bytes.resetBytes(in: 0..<bytes.count) }
        let keys = stride(from: 0, to: 160, by: 32).map { SymmetricKey(data: bytes.subdata(in: $0..<($0 + 32))) }
        let mac = HMAC<SHA256>.authenticationCode(for: Data("squadtime-ble-sas-v1\n".utf8) + hash, using: keys[0])
        let number = mac.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } % 1_000_000
        return BLEDerivedMaterial(transcriptHash: hash, keys: keys, sas: String(format: "%06u", number))
    }
    static func seal(_ plaintext: Data, role: BLEPairingRole, sid: Data, hash: Data, key: SymmetricKey) throws -> Data {
        guard sid.count == 16, hash.count == 32, (1...2048).contains(plaintext.count) else { throw PrototypeFailure.invalid }
        let length = UInt16(plaintext.count + 16)
        let header = Data([0x10]) + sid + Data([role.rawValue]) + Data(repeating: 0, count: 8) + Data([UInt8(length >> 8), UInt8(length & 255)])
        let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: Data(repeating: 0, count: 12)), authenticating: Data("squadtime-ble-data-v1\n".utf8) + hash + header)
        return header + box.ciphertext + box.tag
    }
    static func open(_ packet: Data, sender: BLEPairingRole, sid: Data, hash: Data, key: SymmetricKey) throws -> Data {
        guard sid.count == 16, hash.count == 32, (45...2092).contains(packet.count), packet.first == 0x10,
              Data(packet.dropFirst().prefix(16)) == sid, packet[packet.startIndex + 17] == sender.rawValue else { throw PrototypeFailure.invalid }
        let header = Data(packet.prefix(28)); let sequence = Data(header.dropFirst(18).prefix(8))
        let length = Int(header[header.startIndex + 26]) * 256 + Int(header[header.startIndex + 27])
        guard sequence == Data(repeating: 0, count: 8), (17...2064).contains(length), packet.count == 28 + length else { throw PrototypeFailure.invalid }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(repeating: 0, count: 4) + sequence), ciphertext: Data(packet.dropFirst(28).dropLast(16)), tag: Data(packet.suffix(16)))
        return try AES.GCM.open(box, using: key, authenticating: Data("squadtime-ble-data-v1\n".utf8) + hash + header)
    }
}
