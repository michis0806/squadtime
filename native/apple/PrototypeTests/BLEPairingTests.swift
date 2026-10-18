import CryptoKit
import Foundation
import XCTest
@testable import SquadtimePrototype

final class BLEPairingTests: XCTestCase {
    func testPublicCrossPlatformReference() throws {
        let path = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "ble-pairing-v1", withExtension: "json"))
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any])
        func bytes(_ name: String) throws -> Data { try hex(XCTUnwrap(fixture[name] as? String)) }
        var scalar = Data(repeating: 0, count: 32); scalar[31] = 1
        let owner = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        scalar[31] = 2
        let joiner = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        let sid = try bytes("sidHex"), no = try bytes("ownerNonceHex"), nj = try bytes("joinerNonceHex")
        XCTAssertEqual(owner.publicKey.x963Representation, try bytes("ownerPublicKeyHex"))
        XCTAssertEqual(joiner.publicKey.x963Representation, try bytes("joinerPublicKeyHex"))
        let co = BLEPairingCrypto.commitment(sid: sid, role: .owner, point: owner.publicKey.x963Representation, nonce: no)
        let cj = BLEPairingCrypto.commitment(sid: sid, role: .joiner, point: joiner.publicKey.x963Representation, nonce: nj)
        XCTAssertEqual(co, try bytes("ownerCommitmentHex")); XCTAssertEqual(cj, try bytes("joinerCommitmentHex"))
        let material = try BLEPairingCrypto.derive(role: .owner, key: owner, nonce: no, peerPoint: joiner.publicKey.x963Representation, peerNonce: nj, sid: sid, ownCommit: co, peerCommit: cj)
        XCTAssertEqual(material.transcriptHash, try bytes("transcriptHashHex")); XCTAssertEqual(material.sas, fixture["sas"] as? String)
        for (role, keyIndex, macName, plaintextName, frameName) in [(BLEPairingRole.owner, 1, "ownerConfirmMacHex", "ownerPlaintext", "ownerFrameHex"), (.joiner, 2, "joinerConfirmMacHex", "joinerPlaintext", "joinerFrameHex")] {
            let input = Data("squadtime-ble-confirm-v1\n".utf8) + material.transcriptHash + Data([role.rawValue])
            XCTAssertEqual(Data(HMAC<SHA256>.authenticationCode(for: input, using: material.keys[keyIndex])), try bytes(macName))
            let plaintext = Data(try XCTUnwrap(fixture[plaintextName] as? String).utf8)
            let packet = try BLEPairingCrypto.seal(plaintext, role: role, sid: sid, hash: material.transcriptHash, key: material.keys[keyIndex + 2])
            XCTAssertEqual(packet, try bytes(frameName))
            XCTAssertEqual(try BLEPairingCrypto.open(packet, sender: role, sid: sid, hash: material.transcriptHash, key: material.keys[keyIndex + 2]), plaintext)
            var changed = packet; changed[changed.count - 1] ^= 1
            XCTAssertThrowsError(try BLEPairingCrypto.open(changed, sender: role, sid: sid, hash: material.transcriptHash, key: material.keys[keyIndex + 2]))
            changed = packet; changed[17] ^= 1
            XCTAssertThrowsError(try BLEPairingCrypto.open(changed, sender: role, sid: sid, hash: material.transcriptHash, key: material.keys[keyIndex + 2]))
            var hash = material.transcriptHash; hash[0] ^= 1
            XCTAssertThrowsError(try BLEPairingCrypto.open(packet, sender: role, sid: sid, hash: hash, key: material.keys[keyIndex + 2]))
        }
        var changedCommit = cj; changedCommit[0] ^= 1
        XCTAssertThrowsError(try BLEPairingCrypto.derive(role: .owner, key: owner, nonce: no, peerPoint: joiner.publicKey.x963Representation, peerNonce: nj, sid: sid, ownCommit: co, peerCommit: changedCommit))
        XCTAssertThrowsError(try BLEPairingCrypto.derive(role: .owner, key: owner, nonce: no, peerPoint: Data(repeating: 0, count: 65), peerNonce: nj, sid: sid, ownCommit: co, peerCommit: cj))
    }
    func testMutualApprovalAndExactEncryptedTransfer() async throws {
        let (owner, joiner, sas) = try await exchange()
        XCTAssertEqual(sas.count, 6)
        let oc = try await owner.approve()
        let oq = try await owner.confirmationQueued(); XCTAssertFalse(oq.verified)
        let jr = try await joiner.receive(XCTUnwrap(oc.outbound.first)); XCTAssertFalse(jr.verified)
        let jc = try await joiner.approve()
        let jq = try await joiner.confirmationQueued(); XCTAssertTrue(jq.verified)
        let or = try await owner.receive(XCTUnwrap(jc.outbound.first)); XCTAssertTrue(or.verified)
        let invitation = try pairCode("invite"), request = try pairCode("request")
        let encrypted = try await owner.sealPairCode(invitation)
        let cached = try await owner.sealPairCode(invitation); XCTAssertEqual(encrypted, cached)
        let received = try await joiner.receive(encrypted); XCTAssertEqual(received.pairCode, invitation)
        let requestPacket = try await joiner.sealPairCode(request)
        let accepted = try await owner.receive(requestPacket); XCTAssertEqual(accepted.pairCode, request)
        await expectFailure { _ = try await owner.receive(requestPacket) }
        await expectFailure { try await owner.tick() }
    }
    func testPeerApprovalAloneAndReflectionDoNotAuthorizeData() async throws {
        let (owner, joiner, _) = try await exchange()
        let oc = try await owner.approve(); _ = try await owner.confirmationQueued()
        let remote = try await joiner.receive(XCTUnwrap(oc.outbound.first)); XCTAssertFalse(remote.verified)
        await expectFailure { _ = try await joiner.sealPairCode(try self.pairCode("request")) }
        let (otherOwner, _, _) = try await exchange()
        let reflected = try await otherOwner.approve()
        await expectFailure { _ = try await otherOwner.receive(try XCTUnwrap(reflected.outbound.first)) }
    }
    func testChangedRevealDuplicateCommitAndCancelledStateFailClosed() async throws {
        let owner = BLEPairingSession(role: .owner), joiner = BLEPairingSession(role: .joiner)
        let oc = try await owner.begin(); _ = try await joiner.begin()
        let jc = try await joiner.receive(XCTUnwrap(oc.outbound.first))
        let reveal = try await owner.receive(XCTUnwrap(jc.outbound.first))
        var changed = try XCTUnwrap(reveal.outbound.first); changed[changed.count - 1] ^= 1
        await expectFailure { _ = try await joiner.receive(changed) }
        await expectFailure { _ = try await owner.receive(try XCTUnwrap(jc.outbound.first)) }
        await owner.destroy(); await expectFailure { try await owner.tick() }
        let fresh = BLEPairingSession(role: .owner)
        let freshCommit = try await fresh.begin(); XCTAssertNotEqual(freshCommit.outbound, oc.outbound)
    }
    func testIdleTimeoutDoesNotExtendOverallDeadline() async throws {
        let clock = TestBLEClock()
        let owner = BLEPairingSession(role: .owner, clock: { clock.now() })
        _ = try await owner.begin(); clock.advance(16)
        await expectFailure { try await owner.tick() }
        await expectFailure { _ = try await owner.approve() }
    }
    private func exchange() async throws -> (BLEPairingSession, BLEPairingSession, String) {
        let owner = BLEPairingSession(role: .owner), joiner = BLEPairingSession(role: .joiner)
        let oc = try await owner.begin(); _ = try await joiner.begin()
        let jc = try await joiner.receive(XCTUnwrap(oc.outbound.first))
        let oreveal = try await owner.receive(XCTUnwrap(jc.outbound.first))
        let jreveal = try await joiner.receive(XCTUnwrap(oreveal.outbound.first))
        let oresult = try await owner.receive(XCTUnwrap(jreveal.outbound.first))
        XCTAssertEqual(jreveal.code, oresult.code)
        return (owner, joiner, try XCTUnwrap(oresult.code))
    }
    private func pairCode(_ type: String) throws -> String {
        try PairCode(v: 1, type: type, relay: "http://192.168.1.2:8789", session: String(repeating: "a", count: 64), key: P256.Signing.PrivateKey().publicKey.x963Representation, hash: String(repeating: "b", count: 64), expiresAt: Int64(Date().timeIntervalSince1970) + 240, label: "Synthetic test").text()
    }
    private func hex(_ value: String) throws -> Data {
        var bytes = Data()
        for offset in stride(from: 0, to: value.count, by: 2) {
            let start = value.index(value.startIndex, offsetBy: offset)
            bytes.append(try XCTUnwrap(UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)))
        }
        return bytes
    }
    private func expectFailure(_ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected fail-closed rejection", file: file, line: line) } catch {}
    }
}

private final class TestBLEClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.Instant.now
    func now() -> ContinuousClock.Instant { lock.lock(); defer { lock.unlock() }; return instant }
    func advance(_ seconds: Int) { lock.lock(); defer { lock.unlock() }; instant = instant.advanced(by: .seconds(seconds)) }
}
