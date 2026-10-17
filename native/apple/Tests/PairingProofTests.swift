import CryptoKit
import Foundation
import Security
import XCTest
@testable import PairingProof

@MainActor
final class PairingProofTests: XCTestCase {
    private func key() throws -> DeviceKeyStore { try DeviceKeyStore(alias: UUID().uuidString) }

    func testKeychainReuseSignDeleteAndSimulatorProtection() throws {
        let alias = UUID().uuidString
        let original = try DeviceKeyStore(alias: alias)
        defer { try? original.delete() }
        #if targetEnvironment(simulator)
        XCTAssertEqual(original.protection, .simulatorSoftware)
        #else
        XCTAssertEqual(original.protection, .secureEnclave)
        #endif
        let publicKey = try original.createIfMissing()
        let reopened = try DeviceKeyStore(alias: alias)
        XCTAssertEqual(publicKey, try reopened.createIfMissing())
        let message = Data("synthetic key persistence proof".utf8)
        let signature = try reopened.sign(message)
        try PairingCrypto.verify(signature: signature, message: message, publicKey: publicKey)
        XCTAssertThrowsError(try PairingCrypto.verify(signature: signature, message: Data("tampered".utf8), publicKey: publicKey))
        try reopened.delete()
        XCTAssertThrowsError(try original.sign(message))
        XCTAssertThrowsError(try original.publicKeyHex())
        XCTAssertNotEqual(publicKey, try original.createIfMissing())
    }

    func testKeychainAccessibilityAndAliasScope() throws {
        XCTAssertThrowsError(try DeviceKeyStore(alias: "outside.namespace"))
        let alias = UUID().uuidString
        let store = try DeviceKeyStore(alias: alias)
        defer { try? store.delete() }
        try store.createIfMissing()
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: Data("squadtime.proof.\(alias)".utf8),
                                    kSecReturnAttributes as String: true]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)
        let attributes = try XCTUnwrap(result as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
    }

    func testExplicitApprovalAndRequestValidation() throws {
        let newDevice = try key(), trusted = try key()
        defer { try? newDevice.delete(); try? trusted.delete() }
        let request = try PairingRequest.create(key: newDevice, deviceId: UUID(), now: 1_800_000_000)
        XCTAssertThrowsError(try PairingApproval.approve(request, key: trusted, now: 1_800_000_001, userConfirmed: false))
        var tampered = request
        tampered.deviceId = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try PairingApproval.approve(tampered, key: trusted, now: 1_800_000_001, userConfirmed: true))
        tampered = request; tampered.challenge = String(repeating: "00", count: 32)
        XCTAssertThrowsError(try tampered.validate(now: 1_800_000_001))
        tampered = request; tampered.publicKey = request.publicKey.uppercased()
        XCTAssertThrowsError(try tampered.validate(now: 1_800_000_001))
        tampered = request; tampered.expiresAt = tampered.issuedAt + 301
        XCTAssertThrowsError(try tampered.validate(now: 1_800_000_001))
        XCTAssertThrowsError(try request.validate(now: request.issuedAt - 1))
        XCTAssertThrowsError(try request.validate(now: request.expiresAt))
        try request.validate(now: request.expiresAt - 1)
    }

    func testPinnedAuthorityTamperAndSingleUse() async throws {
        let newDevice = try key(), trusted = try key(), attacker = try key()
        defer { try? newDevice.delete(); try? trusted.delete(); try? attacker.delete() }
        let coordinator = PairingCoordinator()
        let request = try await coordinator.begin(key: newDevice, deviceId: UUID(), now: 1_800_000_000)
        let approval = try PairingApproval.approve(request, key: trusted, now: 1_800_000_001, userConfirmed: true)
        let pinned = try trusted.publicKeyHex()
        let rogue = try PairingApproval.approve(request, key: attacker, now: 1_800_000_001, userConfirmed: true)
        await expectRejected { try await coordinator.receive(rogue, trustedApproverPublicKey: pinned, now: 1_800_000_001) }
        var tampered = approval; tampered.requestDigest = String(repeating: "00", count: 32)
        let wrongDigest = tampered
        await expectRejected { try await coordinator.receive(wrongDigest, trustedApproverPublicKey: pinned, now: 1_800_000_001) }
        tampered = approval; tampered.signature = rogue.signature
        let wrongSignature = tampered
        await expectRejected { try await coordinator.receive(wrongSignature, trustedApproverPublicKey: pinned, now: 1_800_000_001) }
        let accepted = try await coordinator.receive(approval, trustedApproverPublicKey: pinned, now: 1_800_000_001)
        XCTAssertEqual(accepted, request)
        await expectRejected { try await coordinator.receive(approval, trustedApproverPublicKey: pinned, now: 1_800_000_001) }
    }

    func testApprovalExpiryAndExactPendingRequestBinding() async throws {
        let newDevice = try key(), trusted = try key()
        defer { try? newDevice.delete(); try? trusted.delete() }
        let coordinator = PairingCoordinator()
        let first = try await coordinator.begin(key: newDevice, deviceId: UUID(), now: 1_800_000_000)
        let second = try await coordinator.begin(key: newDevice, deviceId: UUID(), now: 1_800_000_000)
        var approval = try PairingApproval.approve(first, key: trusted, now: first.issuedAt, userConfirmed: true)
        let pinned = try trusted.publicKeyHex()
        await expectRejected { try await coordinator.receive(approval, trustedApproverPublicKey: pinned, now: first.expiresAt) }
        approval.requestId = second.requestId
        approval.signature = try trusted.sign(approval.transcript)
        let crossRequest = approval
        await expectRejected { try await coordinator.receive(crossRequest, trustedApproverPublicKey: pinned, now: first.issuedAt) }
    }

    func testSharedCrossPlatformFixture() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "pairing-v1", withExtension: "json"))
        try verifyFixture(at: url)
    }

    func testAndroidNativeFixtureImport() throws {
        let documents = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                   appropriateFor: nil, create: false)
        let url = documents.appendingPathComponent("pairing-android-import.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("Copy the public Android native export into this test host's Documents directory first")
        }
        try verifyFixture(at: url)
    }

    private func verifyFixture(at url: URL) throws {
        struct Fixture: Decodable {
            let request: PairingRequest
            let approval: PairingApproval
            let trustedApproverPublicKey: String
            let now: Int64
            let requestTranscriptHex: String
            let approvalTranscriptHex: String
        }
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
        XCTAssertEqual(fixture.request.transcript.hex, fixture.requestTranscriptHex)
        XCTAssertEqual(fixture.approval.transcript.hex, fixture.approvalTranscriptHex)
        try fixture.request.validate(now: fixture.now)
        XCTAssertEqual(fixture.approval.requestDigest, fixture.request.digest)
        XCTAssertEqual(fixture.approval.requestId, fixture.request.requestId)
        XCTAssertEqual(fixture.approval.approverPublicKey, fixture.trustedApproverPublicKey)
        try PairingCrypto.verify(signature: fixture.approval.signature, message: fixture.approval.transcript,
                                 publicKey: fixture.trustedApproverPublicKey)
    }

    func testExportPublicNativeFixture() throws {
        struct Export: Encodable {
            let request: PairingRequest
            let approval: PairingApproval
            let trustedApproverPublicKey: String
            let now: Int64
            let requestTranscriptHex: String
            let approvalTranscriptHex: String
        }
        let newDevice = try key(), trusted = try key()
        defer { try? newDevice.delete(); try? trusted.delete() }
        let now: Int64 = 1_700_000_001
        let request = try PairingRequest.create(key: newDevice, deviceId: UUID(), now: now - 1, lifetime: 300)
        let approval = try PairingApproval.approve(request, key: trusted, now: now, userConfirmed: true)
        let export = Export(request: request, approval: approval, trustedApproverPublicKey: try trusted.publicKeyHex(),
                            now: now, requestTranscriptHex: request.transcript.hex, approvalTranscriptHex: approval.transcript.hex)
        let documents = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                   appropriateFor: nil, create: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // Deliberately public-only, expired synthetic interoperability artifact. Never key material.
        try encoder.encode(export).write(to: documents.appendingPathComponent("pairing-native-export.json"), options: .atomic)
    }

    private func expectRejected(_ operation: () async throws -> PairingRequest,
                                file: StaticString = #filePath, line: UInt = #line) async {
        do { _ = try await operation(); XCTFail("Expected rejection", file: file, line: line) } catch { }
    }
}
