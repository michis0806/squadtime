import Foundation
import XCTest
@testable import PairingProof

@MainActor
final class MLSEnrollmentTests: XCTestCase {
    private func key() throws -> DeviceKeyStore {
        let key = try DeviceKeyStore(alias: UUID().uuidString)
        try key.createIfMissing()
        return key
    }

    func testNativeEnrollmentCreatesEncryptedVaultAndDecryptsAuthorizedMessages() async throws {
        let device = try key(), approver = try key()
        defer { try? device.delete(); try? approver.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        let joined = try await coordinator.complete(context, requestSignature: signature,
                                                     approvalSignature: approval, now: 1_700_000_001)
        await expectProof(.noPending) {
            _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        }
        let id = UUID()
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("squadtime-enrollment-tests/\(id.uuidString)")
        defer {
            try? VaultKeyStore(vaultID: id.uuidString.lowercased()).delete()
            try? FileManager.default.removeItem(at: directory)
        }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: joined.snapshot)
        for index in joined.packets.indices {
            let event = try await vault.receive(packet: joined.packets[index])
            XCTAssertTrue(event.plaintext == joined.expected[index])
        }
        await vault.close()
        let reopened = try DurableVault.open(directory: directory, vaultID: id)
        let pending = try await reopened.pendingMessages()
        XCTAssertEqual(pending.count, 2)
        await reopened.close()
    }

    func testEnrollmentRejectsKeyPackageGroupAndTranscriptSubstitution() async throws {
        let device = try key(), approver = try key()
        defer { try? device.delete(); try? approver.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        var changed = context
        changed.keyPackage[changed.keyPackage.count - 1] ^= 1
        let substitutedPackage = changed
        await expectContextMismatch {
            _ = try await coordinator.complete(substitutedPackage, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        }
        changed = context
        changed.groupId[0] ^= 1
        let substitutedGroup = changed
        await expectContextMismatch {
            _ = try await coordinator.complete(substitutedGroup, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        }
        changed = context
        changed.request[changed.request.count - 2] ^= 1
        let substitutedTranscript = changed
        await expectContextMismatch {
            _ = try await coordinator.signRequest(substitutedTranscript, deviceKey: device, now: 1_700_000_001)
        }
        // All rejected attempts preserve the exact original pending admission.
        _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
    }

    func testEnrollmentRequiresPinnedKeysExplicitApprovalAndValidSignatures() async throws {
        let device = try key(), approver = try key(), rogue = try key()
        defer { try? device.delete(); try? approver.delete(); try? rogue.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        await expectProof(.untrusted) { _ = try await coordinator.signRequest(context, deviceKey: rogue, now: 1_700_000_001) }
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        await expectProof(.notConfirmed) {
            _ = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                              now: 1_700_000_001, userConfirmed: false)
        }
        await expectProof(.untrusted) {
            _ = try await coordinator.approve(context, requestSignature: signature, approverKey: rogue,
                                              now: 1_700_000_001, userConfirmed: true)
        }
        await expectProof(.malformed) {
            _ = try await coordinator.approve(context, requestSignature: Data([1]), approverKey: approver,
                                              now: 1_700_000_001, userConfirmed: true)
        }
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        await expectProof(.malformed) {
            _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: Data([1]), now: 1_700_000_001)
        }
        _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
    }

    func testEnrollmentExpiryAndCancellationAreFailClosed() async throws {
        let device = try key(), approver = try key()
        defer { try? device.delete(); try? approver.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        await expectProof(.malformed) {
            _ = try await coordinator.begin(deviceKey: device, trustedApproverPublicKeyHex: device.publicKeyHex(), now: 1_700_000_000)
        }
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        await expectProof(.expired) { _ = try await coordinator.signRequest(context, deviceKey: device, now: 1_699_999_999) }
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        await expectProof(.expired) {
            _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_300)
        }
        try await coordinator.cancel()
        await expectProof(.noPending) {
            _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        }
    }

    func testCancellationReleasesLocalSlotAfterRustExpiryCleanup() async throws {
        let device = try key(), approver = try key()
        defer { try? device.delete(); try? approver.delete() }
        let first = MLSEnrollmentCoordinator(), later = MLSEnrollmentCoordinator()
        _ = try await first.begin(deviceKey: device, trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        // A later Rust prepare evicts the first expired handle from its process-local registry.
        _ = try await later.begin(deviceKey: device, trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_300)
        do {
            try await first.cancel()
            XCTFail("The Rust handle should already be expired")
        } catch { XCTAssertEqual(error as? VaultError, .mlsRejected) }
        // A failed remote cancellation must not leave a permanently occupied native slot.
        _ = try await first.begin(deviceKey: device, trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_301)
        try await first.cancel()
        try await later.cancel()
    }

    func testActualRustBridgeRejectsSubstitutionPinsAndReplayWithoutNativeGuards() async throws {
        let device = try key(), approver = try key(), rogue = try key()
        defer { try? device.delete(); try? approver.delete(); try? rogue.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        var input = completionInput(context, requestSignature: signature, approvalSignature: approval)
        var wrongGroup = context.groupId
        wrongGroup[0] ^= 1
        input["groupId"] = wrongGroup.base64EncodedString()
        expectRustRejected(input)
        input = completionInput(context, requestSignature: signature, approvalSignature: approval)
        var wrongPackage = context.keyPackage
        wrongPackage[wrongPackage.count - 1] ^= 1
        input["keyPackage"] = wrongPackage.base64EncodedString()
        expectRustRejected(input)
        let rogueApproval = try Data(strictHex: rogue.sign(context.approval))
        expectRustRejected(completionInput(context, requestSignature: signature, approvalSignature: rogueApproval))
        expectRustRejected(completionInput(context, requestSignature: Data([1]), approvalSignature: approval))
        _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        expectRustRejected(completionInput(context, requestSignature: signature, approvalSignature: approval))
    }

    private func completionInput(_ context: MLSEnrollmentContext, requestSignature: Data,
                                 approvalSignature: Data) -> [String: Any] {
        ["op": "enrollmentcomplete", "pendingId": context.pendingId.base64EncodedString(),
         "groupId": context.groupId.base64EncodedString(), "keyPackage": context.keyPackage.base64EncodedString(),
         "requestSignature": requestSignature.base64EncodedString(), "approvalSignature": approvalSignature.base64EncodedString(),
         "now": Int64(1_700_000_001)]
    }

    private func expectRustRejected(_ input: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
        do {
            let _: MLSFixture = try RustMLS.call(input)
            XCTFail("Expected Rust authorization rejection", file: file, line: line)
        } catch { XCTAssertEqual(error as? VaultError, .mlsRejected, file: file, line: line) }
    }

    func testExportPublicNativeMLSEnrollmentProof() async throws {
        struct Export: Encodable {
            let request: Data
            let approval: Data
            let pendingId: Data
            let groupId: Data
            let keyPackage: Data
            let requestSignature: Data
            let approvalSignature: Data
            let devicePublicKey: Data
            let trustedApproverPublicKey: Data
            let now: Int64
        }
        let device = try key(), approver = try key()
        defer { try? device.delete(); try? approver.delete() }
        let coordinator = MLSEnrollmentCoordinator()
        let context = try await coordinator.begin(deviceKey: device,
                                                  trustedApproverPublicKeyHex: approver.publicKeyHex(), now: 1_700_000_000)
        let signature = try await coordinator.signRequest(context, deviceKey: device, now: 1_700_000_001)
        let approval = try await coordinator.approve(context, requestSignature: signature, approverKey: approver,
                                                     now: 1_700_000_001, userConfirmed: true)
        _ = try await coordinator.complete(context, requestSignature: signature, approvalSignature: approval, now: 1_700_000_001)
        let exported = Export(request: context.request, approval: context.approval, pendingId: context.pendingId,
                              groupId: context.groupId, keyPackage: context.keyPackage,
                              requestSignature: signature, approvalSignature: approval,
                              devicePublicKey: try Data(strictHex: device.publicKeyHex()),
                              trustedApproverPublicKey: try Data(strictHex: approver.publicKeyHex()), now: 1_700_000_001)
        let documents = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                   appropriateFor: nil, create: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        // Public keys, public KeyPackage, signatures and expired synthetic context only.
        // No snapshot, private MLS state, application packets, expected text or native private key.
        try encoder.encode(exported).write(to: documents.appendingPathComponent("mls-enrollment-native-export.json"), options: .atomic)
    }

    private func expectProof(_ expected: ProofError, _ operation: () async throws -> Void,
                             file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected rejection", file: file, line: line) }
        catch { XCTAssertEqual(error as? ProofError, expected, file: file, line: line) }
    }

    private func expectContextMismatch(_ operation: () async throws -> Void,
                                       file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected exact-context rejection", file: file, line: line) }
        catch { XCTAssertEqual(error as? EnrollmentError, .contextMismatch, file: file, line: line) }
    }
}
