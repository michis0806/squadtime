import Foundation
import SQLite3
import XCTest
@testable import PairingProof

@MainActor
final class DurableAdmissionTests: XCTestCase {
    private struct Party {
        let id: UUID
        let directory: URL
        let key: DeviceKeyStore
        var native: Data { get throws { try Data(strictHex: key.publicKeyHex()) } }
        func create(_ role: AdmissionRole, pin: Data? = nil) throws -> DurableAdmission {
            try DurableAdmission.create(directory: directory, id: id, role: role, nativeKey: key, trustedAdminPublicKey: pin)
        }
        func open() throws -> DurableAdmission { try DurableAdmission.open(directory: directory, id: id) }
        func cleanup() {
            try? key.delete()
            try? VaultKeyStore(vaultID: id.uuidString.lowercased(), purpose: .admission).delete()
            try? FileManager.default.removeItem(at: directory)
        }
    }
    private func party() throws -> Party {
        let id = UUID(), key = try DeviceKeyStore(alias: UUID().uuidString)
        try key.createIfMissing()
        let parent = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return Party(id: id, directory: parent.appendingPathComponent("squadtime-admission-unit/\(id.uuidString)"), key: key)
    }
    private let now: Int64 = 1_700_000_000

    func testIndependentAdmissionReopensEveryPhaseAndPersistsInbox() async throws {
        let owner = try party(), joiner = try party()
        defer { owner.cleanup(); joiner.cleanup() }
        let start = try owner.create(.owner)
        let invitation = try await start.ownerStart(nativeKey: owner.key, now: now)
        await start.close()
        let ownerRestored = try owner.open()
        try await assertOutbox(ownerRestored, equals: invitation)
        let prepare = try joiner.create(.joiner, pin: owner.native)
        let request = try await prepare.joinerStart(invitation: invitation.outbox, nativeKey: joiner.key, now: now + 1)
        await prepare.close()
        let joinerRestored = try joiner.open()
        try await assertOutbox(joinerRestored, equals: request)
        let welcome = try await ownerRestored.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native,
                                                         nativeKey: owner.key, now: now + 2, userConfirmed: true)
        await ownerRestored.close()
        let ownerFinal = try owner.open()
        try await assertOutbox(ownerFinal, equals: welcome)
        await ownerFinal.close()
        let accepted = try await joinerRestored.join(welcome: welcome.outbox, now: now + 600)
        XCTAssertTrue(accepted.plaintext == AdmissionValidation.expectedProbe)
        await joinerRestored.close()
        let joined = try joiner.open()
        let pending = try await joined.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        let packet = try await joined.proofProbePacket()
        await expectVault(.mlsRejected) { _ = try await joined.receive(packet: packet) }
        try await joined.acknowledge(messageID: accepted.id)
        await joined.close()
        let acknowledged = try joiner.open()
        let empty = try await acknowledged.pendingMessages()
        XCTAssertTrue(empty.isEmpty)
        await acknowledged.close()
    }

    func testAdmissionRollbackAndUncertainCommitsNeverReleaseStagedOutboxOrPlaintext() async throws {
        let owner = try party(), joiner = try party()
        defer { owner.cleanup(); joiner.cleanup() }
        let admin = try owner.create(.owner)
        await expectVault(.injectedRollback) { _ = try await admin.ownerStart(nativeKey: owner.key, now: self.now, fault: .beforeCommit) }
        let blank = try await admin.outbox()
        XCTAssertTrue(blank.kind == "empty" && blank.outbox.isEmpty)
        let invitation = try await admin.ownerStart(nativeKey: owner.key, now: now)
        let candidate = try joiner.create(.joiner, pin: owner.native)
        let request = try await candidate.joinerStart(invitation: invitation.outbox, nativeKey: joiner.key, now: now + 1)
        await expectVault(.injectedRollback) {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native, nativeKey: owner.key,
                                           now: self.now + 2, userConfirmed: true, fault: .beforeCommit)
        }
        try await assertOutbox(admin, equals: invitation)
        await expectVault(.commitUncertain) {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native, nativeKey: owner.key,
                                           now: self.now + 2, userConfirmed: true, fault: .afterCommit)
        }
        await expectVault(.requiresReopen) { _ = try await admin.outbox() }
        await admin.close()
        let restored = try owner.open()
        let welcome = try await restored.outbox()
        XCTAssertEqual(welcome.kind, "welcome")
        await restored.close()
        await expectVault(.injectedRollback) { _ = try await candidate.join(welcome: welcome.outbox, now: self.now + 600, fault: .beforeCommit) }
        try await assertOutbox(candidate, equals: request)
        await expectVault(.commitUncertain) { _ = try await candidate.join(welcome: welcome.outbox, now: self.now + 600, fault: .afterCommit) }
        await expectVault(.requiresReopen) { _ = try await candidate.pendingMessages() }
        await candidate.close()
        let recovered = try joiner.open()
        let inbox = try await recovered.pendingMessages()
        XCTAssertEqual(inbox.count, 1)
        XCTAssertTrue(inbox.first?.plaintext == AdmissionValidation.expectedProbe)
        let packet = try await recovered.proofProbePacket()
        await expectVault(.mlsRejected) { _ = try await recovered.receive(packet: packet) }
        await recovered.close()
    }

    func testAdmissionIndependentConnectionCASRejectsStaleOwnerAndJoiner() async throws {
        let owner = try party(), joiner = try party()
        defer { owner.cleanup(); joiner.cleanup() }
        let admin = try owner.create(.owner)
        let invitation = try await admin.ownerStart(nativeKey: owner.key, now: now)
        let staleAdmin = try owner.open()
        let candidate = try joiner.create(.joiner, pin: owner.native)
        let request = try await candidate.joinerStart(invitation: invitation.outbox, nativeKey: joiner.key, now: now + 1)
        let staleCandidate = try joiner.open()
        let welcome = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native,
                                                 nativeKey: owner.key, now: now + 2, userConfirmed: true)
        await expectVault(.staleRevision) {
            _ = try await staleAdmin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native,
                                                nativeKey: owner.key, now: self.now + 2, userConfirmed: true)
        }
        await expectVault(.requiresReopen) { _ = try await staleAdmin.outbox() }
        _ = try await candidate.join(welcome: welcome.outbox, now: now + 600)
        await expectVault(.staleRevision) { _ = try await staleCandidate.join(welcome: welcome.outbox, now: self.now + 600) }
        await expectVault(.requiresReopen) { _ = try await staleCandidate.pendingMessages() }
        await staleAdmin.close(); await admin.close(); await staleCandidate.close(); await candidate.close()
        let joined = try joiner.open()
        let pending = try await joined.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        await joined.close()
    }

    func testAdmissionRejectsPinsTamperingExpiryAndRepeatedTransitions() async throws {
        let owner = try party(), joiner = try party(), rogue = try party()
        defer { owner.cleanup(); joiner.cleanup(); rogue.cleanup() }
        let admin = try owner.create(.owner)
        let invitation = try await admin.ownerStart(nativeKey: owner.key, now: now)
        let wrongPin = try rogue.create(.joiner, pin: joiner.native)
        await expectAny { _ = try await wrongPin.joinerStart(invitation: invitation.outbox, nativeKey: rogue.key, now: self.now + 1) }
        await wrongPin.close()
        let candidate = try joiner.create(.joiner, pin: owner.native)
        let altered = try replacingField(invitation.outbox, field: "signature", value: Data([1]).base64EncodedString())
        await expectAny { _ = try await candidate.joinerStart(invitation: altered, nativeKey: joiner.key, now: self.now + 1) }
        let blank = try await candidate.outbox()
        XCTAssertTrue(blank.outbox.isEmpty)
        let request = try await candidate.joinerStart(invitation: invitation.outbox, nativeKey: joiner.key, now: now + 1)
        await expectProof(.notConfirmed) {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native, nativeKey: owner.key,
                                           now: self.now + 2, userConfirmed: false)
        }
        await expectAny {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: rogue.native, nativeKey: owner.key,
                                           now: self.now + 2, userConfirmed: true)
        }
        await expectProof(.expired) {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native, nativeKey: owner.key,
                                           now: self.now + 300, userConfirmed: true)
        }
        let welcome = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native,
                                                 nativeKey: owner.key, now: now + 2, userConfirmed: true)
        await expectProof(.noPending) {
            _ = try await admin.ownerAdmit(request: request.outbox, trustedDevicePublicKey: joiner.native, nativeKey: owner.key,
                                           now: self.now + 2, userConfirmed: true)
        }
        let modified = try replacingField(welcome.outbox, field: "approvalSignature", value: Data([1]).base64EncodedString())
        await expectAny { _ = try await candidate.join(welcome: modified, now: self.now + 600) }
        _ = try await candidate.join(welcome: welcome.outbox, now: now + 600)
        await expectProof(.noPending) { _ = try await candidate.join(welcome: welcome.outbox, now: self.now + 600) }
        await admin.close(); await candidate.close()
    }

    func testAdmissionMissingAndWrongWrappingKeysFailClosed() async throws {
        let owner = try party()
        defer { owner.cleanup() }
        let admin = try owner.create(.owner)
        _ = try await admin.ownerStart(nativeKey: owner.key, now: now)
        await admin.close()
        let keys = VaultKeyStore(vaultID: owner.id.uuidString.lowercased(), purpose: .admission)
        try keys.delete()
        XCTAssertThrowsError(try owner.open()) { XCTAssertEqual($0 as? VaultError, .missingKey) }
        XCTAssertThrowsError(try owner.create(.owner))
        let exists = try keys.load() != nil
        XCTAssertFalse(exists)
        _ = try keys.createIfMissing()
        XCTAssertThrowsError(try owner.open()) { XCTAssertEqual($0 as? VaultError, .authentication) }
    }

    func testAdmissionMissingOrReplacedSigningKeyFailsWithoutImplicitRegeneration() async throws {
        let owner = try party()
        defer { owner.cleanup() }
        let admin = try owner.create(.owner)
        _ = try await admin.ownerStart(nativeKey: owner.key, now: now)
        await admin.close()
        try owner.key.delete()
        XCTAssertThrowsError(try owner.open()) { XCTAssertEqual($0 as? VaultError, .missingKey) }
        XCTAssertThrowsError(try owner.create(.owner)) { XCTAssertEqual($0 as? VaultError, .alreadyExists) }
        XCTAssertThrowsError(try owner.key.publicKeyHex())
        _ = try owner.key.createIfMissing() // Explicit replacement must still fail to open the old admission.
        XCTAssertThrowsError(try owner.open()) { XCTAssertEqual($0 as? ProofError, .untrusted) }
    }

    func testAdmissionCiphertextRevisionAndFileProtectionPolicies() async throws {
        let owner = try party()
        defer { owner.cleanup() }
        let admin = try owner.create(.owner)
        _ = try await admin.ownerStart(nativeKey: owner.key, now: now)
        let directoryFlags = try owner.directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(directoryFlags.isExcludedFromBackup, true)
        for suffix in ["", "-wal", "-shm"] {
            let file = owner.directory.appendingPathComponent("admission.sqlite\(suffix)")
            let flags = try file.resourceValues(forKeys: [.isExcludedFromBackupKey])
            XCTAssertEqual(flags.isExcludedFromBackup, true)
            let bytes = try Data(contentsOf: file)
            XCTAssertTrue(bytes.range(of: AdmissionValidation.expectedProbe) == nil)
        }
        await admin.close()
        var connection: OpaquePointer?
        XCTAssertEqual(sqlite3_open(owner.directory.appendingPathComponent("admission.sqlite").path, &connection), SQLITE_OK)
        defer { sqlite3_close(connection) }
        var query: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, "SELECT ciphertext FROM vault", -1, &query, nil), SQLITE_OK)
        XCTAssertEqual(sqlite3_step(query), SQLITE_ROW)
        let pointer = try XCTUnwrap(sqlite3_column_blob(query, 0))
        let encrypted = Data(bytes: pointer, count: Int(sqlite3_column_bytes(query, 0)))
        sqlite3_finalize(query)
        var tampered = encrypted
        tampered[tampered.count - 1] ^= 1
        try setCiphertext(tampered, connection: connection)
        XCTAssertThrowsError(try owner.open())
        try setCiphertext(encrypted, connection: connection)
        XCTAssertEqual(sqlite3_exec(connection, "UPDATE vault SET revision=2", nil, nil, nil), SQLITE_OK)
        XCTAssertThrowsError(try owner.open())
        XCTAssertEqual(sqlite3_exec(connection, "UPDATE vault SET revision=1", nil, nil, nil), SQLITE_OK)
        let restored = try owner.open()
        let outbox = try await restored.outbox()
        XCTAssertEqual(outbox.kind, "invitation")
        await restored.close()
    }

    private func assertOutbox(_ store: DurableAdmission, equals expected: AdmissionOutbox,
                              file: StaticString = #filePath, line: UInt = #line) async throws {
        let actual = try await store.outbox()
        XCTAssertTrue(actual == expected, file: file, line: line)
    }
    private func replacingField(_ data: Data, field: String, value: String) throws -> Data {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object[field] = value
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
    private func setCiphertext(_ data: Data, connection: OpaquePointer?) throws {
        var statement: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, "UPDATE vault SET ciphertext=?", -1, &statement, nil), SQLITE_OK)
        defer { sqlite3_finalize(statement) }
        let result = data.withUnsafeBytes { sqlite3_bind_blob(statement, 1, $0.baseAddress, Int32(data.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
        XCTAssertEqual(result, SQLITE_OK)
        XCTAssertEqual(sqlite3_step(statement), SQLITE_DONE)
    }
    private func expectVault(_ expected: VaultError, _ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected storage rejection", file: file, line: line) }
        catch { XCTAssertEqual(error as? VaultError, expected, file: file, line: line) }
    }
    private func expectProof(_ expected: ProofError, _ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected proof rejection", file: file, line: line) }
        catch { XCTAssertEqual(error as? ProofError, expected, file: file, line: line) }
    }
    private func expectAny(_ operation: () async throws -> Void, file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected admission rejection", file: file, line: line) } catch { }
    }
}
