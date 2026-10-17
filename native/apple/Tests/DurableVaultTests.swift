import CryptoKit
import Foundation
import Security
import SQLite3
import XCTest
@testable import PairingProof

@MainActor
final class DurableVaultTests: XCTestCase {
    private func location() throws -> (URL, UUID) {
        let id = UUID()
        let parent = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: true)
        return (parent.appendingPathComponent("squadtime-vault-tests/\(id.uuidString)"), id)
    }

    private func cleanup(_ directory: URL, _ id: UUID) {
        try? VaultKeyStore(vaultID: id.uuidString.lowercased()).delete()
        try? FileManager.default.removeItem(at: directory)
    }

    func testMLSDurableRestartInboxAndAcknowledgement() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        let event = try await vault.receive(packet: fixture.packets[0])
        XCTAssertTrue(event.plaintext == fixture.expected[0])
        let revision = try await vault.currentRevision()
        XCTAssertEqual(revision, 1)
        await vault.close()
        let reopened = try DurableVault.open(directory: directory, vaultID: id)
        let pending = try await reopened.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        XCTAssertTrue(pending.first == event)
        await expect(.mlsRejected) { _ = try await reopened.receive(packet: fixture.packets[0]) }
        try await reopened.acknowledge(messageID: event.id)
        await reopened.close()
        let again = try DurableVault.open(directory: directory, vaultID: id)
        let empty = try await again.pendingMessages()
        XCTAssertTrue(empty.isEmpty)
        let second = try await again.receive(packet: fixture.packets[1])
        XCTAssertTrue(second.plaintext == fixture.expected[1])
        await expect(.mlsRejected) { _ = try await again.receive(packet: fixture.packets[0]) }
        await again.close()
    }

    func testTamperedMLSPacketDoesNotConsumeState() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        var tampered = fixture.packets[0]
        tampered[tampered.count - 1] ^= 1
        await expect(.mlsRejected) { _ = try await vault.receive(packet: tampered) }
        let revision = try await vault.currentRevision()
        let pending = try await vault.pendingMessages()
        XCTAssertEqual(revision, 0)
        XCTAssertTrue(pending.isEmpty)
        let event = try await vault.receive(packet: fixture.packets[0])
        XCTAssertTrue(event.plaintext == fixture.expected[0])
        await vault.close()
    }

    func testRollbackAndUncertainCommitReleaseNoPlaintext() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        await expect(.injectedRollback) { _ = try await vault.receive(packet: fixture.packets[0], fault: .beforeCommit) }
        let unchanged = try await vault.currentRevision()
        XCTAssertEqual(unchanged, 0)
        await vault.close()
        let retry = try DurableVault.open(directory: directory, vaultID: id)
        let empty = try await retry.pendingMessages()
        XCTAssertTrue(empty.isEmpty)
        let accepted = try await retry.receive(packet: fixture.packets[0])
        XCTAssertTrue(accepted.plaintext == fixture.expected[0])
        await expect(.commitUncertain) { _ = try await retry.receive(packet: fixture.packets[1], fault: .afterCommit) }
        await expect(.requiresReopen) { _ = try await retry.pendingMessages() }
        await retry.close()
        let reconciled = try DurableVault.open(directory: directory, vaultID: id)
        let pending = try await reconciled.pendingMessages()
        XCTAssertEqual(pending.count, 2)
        XCTAssertTrue(pending[1].plaintext == fixture.expected[1])
        await expect(.mlsRejected) { _ = try await reconciled.receive(packet: fixture.packets[1]) }
        await reconciled.close()
    }

    func testIndependentConnectionsRejectStaleReceiveAndAcknowledgement() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let first = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        let stale = try DurableVault.open(directory: directory, vaultID: id)
        let event = try await first.receive(packet: fixture.packets[0])
        await expect(.staleRevision) { _ = try await stale.receive(packet: fixture.packets[0]) }
        await stale.close()
        let current = try DurableVault.open(directory: directory, vaultID: id)
        _ = try await current.receive(packet: fixture.packets[1])
        await expect(.staleRevision) { try await first.acknowledge(messageID: event.id) }
        await first.close()
        await current.close()
        let reopened = try DurableVault.open(directory: directory, vaultID: id)
        let pending = try await reopened.pendingMessages()
        XCTAssertEqual(pending.count, 2)
        await reopened.close()
    }

    func testBoundedInboxDoesNotConsumeRejectedPacket() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot, maxPending: 1)
        let first = try await vault.receive(packet: fixture.packets[0])
        await expect(.inboxFull) { _ = try await vault.receive(packet: fixture.packets[1]) }
        await expect(.injectedRollback) { try await vault.acknowledge(messageID: first.id, fault: .beforeCommit) }
        let retained = try await vault.pendingMessages()
        XCTAssertEqual(retained.count, 1)
        try await vault.acknowledge(messageID: first.id)
        let second = try await vault.receive(packet: fixture.packets[1])
        XCTAssertTrue(second.plaintext == fixture.expected[1])
        await vault.close()
    }

    func testMissingKeyAndWrongKeyFailClosed() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        await vault.close()
        let keys = VaultKeyStore(vaultID: id.uuidString.lowercased())
        try keys.delete()
        XCTAssertThrowsError(try DurableVault.open(directory: directory, vaultID: id)) { error in
            XCTAssertEqual(error as? VaultError, .missingKey)
        }
        XCTAssertThrowsError(try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot))
        let keyStillExists = try keys.load() != nil
        XCTAssertFalse(keyStillExists)
        _ = try keys.createIfMissing()
        XCTAssertThrowsError(try DurableVault.open(directory: directory, vaultID: id)) { error in
            XCTAssertEqual(error as? VaultError, .authentication)
        }
    }

    func testCiphertextRevisionAndVaultIdentityTamperRejected() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        await vault.close()
        let database = directory.appendingPathComponent("vault.sqlite")
        var connection: OpaquePointer?
        XCTAssertEqual(sqlite3_open(database.path, &connection), SQLITE_OK)
        defer { sqlite3_close(connection) }
        var query: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, "SELECT ciphertext FROM vault", -1, &query, nil), SQLITE_OK)
        XCTAssertEqual(sqlite3_step(query), SQLITE_ROW)
        let bytes = try XCTUnwrap(sqlite3_column_blob(query, 0))
        let encrypted = Data(bytes: bytes, count: Int(sqlite3_column_bytes(query, 0)))
        sqlite3_finalize(query)
        var tampered = encrypted
        tampered[tampered.count - 1] ^= 1
        try setCiphertext(tampered, connection: connection)
        XCTAssertThrowsError(try DurableVault.open(directory: directory, vaultID: id))
        try setCiphertext(encrypted, connection: connection)
        XCTAssertEqual(sqlite3_exec(connection, "UPDATE vault SET revision=1", nil, nil, nil), SQLITE_OK)
        XCTAssertThrowsError(try DurableVault.open(directory: directory, vaultID: id))
        XCTAssertEqual(sqlite3_exec(connection, "UPDATE vault SET revision=0, vault_id='wrong'", nil, nil, nil), SQLITE_OK)
        XCTAssertThrowsError(try DurableVault.open(directory: directory, vaultID: id))
    }

    func testFilesAndKeychainProtectionAndNoRawSnapshotOnDisk() async throws {
        let fixture = try RustMLS.fixture()
        let (directory, id) = try location()
        defer { cleanup(directory, id) }
        let vault = try DurableVault.create(directory: directory, vaultID: id, initialSnapshot: fixture.snapshot)
        _ = try await vault.receive(packet: fixture.packets[0])
        let backup = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(backup.isExcludedFromBackup, true)
        for suffix in ["", "-wal", "-shm"] {
            let url = directory.appendingPathComponent("vault.sqlite\(suffix)")
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let protection = (attributes[.protectionKey] as? FileProtectionType)?.rawValue
                ?? (attributes[.protectionKey] as? String)
            #if targetEnvironment(simulator)
            // Simulator accepts the policy setter but may expose no Data Protection metadata.
            // This still checks any reported policy; physical lock enforcement remains unverified.
            XCTAssertTrue(protection == nil || protection == FileProtectionType.complete.rawValue)
            #else
            XCTAssertEqual(protection, FileProtectionType.complete.rawValue, "File protection metadata for database sidecar \(suffix)")
            #endif
            let flags = try url.resourceValues(forKeys: [.isExcludedFromBackupKey])
            XCTAssertEqual(flags.isExcludedFromBackup, true)
            let stored = try Data(contentsOf: url)
            XCTAssertTrue(stored.range(of: fixture.snapshot) == nil)
            XCTAssertTrue(stored.range(of: Data(fixture.snapshot.base64EncodedString().utf8)) == nil)
            XCTAssertTrue(stored.range(of: fixture.expected[0]) == nil)
        }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: "squadtime.proof.vault",
                                    kSecAttrAccount as String: id.uuidString.lowercased(),
                                    kSecReturnAttributes as String: true]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)
        let attributes = try XCTUnwrap(result as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
        await vault.close()
    }

    private func setCiphertext(_ data: Data, connection: OpaquePointer?) throws {
        var statement: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, "UPDATE vault SET ciphertext=?", -1, &statement, nil), SQLITE_OK)
        defer { sqlite3_finalize(statement) }
        let status = data.withUnsafeBytes {
            sqlite3_bind_blob(statement, 1, $0.baseAddress, Int32(data.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        XCTAssertEqual(status, SQLITE_OK)
        XCTAssertEqual(sqlite3_step(statement), SQLITE_DONE)
    }

    private func expect(_ expected: VaultError, _ operation: () async throws -> Void,
                        file: StaticString = #filePath, line: UInt = #line) async {
        do { try await operation(); XCTFail("Expected rejection", file: file, line: line) }
        catch { XCTAssertEqual(error as? VaultError, expected, file: file, line: line) }
    }
}
