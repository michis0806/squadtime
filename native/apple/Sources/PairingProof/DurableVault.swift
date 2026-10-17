import CryptoKit
import Foundation
import SQLite3

public struct AcceptedMessage: Codable, Equatable, Sendable {
    public let id: String
    public let plaintext: Data
    public let senderIndex: UInt32
}

private struct VaultPayload: Codable {
    var snapshot: Data
    var inbox: [AcceptedMessage]
}

/// Development fault injection only. Neither failure returns accepted plaintext.
public enum VaultCommitFault: Sendable { case none, beforeCommit, afterCommit }

/// One encrypted row contains the entire MLS snapshot and pending inbox.
/// Each instance owns an independent SQLite connection; revision CAS rejects stale writers.
public actor DurableVault {
    private let database: VaultDatabase
    private let key: SymmetricKey
    private let vaultID: String
    private let maxPending: Int
    private var revision: Int64
    private var payload: VaultPayload
    private var uncertain = false

    private init(database: VaultDatabase, key: SymmetricKey, vaultID: String,
                 revision: Int64, payload: VaultPayload, maxPending: Int) {
        self.database = database; self.key = key; self.vaultID = vaultID
        self.revision = revision; self.payload = payload; self.maxPending = maxPending
    }

    /// Directory must be dedicated to this vault. Creation never overwrites a database.
    /// A crash leaving an incomplete database fails closed; no automatic state reset.
    public static func create(directory: URL, vaultID: UUID, initialSnapshot: Data,
                              maxPending: Int = 32) throws -> DurableVault {
        guard (1...32).contains(maxPending), !initialSnapshot.isEmpty,
              initialSnapshot.count <= 8 * 1024 * 1024 else { throw VaultError.malformed }
        let path = directory.appendingPathComponent("vault.sqlite")
        guard !FileManager.default.fileExists(atPath: path.path) else { throw VaultError.alreadyExists }
        let id = vaultID.uuidString.lowercased()
        // Key first: an interrupted creation may leave an orphan key, never a silently replaced key.
        let key = try VaultKeyStore(vaultID: id).createIfMissing()
        let database = try VaultDatabase(directory: directory, create: true)
        let payload = VaultPayload(snapshot: initialSnapshot, inbox: [])
        let encrypted = try seal(payload, key: key, vaultID: id, revision: 0)
        try database.insert(vaultID: id, encrypted: encrypted)
        return DurableVault(database: database, key: key, vaultID: id, revision: 0,
                            payload: payload, maxPending: maxPending)
    }

    public static func open(directory: URL, vaultID: UUID, maxPending: Int = 32) throws -> DurableVault {
        guard (1...32).contains(maxPending) else { throw VaultError.malformed }
        guard FileManager.default.fileExists(atPath: directory.appendingPathComponent("vault.sqlite").path)
        else { throw VaultError.missingDatabase }
        let id = vaultID.uuidString.lowercased()
        guard let key = try VaultKeyStore(vaultID: id).load() else { throw VaultError.missingKey }
        let database = try VaultDatabase(directory: directory, create: false)
        let row = try database.read(vaultID: id)
        let payload = try unseal(row.encrypted, key: key, vaultID: id, revision: row.revision)
        return DurableVault(database: database, key: key, vaultID: id, revision: row.revision,
                            payload: payload, maxPending: maxPending)
    }

    /// No display data is returned until snapshot+inbox commit succeeds.
    public func receive(packet: Data, fault: VaultCommitFault = .none) throws -> AcceptedMessage {
        try checkUsable()
        guard payload.inbox.count < maxPending else { throw VaultError.inboxFull }
        let received = try RustMLS.receive(snapshot: payload.snapshot, packet: packet)
        let event = AcceptedMessage(id: Data(SHA256.hash(data: packet)).hex,
                                    plaintext: received.plaintext, senderIndex: received.senderIndex)
        guard !payload.inbox.contains(where: { $0.id == event.id }) else { throw VaultError.mlsRejected }
        var next = payload
        next.snapshot = received.snapshot
        next.inbox.append(event)
        guard next.inbox.reduce(0, { $0 + $1.plaintext.count }) <= 2 * 1024 * 1024 else { throw VaultError.inboxFull }
        try commit(next, fault: fault)
        return event
    }

    /// Reopen after a restart or uncertain commit to reconcile the durable pending inbox.
    /// UI delivery is at least once until acknowledge succeeds; it is not exactly-once rendering.
    public func pendingMessages() throws -> [AcceptedMessage] {
        try checkUsable()
        return payload.inbox
    }

    public func acknowledge(messageID: String, fault: VaultCommitFault = .none) throws {
        try checkUsable()
        guard payload.inbox.contains(where: { $0.id == messageID }) else { throw VaultError.unknownMessage }
        var next = payload
        next.inbox.removeAll { $0.id == messageID }
        try commit(next, fault: fault)
    }

    public func currentRevision() throws -> Int64 { try checkUsable(); return revision }

    public func close() {
        database.close()
        uncertain = true
    }

    private func checkUsable() throws {
        guard !uncertain else { throw VaultError.requiresReopen }
    }

    private func commit(_ next: VaultPayload, fault: VaultCommitFault) throws {
        guard revision < Int64.max else { throw VaultError.malformed }
        let nextRevision = revision + 1
        let encrypted = try Self.seal(next, key: key, vaultID: vaultID, revision: nextRevision)
        do {
            try database.compareAndSwap(vaultID: vaultID, expectedRevision: revision,
                                        encrypted: encrypted, fault: fault)
        } catch VaultError.commitUncertain {
            uncertain = true
            throw VaultError.commitUncertain
        } catch VaultError.staleRevision {
            uncertain = true
            throw VaultError.staleRevision
        }
        // Only publish the in-memory transition after the durable commit.
        revision = nextRevision
        payload = next
    }

    private static func aad(vaultID: String, revision: Int64) -> Data {
        Data("squadtime-vault-v1\n\(vaultID)\n\(revision)\n".utf8)
    }

    private static func seal(_ payload: VaultPayload, key: SymmetricKey, vaultID: String, revision: Int64) throws -> Data {
        let bytes = try JSONEncoder().encode(payload)
        guard let combined = try AES.GCM.seal(bytes, using: key, authenticating: aad(vaultID: vaultID, revision: revision)).combined
        else { throw VaultError.authentication }
        return combined
    }

    private static func unseal(_ encrypted: Data, key: SymmetricKey, vaultID: String, revision: Int64) throws -> VaultPayload {
        do {
            guard encrypted.count <= 16 * 1024 * 1024, revision >= 0 else { throw VaultError.malformed }
            let bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: encrypted), using: key,
                                         authenticating: aad(vaultID: vaultID, revision: revision))
            let payload = try JSONDecoder().decode(VaultPayload.self, from: bytes)
            guard !payload.snapshot.isEmpty, payload.snapshot.count <= 8 * 1024 * 1024,
                  payload.inbox.count <= 32, payload.inbox.reduce(0, { $0 + $1.plaintext.count }) <= 2 * 1024 * 1024
            else { throw VaultError.malformed }
            return payload
        } catch { throw VaultError.authentication }
    }
}

/// Connections are owned by one vault actor and never shared. No SQL includes secret values.
private final class VaultDatabase {
    private var handle: OpaquePointer?
    private let directory: URL
    private var transient: sqlite3_destructor_type { unsafeBitCast(-1, to: sqlite3_destructor_type.self) }

    init(directory: URL, create: Bool) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.protectionKey: FileProtectionType.complete])
        var protectedDirectory = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try protectedDirectory.setResourceValues(values)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: directory.path)
        let path = directory.appendingPathComponent("vault.sqlite").path
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | (create ? SQLITE_OPEN_CREATE : 0)
        let status = sqlite3_open_v2(path, &handle, flags, nil)
        guard status == SQLITE_OK else {
            sqlite3_close_v2(handle); handle = nil
            throw VaultError.sqlite(status)
        }
        do {
            try execute("PRAGMA busy_timeout=1000")
            try execute("PRAGMA journal_mode=WAL")
            try execute("PRAGMA synchronous=FULL")
            try execute("PRAGMA fullfsync=ON")
            try execute("PRAGMA checkpoint_fullfsync=ON")
            try execute("PRAGMA temp_store=MEMORY")
            guard try scalar("PRAGMA journal_mode") == "wal",
                  try scalar("PRAGMA synchronous") == "2",
                  try scalar("PRAGMA fullfsync") == "1",
                  try scalar("PRAGMA checkpoint_fullfsync") == "1" else { throw VaultError.malformed }
            if create {
                try execute("CREATE TABLE IF NOT EXISTS vault (slot INTEGER PRIMARY KEY CHECK(slot=1), vault_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0), ciphertext BLOB NOT NULL)")
            }
            try protectFiles()
        } catch { close(); throw error }
    }

    deinit { close() }
    func close() {
        if let handle { sqlite3_close_v2(handle); self.handle = nil }
    }

    private func execute(_ sql: String) throws {
        let status = sqlite3_exec(handle, sql, nil, nil, nil)
        guard status == SQLITE_OK else { throw VaultError.sqlite(status) }
    }

    private func statement(_ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        let status = sqlite3_prepare_v2(handle, sql, -1, &statement, nil)
        guard status == SQLITE_OK, let statement else { throw VaultError.sqlite(status) }
        return statement
    }

    private func scalar(_ sql: String) throws -> String {
        let query = try statement(sql)
        defer { sqlite3_finalize(query) }
        guard sqlite3_step(query) == SQLITE_ROW, let bytes = sqlite3_column_text(query, 0)
        else { throw VaultError.malformed }
        return String(cString: bytes)
    }

    private func bind(_ text: String, at index: Int32, to statement: OpaquePointer) throws {
        let status = sqlite3_bind_text(statement, index, text, -1, transient)
        guard status == SQLITE_OK else { throw VaultError.sqlite(status) }
    }

    private func bind(_ data: Data, at index: Int32, to statement: OpaquePointer) throws {
        let status = data.withUnsafeBytes { sqlite3_bind_blob(statement, index, $0.baseAddress, Int32(data.count), transient) }
        guard status == SQLITE_OK else { throw VaultError.sqlite(status) }
    }

    func insert(vaultID: String, encrypted: Data) throws {
        try execute("BEGIN IMMEDIATE")
        do {
            let insert = try statement("INSERT INTO vault(slot,vault_id,revision,ciphertext) VALUES(1,?,0,?)")
            defer { sqlite3_finalize(insert) }
            try bind(vaultID, at: 1, to: insert)
            try bind(encrypted, at: 2, to: insert)
            let status = sqlite3_step(insert)
            guard status == SQLITE_DONE else { throw VaultError.sqlite(status) }
            try protectFiles()
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
    }

    func read(vaultID: String) throws -> (revision: Int64, encrypted: Data) {
        let query = try statement("SELECT revision,ciphertext FROM vault WHERE slot=1 AND vault_id=?")
        defer { sqlite3_finalize(query) }
        try bind(vaultID, at: 1, to: query)
        let status = sqlite3_step(query)
        guard status == SQLITE_ROW else { throw VaultError.sqlite(status) }
        guard sqlite3_column_type(query, 0) == SQLITE_INTEGER else { throw VaultError.malformed }
        let count = sqlite3_column_bytes(query, 1)
        guard count > 0, count <= 16 * 1024 * 1024, let bytes = sqlite3_column_blob(query, 1) else { throw VaultError.malformed }
        return (sqlite3_column_int64(query, 0), Data(bytes: bytes, count: Int(count)))
    }

    func compareAndSwap(vaultID: String, expectedRevision: Int64, encrypted: Data, fault: VaultCommitFault) throws {
        try execute("BEGIN IMMEDIATE")
        var committed = false
        defer { if !committed { try? execute("ROLLBACK") } }
        let update = try statement("UPDATE vault SET revision=?,ciphertext=? WHERE slot=1 AND vault_id=? AND revision=?")
        defer { sqlite3_finalize(update) }
        guard sqlite3_bind_int64(update, 1, expectedRevision + 1) == SQLITE_OK,
              sqlite3_bind_int64(update, 4, expectedRevision) == SQLITE_OK else { throw VaultError.malformed }
        try bind(encrypted, at: 2, to: update)
        try bind(vaultID, at: 3, to: update)
        let status = sqlite3_step(update)
        guard status == SQLITE_DONE else { throw VaultError.sqlite(status) }
        guard sqlite3_changes(handle) == 1 else { throw VaultError.staleRevision }
        try protectFiles()
        if fault == .beforeCommit { throw VaultError.injectedRollback }
        do { try execute("COMMIT") }
        catch { throw VaultError.commitUncertain }
        committed = true
        if fault == .afterCommit { throw VaultError.commitUncertain }
    }

    private func protectFiles() throws {
        for suffix in ["", "-wal", "-shm"] {
            var url = directory.appendingPathComponent("vault.sqlite\(suffix)")
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try url.setResourceValues(values)
        }
    }
}
