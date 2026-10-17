import CryptoKit
import Foundation

/// Internal storage owned by one admission actor. The payload schema is separate from DurableVault.
/// Secret phase state and its exact public outbox are encrypted and committed together.
final class AdmissionStorage {
    private let database: VaultDatabase
    private let key: SymmetricKey
    private let id: String
    private var revision: Int64
    private var unusable = false

    private init(database: VaultDatabase, key: SymmetricKey, id: String, revision: Int64) {
        self.database = database; self.key = key; self.id = id; self.revision = revision
    }

    static func create<T: Encodable>(directory: URL, id: UUID, payload: T) throws -> AdmissionStorage {
        guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite").path)
        else { throw VaultError.alreadyExists }
        let identifier = id.uuidString.lowercased()
        let key = try VaultKeyStore(vaultID: identifier, purpose: .admission).createIfMissing()
        let database = try VaultDatabase(directory: directory, create: true, fileName: "admission.sqlite")
        let encrypted = try seal(payload, key: key, id: identifier, revision: 0)
        try database.insert(vaultID: identifier, encrypted: encrypted)
        return AdmissionStorage(database: database, key: key, id: identifier, revision: 0)
    }

    static func open<T: Decodable>(directory: URL, id: UUID, as type: T.Type) throws -> (AdmissionStorage, T) {
        guard FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite").path)
        else { throw VaultError.missingDatabase }
        let identifier = id.uuidString.lowercased()
        guard let key = try VaultKeyStore(vaultID: identifier, purpose: .admission).load() else { throw VaultError.missingKey }
        let database = try VaultDatabase(directory: directory, create: false, fileName: "admission.sqlite")
        let row = try database.read(vaultID: identifier)
        do {
            guard row.revision >= 0, row.encrypted.count <= 16 * 1024 * 1024 else { throw VaultError.authentication }
            let bytes = try AES.GCM.open(AES.GCM.SealedBox(combined: row.encrypted), using: key,
                                         authenticating: aad(id: identifier, revision: row.revision))
            let payload = try JSONDecoder().decode(type, from: bytes)
            return (AdmissionStorage(database: database, key: key, id: identifier, revision: row.revision), payload)
        } catch { throw VaultError.authentication }
    }

    /// A staged Rust transition and outbox must never be exposed before this returns successfully.
    func commit<T: Encodable>(_ payload: T, fault: VaultCommitFault = .none) throws {
        try ensureUsable()
        guard revision < Int64.max else { throw VaultError.malformed }
        let encrypted = try Self.seal(payload, key: key, id: id, revision: revision + 1)
        do {
            try database.compareAndSwap(vaultID: id, expectedRevision: revision, encrypted: encrypted, fault: fault)
        } catch VaultError.commitUncertain {
            unusable = true
            throw VaultError.commitUncertain
        } catch VaultError.staleRevision {
            unusable = true
            throw VaultError.staleRevision
        }
        revision += 1
    }

    func ensureUsable() throws {
        guard !unusable else { throw VaultError.requiresReopen }
    }

    func currentRevision() throws -> Int64 { try ensureUsable(); return revision }
    func close() { database.close(); unusable = true }

    private static func aad(id: String, revision: Int64) -> Data {
        Data("squadtime-admission-v1\n\(id)\n\(revision)\n".utf8)
    }

    private static func seal<T: Encodable>(_ payload: T, key: SymmetricKey, id: String, revision: Int64) throws -> Data {
        let bytes = try JSONEncoder().encode(payload)
        guard bytes.count <= 16 * 1024 * 1024 - 28,
              let combined = try AES.GCM.seal(bytes, using: key, authenticating: aad(id: id, revision: revision)).combined
        else { throw VaultError.malformed }
        return combined
    }
}
