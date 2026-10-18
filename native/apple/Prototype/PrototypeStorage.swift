import CryptoKit
import Foundation
import Security
import PairingProof

enum PrototypeFailure: Error { case unavailable, invalid }

struct PrototypeProfile: Codable, Sendable {
    var nickname: String
    var avatar: String
    var admissionID: UUID?
    var role: String?
    var bootstrap: String?
    var peerKey: Data?
    var manual = false
    var verificationMethod: String?
    var session: String?
    var invitationHash: String?
    var requestHash: String?
    var welcomeHash: String?
    var receipt: Data?
    var expiresAt: Int64?
    var pendingCode: String?
    var contactConfirmed = false
}

/// All profile and pairing pointers are authenticated ciphertext; missing keys never reset data.
actor PrototypeStorage {
    static let service = "dev.squadtime.prototype.profile"
    static let keyAlias = "prototype-device-v1"
    let directory: URL
    private let file: URL
    init() {
        directory = URL.applicationSupportDirectory.appendingPathComponent("SquadtimePrototype", isDirectory: true)
        file = directory.appendingPathComponent("profile.enc")
    }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service,
         kSecAttrAccount as String: "profile-v1", kSecAttrSynchronizable as String: false]
    }
    private func key(create: Bool) throws -> SymmetricKey {
        var request = query
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 { return SymmetricKey(data: data) }
        guard status == errSecItemNotFound, create, !FileManager.default.fileExists(atPath: file.path) else { throw PrototypeFailure.unavailable }
        let key = SymmetricKey(size: .bits256)
        var attributes = query
        attributes[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw PrototypeFailure.unavailable }
        return key
    }
    func load() throws -> PrototypeProfile? {
        guard FileManager.default.fileExists(atPath: file.path) else {
            guard !FileManager.default.fileExists(atPath: directory.path) else { throw PrototypeFailure.unavailable }
            return nil
        }
        let encrypted = try Data(contentsOf: file)
        return try JSONDecoder().decode(PrototypeProfile.self, from: AES.GCM.open(AES.GCM.SealedBox(combined: encrypted), using: key(create: false), authenticating: Data(Self.service.utf8)))
    }
    func save(_ profile: PrototypeProfile) throws {
        let wrappingKey = try key(create: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var protected = directory
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try protected.setResourceValues(values)
        guard let encrypted = try AES.GCM.seal(JSONEncoder().encode(profile), using: wrappingKey, authenticating: Data(Self.service.utf8)).combined else { throw PrototypeFailure.unavailable }
        try encrypted.write(to: file, options: [.atomic, .completeFileProtection])
    }
    func admissionDirectory() -> URL { directory.appendingPathComponent("contact", isDirectory: true) }
    func reset() throws {
        if let id = (try? load())?.admissionID {
            let scoped: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "squadtime.proof.admission", kSecAttrAccount as String: id.uuidString.lowercased(), kSecAttrSynchronizable as String: false]
            let status = SecItemDelete(scoped as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw PrototypeFailure.unavailable }
        }
        // Only this application-scoped directory and exact key identifiers are removed.
        if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw PrototypeFailure.unavailable }
        try DeviceKeyStore(alias: Self.keyAlias).delete()
    }
}
