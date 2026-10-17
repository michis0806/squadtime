import CryptoKit
import Foundation
import Security

/// AES wrapping key in Keychain, not a Secure Enclave AES key. No public export API.
struct VaultKeyStore {
    enum Purpose: String {
        case vault = "squadtime.proof.vault"
        case admission = "squadtime.proof.admission"
    }
    let vaultID: String
    private let purpose: Purpose
    init(vaultID: String, purpose: Purpose = .vault) {
        self.vaultID = vaultID
        self.purpose = purpose
    }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: purpose.rawValue,
         kSecAttrAccount as String: vaultID,
         kSecAttrSynchronizable as String: false]
    }

    func load() throws -> SymmetricKey? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
        guard let data = result as? Data, data.count == 32 else { throw VaultError.malformed }
        return SymmetricKey(data: data)
    }

    func createIfMissing() throws -> SymmetricKey {
        if let existing = try load() { return existing }
        var data = Data(count: 32)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(attributes as CFDictionary, nil)
        if added == errSecDuplicateItem, let existing = try load() { return existing }
        guard added == errSecSuccess else { throw VaultError.keychain(added) }
        return SymmetricKey(data: data)
    }

    // Internal scoped cleanup; deleting a key never resets an existing database.
    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychain(status) }
    }
}
