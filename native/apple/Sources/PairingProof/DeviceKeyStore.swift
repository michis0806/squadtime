import Foundation
import Security

public enum ProofError: Error, Equatable {
    case invalidAlias, keychain(OSStatus), crypto, malformed, expired, notConfirmed, untrusted, noPending
}

/// P-256 signing only. Private SecKey references never leave this type and are never exported.
/// Physical builds always require Secure Enclave; there is no silent software downgrade.
public struct DeviceKeyStore: Sendable {
    public enum Protection: String, Sendable { case secureEnclave, simulatorSoftware }
    private let tag: Data
    public let protection: Protection

    public init(alias: String) throws {
        guard !alias.isEmpty, alias.count <= 100,
              alias.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 })
        else { throw ProofError.invalidAlias }
        tag = Data("squadtime.proof.\(alias)".utf8)
        #if targetEnvironment(simulator)
        protection = .simulatorSoftware
        #else
        protection = .secureEnclave
        #endif
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
         kSecAttrApplicationTag as String: tag]
    }

    private func load() throws -> SecKey? {
        var request = query
        request[kSecReturnRef as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let result else { throw ProofError.keychain(status) }
        let key = result as! SecKey
        // Refuse a pre-existing software key in a physical build.
        #if !targetEnvironment(simulator)
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        guard attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
        else { throw ProofError.crypto }
        #endif
        return key
    }

    /// Creates a permanent scoped key if missing. Callers serialize lifecycle operations per alias.
    @discardableResult
    public func createIfMissing() throws -> String {
        if let key = try load() { return try publicKey(key) }
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        #if targetEnvironment(simulator)
        privateAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #else
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                         .privateKeyUsage, &accessError)
        else { throw ProofError.crypto }
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        privateAttributes[kSecAttrAccessControl as String] = access
        #endif
        attributes[kSecPrivateKeyAttrs as String] = privateAttributes
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let existing = try load() { return try publicKey(existing) }
            throw ProofError.crypto
        }
        return try publicKey(key)
    }

    public func publicKeyHex() throws -> String {
        guard let key = try load() else { throw ProofError.keychain(errSecItemNotFound) }
        return try publicKey(key)
    }

    private func publicKey(_ privateKey: SecKey) throws -> String {
        guard let key = SecKeyCopyPublicKey(privateKey),
              let bytes = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              bytes.count == 65, bytes.first == 4 else { throw ProofError.crypto }
        return bytes.hex
    }

    public func sign(_ message: Data) throws -> String {
        guard let key = try load() else { throw ProofError.keychain(errSecItemNotFound) }
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, nil)
        else { throw ProofError.crypto }
        return (signature as Data).hex
    }

    public func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ProofError.keychain(status) }
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    init(strictHex: String) throws {
        guard !strictHex.isEmpty, strictHex.count % 2 == 0,
              strictHex.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw ProofError.malformed }
        var data = Data()
        var index = strictHex.startIndex
        while index < strictHex.endIndex {
            let end = strictHex.index(index, offsetBy: 2)
            guard let byte = UInt8(strictHex[index..<end], radix: 16) else { throw ProofError.malformed }
            data.append(byte)
            index = end
        }
        self = data
    }
}
