import CryptoKit
import Foundation
import Security

private let maxJSONInteger: Int64 = 9_007_199_254_740_991

public struct PairingRequest: Codable, Equatable, Sendable {
    public var version: Int
    public var requestId: String
    public var deviceId: String
    public var challenge: String
    public var publicKey: String
    public var issuedAt: Int64
    public var expiresAt: Int64
    public var signature: String

    public init(version: Int = 1, requestId: String, deviceId: String, challenge: String,
                publicKey: String, issuedAt: Int64, expiresAt: Int64, signature: String) {
        self.version = version; self.requestId = requestId; self.deviceId = deviceId
        self.challenge = challenge; self.publicKey = publicKey
        self.issuedAt = issuedAt; self.expiresAt = expiresAt; self.signature = signature
    }

    public var transcript: Data {
        Data("squadtime-pairing-request-v1\n\(requestId)\n\(deviceId)\n\(challenge)\n\(publicKey)\n\(issuedAt)\n\(expiresAt)\n".utf8)
    }
    public var digest: String { Data(SHA256.hash(data: transcript)).hex }

    public static func create(key: DeviceKeyStore, deviceId: UUID, now: Int64, lifetime: Int64 = 120) throws -> Self {
        guard now >= 0, now <= maxJSONInteger - 300, lifetime > 0, lifetime <= 300 else { throw ProofError.malformed }
        var challenge = Data(count: 32)
        let status = challenge.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw ProofError.crypto }
        var request = Self(requestId: UUID().uuidString.lowercased(), deviceId: deviceId.uuidString.lowercased(),
                           challenge: challenge.hex, publicKey: try key.createIfMissing(),
                           issuedAt: now, expiresAt: now + lifetime, signature: "")
        request.signature = try key.sign(request.transcript)
        return request
    }

    public func validate(now: Int64) throws {
        guard version == 1, Self.validUUID(requestId), Self.validUUID(deviceId),
              challenge.count == 64, try Data(strictHex: challenge).count == 32,
              issuedAt >= 0, expiresAt <= maxJSONInteger, expiresAt > issuedAt,
              expiresAt - issuedAt <= 300 else { throw ProofError.malformed }
        guard now >= issuedAt, now < expiresAt else { throw ProofError.expired }
        try PairingCrypto.verify(signature: signature, message: transcript, publicKey: publicKey)
    }

    private static func validUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

public struct PairingApproval: Codable, Equatable, Sendable {
    public var version: Int
    public var requestId: String
    public var requestDigest: String
    public var approverPublicKey: String
    public var signature: String

    public init(version: Int = 1, requestId: String, requestDigest: String, approverPublicKey: String, signature: String) {
        self.version = version; self.requestId = requestId; self.requestDigest = requestDigest
        self.approverPublicKey = approverPublicKey; self.signature = signature
    }

    public var transcript: Data {
        Data("squadtime-pairing-approval-v1\n\(requestId)\n\(requestDigest)\n\(approverPublicKey)\n".utf8)
    }

    /// The caller must obtain deliberate approval in its own UI before passing true.
    /// This proof does not establish how the trusted device itself was authorized.
    public static func approve(_ request: PairingRequest, key: DeviceKeyStore,
                               now: Int64, userConfirmed: Bool) throws -> Self {
        guard userConfirmed else { throw ProofError.notConfirmed }
        try request.validate(now: now)
        var approval = Self(requestId: request.requestId, requestDigest: request.digest,
                            approverPublicKey: try key.createIfMissing(), signature: "")
        approval.signature = try key.sign(approval.transcript)
        return approval
    }
}

public enum PairingCrypto {
    public static func verify(signature: String, message: Data, publicKey: String) throws {
        guard publicKey.count == 130, signature.count <= 144 else { throw ProofError.malformed }
        let bytes = try Data(strictHex: publicKey)
        guard bytes.count == 65, bytes.first == 4 else { throw ProofError.malformed }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                         kSecAttrKeySizeInBits as String: 256]
        guard let key = SecKeyCreateWithData(bytes as CFData, attributes as CFDictionary, nil) else {
            throw ProofError.malformed
        }
        let der = try Data(strictHex: signature)
        // CryptoKit enforces DER framing; round-trip rejects trailing/noncanonical data.
        guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: der),
              parsed.derRepresentation == der else { throw ProofError.malformed }
        guard SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, der as CFData, nil)
        else { throw ProofError.crypto }
    }
}

/// Only in-memory, atomic single-use pending state. No restart-persistent replay guarantee.
public actor PairingCoordinator {
    private var pending: [String: PairingRequest] = [:]
    public init() {}

    public func begin(key: DeviceKeyStore, deviceId: UUID, now: Int64) throws -> PairingRequest {
        let request = try PairingRequest.create(key: key, deviceId: deviceId, now: now)
        pending[request.requestId] = request
        return request
    }

    /// The pinned approver key must come from a separately established trust channel.
    /// An invalid attempt never consumes the pending request.
    public func receive(_ approval: PairingApproval, trustedApproverPublicKey: String, now: Int64) throws -> PairingRequest {
        guard let request = pending[approval.requestId] else { throw ProofError.noPending }
        try request.validate(now: now)
        guard approval.version == 1, approval.requestDigest == request.digest else { throw ProofError.malformed }
        guard approval.approverPublicKey == trustedApproverPublicKey else { throw ProofError.untrusted }
        try PairingCrypto.verify(signature: approval.signature, message: approval.transcript, publicKey: trustedApproverPublicKey)
        pending.removeValue(forKey: request.requestId)
        return request
    }
}
