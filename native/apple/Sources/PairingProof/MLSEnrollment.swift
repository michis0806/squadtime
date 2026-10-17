import CryptoKit
import Foundation

public enum EnrollmentError: Error, Equatable { case alreadyPending, contextMismatch }

/// Public local-proof context. Rust retains both synthetic MLS participants in this process.
/// This is not a portable independent-device onboarding request.
public struct MLSEnrollmentContext: Codable, Equatable, Sendable {
    public var pendingId: Data
    public var groupId: Data
    public var keyPackage: Data
    public var request: Data
    public var approval: Data

    func validate(devicePublicKey: Data, approverPublicKey: Data, now: Int64,
                  expectedIssuedAt: Int64? = nil) throws {
        guard pendingId.count == 32, (1...256).contains(groupId.count),
              !keyPackage.isEmpty, keyPackage.count <= 1024 * 1024,
              request.count <= 4096, approval.count <= 1024,
              let requestText = String(data: request, encoding: .utf8),
              let approvalText = String(data: approval, encoding: .utf8) else { throw ProofError.malformed }
        let fields = requestText.components(separatedBy: "\n")
        guard fields.count == 11,
              fields[0] == "squadtime-mls-device-request-v1",
              fields[1] == pendingId.base64EncodedString(),
              fields[2] == groupId.base64EncodedString(),
              fields[3] == Data(SHA256.hash(data: keyPackage)).hex,
              Self.isDigest(fields[4]), Self.isDigest(fields[5]),
              fields[6] == devicePublicKey.base64EncodedString(),
              fields[7] == approverPublicKey.base64EncodedString(), fields[10].isEmpty,
              let issuedAt = Int64(fields[8]), String(issuedAt) == fields[8],
              let expiresAt = Int64(fields[9]), String(expiresAt) == fields[9],
              issuedAt >= 0, issuedAt <= 9_007_199_254_740_691,
              expiresAt == issuedAt + 300,
              expectedIssuedAt == nil || expectedIssuedAt == issuedAt else { throw ProofError.malformed }
        guard now >= issuedAt, now < expiresAt else { throw ProofError.expired }
        let approved = approvalText.components(separatedBy: "\n")
        guard approved.count == 5,
              approved[0] == "squadtime-mls-device-approval-v1",
              approved[1] == pendingId.base64EncodedString(),
              approved[2] == Data(SHA256.hash(data: request)).hex,
              approved[3] == approverPublicKey.base64EncodedString(), approved[4].isEmpty
        else { throw ProofError.malformed }
    }

    private static func isDigest(_ value: String) -> Bool {
        value.count == 64 && (try? Data(strictHex: value).count) == 32
    }
}

/// Memory-only local binding proof. The Rust bridge holds synthetic admin and joiner state.
/// It validates native signatures before actual MLS Add/Welcome and checks the resulting roster.
public actor MLSEnrollmentCoordinator {
    private struct Pending {
        let context: MLSEnrollmentContext
        let devicePublicKey: Data
        let approverPublicKey: Data
    }
    private var pending: Pending?
    public init() {}

    public func begin(deviceKey: DeviceKeyStore, trustedApproverPublicKeyHex: String,
                      now: Int64) throws -> MLSEnrollmentContext {
        guard pending == nil else { throw EnrollmentError.alreadyPending }
        guard now >= 0, now <= 9_007_199_254_740_691 else { throw ProofError.malformed }
        let devicePublicKey = try Data(strictHex: deviceKey.createIfMissing())
        let approverPublicKey = try Data(strictHex: trustedApproverPublicKeyHex)
        guard approverPublicKey != devicePublicKey,
              approverPublicKey.count == 65, approverPublicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: approverPublicKey)) != nil
        else { throw ProofError.malformed }
        let context: MLSEnrollmentContext = try RustMLS.call([
            "op": "enrollmentprepare", "devicePublicKey": devicePublicKey.base64EncodedString(),
            "approverPublicKey": approverPublicKey.base64EncodedString(), "now": now
        ])
        do {
            try context.validate(devicePublicKey: devicePublicKey, approverPublicKey: approverPublicKey,
                                 now: now, expectedIssuedAt: now)
        } catch {
            try? Self.cancelRust(context.pendingId)
            throw error
        }
        pending = Pending(context: context, devicePublicKey: devicePublicKey, approverPublicKey: approverPublicKey)
        return context
    }

    /// Signs only this coordinator's exact locally prepared context with its expected native device key.
    public func signRequest(_ context: MLSEnrollmentContext, deviceKey: DeviceKeyStore, now: Int64) throws -> Data {
        let current = try checked(context, now: now)
        guard try deviceKey.publicKeyHex() == current.devicePublicKey.hex else { throw ProofError.untrusted }
        return try Data(strictHex: deviceKey.sign(context.request))
    }

    /// Explicit approval, pinned native approver, and valid native request signature are all required.
    /// No generic API signs an arbitrary server-provided transcript.
    public func approve(_ context: MLSEnrollmentContext, requestSignature: Data,
                        approverKey: DeviceKeyStore, now: Int64, userConfirmed: Bool) throws -> Data {
        guard userConfirmed else { throw ProofError.notConfirmed }
        let current = try checked(context, now: now)
        guard try approverKey.publicKeyHex() == current.approverPublicKey.hex else { throw ProofError.untrusted }
        try Self.verify(requestSignature, transcript: context.request, key: current.devicePublicKey)
        return try Data(strictHex: approverKey.sign(context.approval))
    }

    /// Returns secret joined state in memory only. The caller can immediately create DurableVault.
    /// Rust consumes its pending admission on success; this is not an atomic durable admission workflow.
    public func complete(_ context: MLSEnrollmentContext, requestSignature: Data,
                         approvalSignature: Data, now: Int64) throws -> MLSFixture {
        let current = try checked(context, now: now)
        try Self.verify(requestSignature, transcript: context.request, key: current.devicePublicKey)
        try Self.verify(approvalSignature, transcript: context.approval, key: current.approverPublicKey)
        let joined: MLSFixture = try RustMLS.call([
            "op": "enrollmentcomplete", "pendingId": context.pendingId.base64EncodedString(),
            "groupId": context.groupId.base64EncodedString(), "keyPackage": context.keyPackage.base64EncodedString(),
            "requestSignature": requestSignature.base64EncodedString(),
            "approvalSignature": approvalSignature.base64EncodedString(), "now": now
        ])
        // Rust already consumed the handle. Never permit retry if its result shape is invalid.
        pending = nil
        guard !joined.snapshot.isEmpty, joined.snapshot.count <= 8 * 1024 * 1024,
              joined.packets.count == 2, joined.expected.count == 2,
              joined.packets.allSatisfy({ !$0.isEmpty && $0.count <= 1024 * 1024 }),
              joined.expected.allSatisfy({ $0.count <= 1024 * 1024 }) else { throw VaultError.malformed }
        return joined
    }

    public func cancel() throws {
        guard let current = pending else { throw ProofError.noPending }
        // Rust may already have evicted an expired handle. Always release the local slot.
        defer { pending = nil }
        try Self.cancelRust(current.context.pendingId)
    }

    private func checked(_ context: MLSEnrollmentContext, now: Int64) throws -> Pending {
        guard let current = pending else { throw ProofError.noPending }
        guard context == current.context else { throw EnrollmentError.contextMismatch }
        try context.validate(devicePublicKey: current.devicePublicKey, approverPublicKey: current.approverPublicKey, now: now)
        return current
    }

    private static func verify(_ signature: Data, transcript: Data, key: Data) throws {
        guard !signature.isEmpty, signature.count <= 72 else { throw ProofError.malformed }
        try PairingCrypto.verify(signature: signature.hex, message: transcript, publicKey: key.hex)
    }

    private static func cancelRust(_ id: Data) throws {
        struct Result: Decodable { let cancelled: Bool }
        let result: Result = try RustMLS.call(["op": "enrollmentcancel", "pendingId": id.base64EncodedString()])
        guard result.cancelled else { throw VaultError.mlsRejected }
    }
}
