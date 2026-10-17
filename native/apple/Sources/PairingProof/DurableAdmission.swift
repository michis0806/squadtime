import CryptoKit
import Foundation
import Security

public enum AdmissionRole: String, Codable, Sendable { case owner, joiner }
public enum AdmissionPhase: String, Codable, Sendable { case empty, invitation, request, welcome, joined }

public struct AdmissionOutbox: Codable, Equatable, Sendable {
    public let kind: String
    public let outbox: Data
    public let nativePublicKey: Data
}

struct AdmissionInvitation: Codable {
    let version: Int
    let invitationId: Data
    let groupId: Data
    let adminIdentity: Data
    let adminPublicKey: Data
    let issuedAt: Int64
    let expiresAt: Int64
    let signature: Data
    var transcript: Data {
        AdmissionValidation.lines(["squadtime-mls-invitation-v1", invitationId.base64EncodedString(),
                                   groupId.base64EncodedString(), AdmissionValidation.digest(adminIdentity),
                                   adminPublicKey.base64EncodedString(), String(issuedAt), String(expiresAt)])
    }
}

struct AdmissionRequest: Codable {
    let version: Int
    let requestId: Data
    let invitation: Data
    let keyPackage: Data
    let joinerIdentity: Data
    let devicePublicKey: Data
    let issuedAt: Int64
    let expiresAt: Int64
    let signature: Data
    func transcript(invite: AdmissionInvitation) -> Data {
        AdmissionValidation.lines(["squadtime-mls-admission-request-v1", requestId.base64EncodedString(),
                                   AdmissionValidation.digest(invitation), invite.groupId.base64EncodedString(),
                                   AdmissionValidation.digest(keyPackage), AdmissionValidation.digest(joinerIdentity),
                                   AdmissionValidation.digest(invite.adminIdentity), devicePublicKey.base64EncodedString(),
                                   invite.adminPublicKey.base64EncodedString(), String(issuedAt), String(expiresAt)])
    }
    func approval(invite: AdmissionInvitation) -> Data {
        AdmissionValidation.lines(["squadtime-mls-admission-approval-v1", requestId.base64EncodedString(),
                                   AdmissionValidation.digest(transcript(invite: invite)), AdmissionValidation.digest(invitation),
                                   invite.groupId.base64EncodedString(), AdmissionValidation.digest(invite.adminIdentity),
                                   devicePublicKey.base64EncodedString(), invite.adminPublicKey.base64EncodedString(), String(expiresAt)])
    }
}

struct AdmissionWelcome: Codable {
    let version: Int
    let request: Data
    let approvalSignature: Data
    let welcome: Data
    let probe: Data
}

private struct AdmissionPayload: Codable {
    let role: AdmissionRole
    let nativePublicKey: Data
    let nativeKeyAlias: String
    let trustedAdminPublicKey: Data
    var phase: AdmissionPhase = .empty
    var state = Data()
    var outbox = Data()
    var peerPublicKey: Data?
    var acceptedInputDigest: String?
    var probePacket: Data?
    var inbox: [AcceptedMessage] = []
}

private struct AdmissionDraft: Decodable { let state: Data; let transcript: Data }
private struct AdmissionTransition: Decodable { let state: Data; let outbox: Data; let kind: String }
private struct AdmissionResume: Decodable { let outbox: Data; let kind: String }
private struct AdmissionReceived: Decodable { let state: Data; let plaintext: Data; let senderIndex: UInt32 }

/// Independent owner/joiner secrets exist only in this actor's memory or its encrypted row.
/// Every transition commits the opaque Rust state, exact public outbox and inbox in one CAS.
public actor DurableAdmission {
    private let storage: AdmissionStorage
    private var payload: AdmissionPayload
    private init(storage: AdmissionStorage, payload: AdmissionPayload) { self.storage = storage; self.payload = payload }

    public static func create(directory: URL, id: UUID, role: AdmissionRole, nativeKey: DeviceKeyStore,
                              trustedAdminPublicKey: Data? = nil) throws -> DurableAdmission {
        // An existing database must never trigger native signing-key generation or replacement.
        guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent("admission.sqlite").path)
        else { throw VaultError.alreadyExists }
        let native = try Data(strictHex: nativeKey.createIfMissing())
        let admin = role == .owner ? native : (trustedAdminPublicKey ?? Data())
        try AdmissionValidation.key(admin)
        guard role == .owner || native != admin else { throw ProofError.untrusted }
        let payload = AdmissionPayload(role: role, nativePublicKey: native, nativeKeyAlias: nativeKey.scopedAlias, trustedAdminPublicKey: admin)
        return DurableAdmission(storage: try AdmissionStorage.create(directory: directory, id: id, payload: payload), payload: payload)
    }

    public static func open(directory: URL, id: UUID) throws -> DurableAdmission {
        let (storage, payload) = try AdmissionStorage.open(directory: directory, id: id, as: AdmissionPayload.self)
        do {
            let existing = try DeviceKeyStore(alias: payload.nativeKeyAlias).publicKeyHex()
            guard existing == payload.nativePublicKey.hex else { throw ProofError.untrusted }
        } catch ProofError.keychain(let status) where status == errSecItemNotFound {
            throw VaultError.missingKey
        }
        try validate(payload)
        return DurableAdmission(storage: storage, payload: payload)
    }

    public func ownerStart(nativeKey: DeviceKeyStore, now: Int64, fault: VaultCommitFault = .none) throws -> AdmissionOutbox {
        try require(role: .owner, phase: .empty, nativeKey: nativeKey)
        try AdmissionValidation.time(now)
        let draft: AdmissionDraft = try RustMLS.call(["op": "admissioncreateadmin", "adminPublicKey": payload.nativePublicKey.base64EncodedString(), "now": now])
        try AdmissionValidation.invitationDraft(draft.transcript, native: payload.nativePublicKey, now: now)
        let signature = try Data(strictHex: nativeKey.sign(draft.transcript))
        let result: AdmissionTransition = try RustMLS.call(["op": "admissionpublishinvitation", "state": draft.state.base64EncodedString(),
                                                           "signature": signature.base64EncodedString(), "now": now])
        let invite = try AdmissionValidation.invitation(result.outbox, pin: payload.nativePublicKey, now: now)
        guard invite.transcript == draft.transcript, result.kind == AdmissionPhase.invitation.rawValue else { throw VaultError.malformed }
        return try publish(result, phase: .invitation, input: nil, peer: nil, fault: fault)
    }

    public func joinerStart(invitation: Data, nativeKey: DeviceKeyStore, now: Int64,
                            fault: VaultCommitFault = .none) throws -> AdmissionOutbox {
        try require(role: .joiner, phase: .empty, nativeKey: nativeKey)
        let invite = try AdmissionValidation.invitation(invitation, pin: payload.trustedAdminPublicKey, now: now)
        let draft: AdmissionDraft = try RustMLS.call(["op": "admissioncreatejoiner", "invitation": invitation.base64EncodedString(),
                                                      "trustedAdminPublicKey": payload.trustedAdminPublicKey.base64EncodedString(),
                                                      "devicePublicKey": payload.nativePublicKey.base64EncodedString(), "now": now])
        try AdmissionValidation.requestDraft(draft.transcript, invite: invite, invitation: invitation, native: payload.nativePublicKey, now: now)
        let signature = try Data(strictHex: nativeKey.sign(draft.transcript))
        let result: AdmissionTransition = try RustMLS.call(["op": "admissionpublishrequest", "state": draft.state.base64EncodedString(),
                                                           "signature": signature.base64EncodedString(), "now": now])
        let request = try AdmissionValidation.request(result.outbox, invitation: invitation, devicePin: payload.nativePublicKey,
                                                      adminPin: payload.trustedAdminPublicKey, now: now)
        guard request.transcript(invite: invite) == draft.transcript, result.kind == AdmissionPhase.request.rawValue else { throw VaultError.malformed }
        return try publish(result, phase: .request, input: invitation, peer: nil, fault: fault)
    }

    public func ownerAdmit(request: Data, trustedDevicePublicKey: Data, nativeKey: DeviceKeyStore,
                           now: Int64, userConfirmed: Bool, fault: VaultCommitFault = .none) throws -> AdmissionOutbox {
        guard userConfirmed else { throw ProofError.notConfirmed }
        try require(role: .owner, phase: .invitation, nativeKey: nativeKey)
        try AdmissionValidation.key(trustedDevicePublicKey)
        guard trustedDevicePublicKey != payload.nativePublicKey else { throw ProofError.untrusted }
        let invite = try AdmissionValidation.invitation(payload.outbox, pin: payload.nativePublicKey, now: now)
        let parsed = try AdmissionValidation.request(request, invitation: payload.outbox, devicePin: trustedDevicePublicKey,
                                                     adminPin: payload.nativePublicKey, now: now)
        struct Inspection: Decodable { let transcript: Data }
        let inspection: Inspection = try RustMLS.call(["op": "admissioninspectrequest", "state": payload.state.base64EncodedString(),
                                                       "request": request.base64EncodedString(), "trustedDevicePublicKey": trustedDevicePublicKey.base64EncodedString(), "now": now])
        guard inspection.transcript == parsed.approval(invite: invite) else { throw EnrollmentError.contextMismatch }
        let approval = try Data(strictHex: nativeKey.sign(inspection.transcript))
        let result: AdmissionTransition = try RustMLS.call(["op": "admissionadmit", "state": payload.state.base64EncodedString(),
                                                           "request": request.base64EncodedString(), "trustedDevicePublicKey": trustedDevicePublicKey.base64EncodedString(),
                                                           "approvalSignature": approval.base64EncodedString(), "now": now])
        let welcome = try AdmissionValidation.welcome(result.outbox, request: request, adminPin: payload.nativePublicKey)
        guard welcome.approvalSignature == approval, result.kind == AdmissionPhase.welcome.rawValue else { throw VaultError.malformed }
        return try publish(result, phase: .welcome, input: request, peer: trustedDevicePublicKey, fault: fault)
    }

    /// Joins and authenticates the fixed synthetic probe, then atomically commits joined state+inbox.
    public func join(welcome: Data, now: Int64, fault: VaultCommitFault = .none) throws -> AcceptedMessage {
        try require(role: .joiner, phase: .request)
        try AdmissionValidation.time(now)
        // Delayed delivery is allowed: validity gates owner admission, not an authenticated Welcome's later arrival.
        let parsed = try AdmissionValidation.welcome(welcome, request: payload.outbox, adminPin: payload.trustedAdminPublicKey)
        let joined: AdmissionTransition = try RustMLS.call(["op": "admissionjoin", "state": payload.state.base64EncodedString(),
                                                           "welcome": welcome.base64EncodedString(), "now": now])
        guard joined.kind == AdmissionPhase.joined.rawValue, joined.outbox.isEmpty else { throw VaultError.malformed }
        let received: AdmissionReceived = try RustMLS.call(["op": "admissionreceive", "state": joined.state.base64EncodedString(), "packet": parsed.probe.base64EncodedString()])
        let event = AcceptedMessage(id: AdmissionValidation.digest(parsed.probe), plaintext: received.plaintext, senderIndex: received.senderIndex)
        var next = payload
        next.phase = .joined; next.state = received.state; next.outbox = Data()
        next.acceptedInputDigest = AdmissionValidation.digest(welcome); next.probePacket = parsed.probe; next.inbox = [event]
        try commit(next, fault: fault)
        return event
    }

    public func receive(packet: Data, fault: VaultCommitFault = .none) throws -> AcceptedMessage {
        try storage.ensureUsable()
        guard payload.phase == .joined || payload.phase == .welcome else { throw ProofError.noPending }
        guard packet.count <= 1024 * 1024, payload.inbox.count < 32 else { throw VaultError.inboxFull }
        let received: AdmissionReceived = try RustMLS.call(["op": "admissionreceive", "state": payload.state.base64EncodedString(), "packet": packet.base64EncodedString()])
        let event = AcceptedMessage(id: AdmissionValidation.digest(packet), plaintext: received.plaintext, senderIndex: received.senderIndex)
        var next = payload
        next.state = received.state; next.inbox.append(event)
        try commit(next, fault: fault)
        return event
    }

    public func outbox() throws -> AdmissionOutbox {
        try storage.ensureUsable()
        return AdmissionOutbox(kind: payload.phase.rawValue, outbox: payload.outbox, nativePublicKey: payload.nativePublicKey)
    }
    public func pendingMessages() throws -> [AcceptedMessage] { try storage.ensureUsable(); return payload.inbox }
    public func proofProbePacket() throws -> Data {
        try storage.ensureUsable()
        guard let packet = payload.probePacket else { throw ProofError.noPending }
        return packet
    }
    public func acknowledge(messageID: String, fault: VaultCommitFault = .none) throws {
        try storage.ensureUsable()
        guard payload.inbox.contains(where: { $0.id == messageID }) else { throw VaultError.unknownMessage }
        var next = payload
        next.inbox.removeAll { $0.id == messageID }
        try commit(next, fault: fault)
    }
    public func currentRevision() throws -> Int64 { try storage.currentRevision() }
    public func close() { storage.close() }

    private func require(role: AdmissionRole, phase: AdmissionPhase, nativeKey: DeviceKeyStore? = nil) throws {
        try storage.ensureUsable()
        guard payload.role == role, payload.phase == phase else { throw ProofError.noPending }
        if let nativeKey {
            guard try nativeKey.publicKeyHex() == payload.nativePublicKey.hex else { throw ProofError.untrusted }
        }
    }
    private func publish(_ result: AdmissionTransition, phase: AdmissionPhase, input: Data?, peer: Data?, fault: VaultCommitFault) throws -> AdmissionOutbox {
        var next = payload
        next.phase = phase; next.state = result.state; next.outbox = result.outbox
        next.acceptedInputDigest = input.map(AdmissionValidation.digest); next.peerPublicKey = peer
        try commit(next, fault: fault)
        return try outbox()
    }
    private func commit(_ next: AdmissionPayload, fault: VaultCommitFault) throws {
        try Self.validate(next)
        try storage.commit(next, fault: fault)
        payload = next
    }
    private static func validate(_ payload: AdmissionPayload) throws {
        try AdmissionValidation.key(payload.nativePublicKey)
        try AdmissionValidation.key(payload.trustedAdminPublicKey)
        guard payload.state.count <= 512 * 1024, payload.outbox.count <= 128 * 1024,
              payload.inbox.count <= 32, payload.inbox.reduce(0, { $0 + $1.plaintext.count }) <= 2 * 1024 * 1024,
              payload.inbox.allSatisfy({ $0.plaintext.count <= 1024 * 1024 }),
              payload.probePacket == nil || payload.probePacket!.count <= 1024 * 1024 else { throw VaultError.malformed }
        guard payload.role == .owner ? payload.trustedAdminPublicKey == payload.nativePublicKey : payload.trustedAdminPublicKey != payload.nativePublicKey
        else { throw VaultError.authentication }
        if payload.phase == .empty {
            guard payload.state.isEmpty, payload.outbox.isEmpty, payload.inbox.isEmpty else { throw VaultError.malformed }
            return
        }
        guard !payload.state.isEmpty,
              payload.role == .owner ? [.invitation, .welcome].contains(payload.phase) : [.request, .joined].contains(payload.phase)
        else { throw VaultError.malformed }
        let resumed: AdmissionResume = try RustMLS.call(["op": "admissionresume", "state": payload.state.base64EncodedString()])
        guard resumed.kind == payload.phase.rawValue, resumed.outbox == payload.outbox else { throw VaultError.authentication }
    }
}

enum AdmissionValidation {
    static let expectedProbe = Data("{\"v\":1,\"eventId\":\"independent-admission-probe\",\"type\":\"availability.set\"}".utf8)
    static func digest(_ bytes: Data) -> String { Data(SHA256.hash(data: bytes)).hex }
    static func lines(_ fields: [String]) -> Data { Data((fields.joined(separator: "\n") + "\n").utf8) }
    static func key(_ key: Data) throws {
        guard key.count == 65, key.first == 4, (try? P256.Signing.PublicKey(x963Representation: key)) != nil else { throw ProofError.malformed }
    }
    static func time(_ now: Int64) throws { guard now >= 0, now <= 9_007_199_254_740_991 else { throw ProofError.malformed } }
    static func signature(_ signature: Data, transcript: Data, pin: Data) throws {
        guard (8...72).contains(signature.count) else { throw ProofError.malformed }
        try PairingCrypto.verify(signature: signature.hex, message: transcript, publicKey: pin.hex)
    }
    static func decode<T: Decodable>(_ bytes: Data, as type: T.Type) throws -> T {
        guard !bytes.isEmpty, bytes.count <= 128 * 1024 else { throw ProofError.malformed }
        do { return try JSONDecoder().decode(type, from: bytes) } catch { throw ProofError.malformed }
    }
    static func invitation(_ bytes: Data, pin: Data, now: Int64?) throws -> AdmissionInvitation {
        let invite = try decode(bytes, as: AdmissionInvitation.self)
        guard invite.version == 1, invite.invitationId.count == 32, (1...256).contains(invite.groupId.count),
              !invite.adminIdentity.isEmpty, invite.adminIdentity.count <= 4096,
              invite.adminPublicKey == pin, invite.issuedAt >= 0, invite.issuedAt <= 9_007_199_254_740_691,
              invite.expiresAt == invite.issuedAt + 300 else { throw ProofError.untrusted }
        try key(pin)
        if let now { try time(now); guard invite.issuedAt <= now, now < invite.expiresAt else { throw ProofError.expired } }
        try signature(invite.signature, transcript: invite.transcript, pin: pin)
        return invite
    }
    static func request(_ bytes: Data, invitation: Data?, devicePin: Data, adminPin: Data, now: Int64?) throws -> AdmissionRequest {
        let request = try decode(bytes, as: AdmissionRequest.self)
        guard request.version == 1, request.requestId.count == 32, request.devicePublicKey == devicePin,
              devicePin != adminPin, !request.keyPackage.isEmpty, request.keyPackage.count <= 128 * 1024,
              !request.joinerIdentity.isEmpty, request.joinerIdentity.count <= 4096,
              invitation == nil || request.invitation == invitation else { throw ProofError.untrusted }
        try key(devicePin)
        let invite = try self.invitation(request.invitation, pin: adminPin, now: now)
        guard request.issuedAt >= invite.issuedAt, request.issuedAt < invite.expiresAt,
              request.expiresAt == invite.expiresAt else { throw ProofError.malformed }
        if let now { guard request.issuedAt <= now, now < request.expiresAt else { throw ProofError.expired } }
        try signature(request.signature, transcript: request.transcript(invite: invite), pin: devicePin)
        return request
    }
    static func welcome(_ bytes: Data, request: Data, adminPin: Data) throws -> AdmissionWelcome {
        let welcome = try decode(bytes, as: AdmissionWelcome.self)
        guard welcome.version == 1, welcome.request == request, !welcome.welcome.isEmpty,
              welcome.welcome.count <= 128 * 1024, !welcome.probe.isEmpty, welcome.probe.count <= 1024 * 1024 else { throw ProofError.untrusted }
        let parsed = try decode(request, as: AdmissionRequest.self)
        _ = try self.request(request, invitation: nil, devicePin: parsed.devicePublicKey, adminPin: adminPin, now: nil)
        let invite = try invitation(parsed.invitation, pin: adminPin, now: nil)
        try signature(welcome.approvalSignature, transcript: parsed.approval(invite: invite), pin: adminPin)
        return welcome
    }
    static func invitationDraft(_ transcript: Data, native: Data, now: Int64) throws {
        let fields = try components(transcript, count: 8)
        guard fields[0] == "squadtime-mls-invitation-v1", canonicalBase64(fields[1], length: 32),
              canonicalBase64(fields[2], length: nil), isDigest(fields[3]), fields[4] == native.base64EncodedString(),
              now <= 9_007_199_254_740_691, fields[5] == String(now), fields[6] == String(now + 300) else { throw EnrollmentError.contextMismatch }
    }
    static func requestDraft(_ transcript: Data, invite: AdmissionInvitation, invitation: Data, native: Data, now: Int64) throws {
        let fields = try components(transcript, count: 12)
        guard fields[0] == "squadtime-mls-admission-request-v1", canonicalBase64(fields[1], length: 32),
              fields[2] == digest(invitation), fields[3] == invite.groupId.base64EncodedString(),
              isDigest(fields[4]), isDigest(fields[5]), fields[6] == digest(invite.adminIdentity),
              fields[7] == native.base64EncodedString(), fields[8] == invite.adminPublicKey.base64EncodedString(),
              fields[9] == String(now), fields[10] == String(invite.expiresAt) else { throw EnrollmentError.contextMismatch }
    }
    private static func components(_ bytes: Data, count: Int) throws -> [String] {
        guard bytes.count <= 4096, let string = String(data: bytes, encoding: .utf8) else { throw ProofError.malformed }
        let fields = string.components(separatedBy: "\n")
        guard fields.count == count, fields.last?.isEmpty == true else { throw ProofError.malformed }
        return fields
    }
    private static func canonicalBase64(_ string: String, length: Int?) -> Bool {
        guard let data = Data(base64Encoded: string), data.base64EncodedString() == string else { return false }
        if let length { return data.count == length }
        return (1...256).contains(data.count)
    }
    private static func isDigest(_ string: String) -> Bool { string.count == 64 && (try? Data(strictHex: string).count) == 32 }
}
