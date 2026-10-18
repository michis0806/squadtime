import CryptoKit
import Foundation
import Observation
import PairingProof

struct PrototypeSnapshot: Sendable {
    let profile: PrototypeProfile?
    var phase = ""
    var code = ""
    var fingerprint = ""
    var status = "Choose a local test relay, then show or scan a code."
}

/// Serial owner of encrypted UI metadata and the real durable MLS admission actor.
actor PrototypeEngine {
    let storage = PrototypeStorage()
    let relay = PrototypeRelay()
    var profile: PrototypeProfile?
    var admission: DurableAdmission?
    let signing = try! DeviceKeyStore(alias: PrototypeStorage.keyAlias)
    func load() async throws -> PrototypeSnapshot {
        if let admission { await admission.close(); self.admission = nil }
        profile = try await storage.load()
        if profile != nil { _ = try signing.publicKeyHex() }
        if let id = profile?.admissionID {
            admission = try DurableAdmission.open(directory: await storage.admissionDirectory(), id: id)
            let out = try await admission!.outbox()
            if out.kind == "invitation" {
                let object = try JSONSerialization.jsonObject(with: out.outbox) as? [String: Any]
                profile?.invitationHash = digest(out.outbox)
                profile?.expiresAt = (object?["expiresAt"] as? NSNumber)?.int64Value
            }
            if out.kind == "request" { profile?.requestHash = digest(out.outbox) }
            if out.kind == "welcome" { profile?.welcomeHash = digest(out.outbox) }
            if ["request", "welcome", "joined"].contains(out.kind) { profile?.pendingCode = nil }
            try await persist()
        }
        return try await snapshot()
    }
    func create(nickname: String, avatar: String) async throws -> PrototypeSnapshot {
        guard profile == nil, nickname.unicodeScalars.count <= 32, !nickname.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !nickname.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }), ["fox","cat","dog","panda"].contains(avatar) else { throw PrototypeFailure.invalid }
        _ = try signing.createIfMissing()
        profile = PrototypeProfile(nickname: nickname, avatar: avatar)
        try await persist(); return try await snapshot()
    }
    func configure(_ text: String) async throws -> PrototypeSnapshot {
        guard profile?.admissionID == nil else { throw PrototypeFailure.invalid }
        profile?.bootstrap = try origin(text); try await persist(); return try await snapshot()
    }
    func start() async throws -> PrototypeSnapshot {
        guard var p = profile, p.admissionID == nil, p.bootstrap != nil else { throw PrototypeFailure.invalid }
        var random = Data(count: 32)
        guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw PrototypeFailure.unavailable }
        p.session = random.map { String(format: "%02x", $0) }.joined(); p.admissionID = UUID(); p.role = "owner"
        profile = p; try await persist()
        admission = try DurableAdmission.create(directory: await storage.admissionDirectory(), id: p.admissionID!, role: .owner, nativeKey: signing)
        _ = try await admission!.ownerStart(nativeKey: signing, now: now())
        return try await refresh()
    }
    func receive(_ text: String, manual: Bool) async throws -> PrototypeSnapshot {
        let code = try PairCode.parse(text)
        guard var p = profile, let configured = p.bootstrap, code.relay == configured else { throw PrototypeFailure.invalid }
        if code.type == "invite" { guard p.admissionID == nil else { throw PrototypeFailure.invalid } }
        else { guard p.role == "owner", p.session == code.session, try await admission?.outbox().kind == "invitation" else { throw PrototypeFailure.invalid } }
        p.pendingCode = text; p.manual = manual; profile = p; try await persist(); return try await snapshot()
    }
    func confirm() async throws -> PrototypeSnapshot {
        guard var p = profile, let text = p.pendingCode else { throw PrototypeFailure.invalid }
        let code = try PairCode.parse(text)
        guard code.relay == p.bootstrap, let bytes = try await relay.exchange(relay: code.relay, id: code.session, kind: code.type == "invite" ? "invitation" : "request"), digest(bytes) == code.hash else { throw PrototypeFailure.invalid }
        let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        guard let key = object?[code.type == "invite" ? "adminPublicKey" : "devicePublicKey"] as? String,
              key == code.key.base64EncodedString(), (object?["expiresAt"] as? NSNumber)?.int64Value == code.expiresAt else { throw PrototypeFailure.invalid }
        p.peerKey = code.key; p.expiresAt = code.expiresAt
        if code.type == "invite" {
            p.admissionID = UUID(); p.role = "joiner"; p.session = code.session; p.invitationHash = code.hash
            profile = p; try await persist()
            admission = try DurableAdmission.create(directory: await storage.admissionDirectory(), id: p.admissionID!, role: .joiner, nativeKey: signing, trustedAdminPublicKey: code.key)
            _ = try await admission!.joinerStart(invitation: bytes, nativeKey: signing, now: now())
        } else {
            p.requestHash = code.hash; profile = p; try await persist()
            guard let admission else { throw PrototypeFailure.unavailable }
            _ = try await admission.ownerAdmit(request: bytes, trustedDevicePublicKey: code.key, nativeKey: signing, now: now(), userConfirmed: true)
        }
        profile?.pendingCode = nil; try await persist(); return try await refresh()
    }
    func refresh() async throws -> PrototypeSnapshot {
        guard var p = profile, let admission, let server = p.bootstrap, let id = p.session else { return try await snapshot() }
        let out = try await admission.outbox()
        if !out.outbox.isEmpty {
            let object = try JSONSerialization.jsonObject(with: out.outbox) as? [String: Any]
            if out.kind == "invitation" { p.invitationHash = digest(out.outbox); p.expiresAt = (object?["expiresAt"] as? NSNumber)?.int64Value }
            if out.kind == "request" { p.requestHash = digest(out.outbox) }
            if out.kind == "welcome" { p.welcomeHash = digest(out.outbox) }
            if ["request", "welcome"].contains(out.kind) { p.pendingCode = nil }; profile = p; try await persist()
            _ = try await relay.exchange(relay: server, id: id, kind: out.kind, put: out.outbox)
        }
        if out.kind == "request", let welcome = try await relay.exchange(relay: server, id: id, kind: "welcome") {
            profile?.welcomeHash = digest(welcome); try await persist()
            _ = try await admission.join(welcome: welcome, now: now())
        }
        if try await admission.outbox().kind == "joined" {
            if profile?.welcomeHash == nil, let welcome = try await relay.exchange(relay: server, id: id, kind: "welcome") {
                // A recovered receipt must bind the same exact request and authenticated probe.
                let object = try JSONSerialization.jsonObject(with: welcome) as? [String: Any]
                guard let request64 = object?["request"] as? String, let request = Data(base64Encoded: request64), digest(request) == profile?.requestHash,
                      let probe64 = object?["probe"] as? String, let probe = Data(base64Encoded: probe64), probe == (try await admission.proofProbePacket()) else { throw PrototypeFailure.invalid }
                profile?.welcomeHash = digest(welcome)
            }
            if profile?.receipt == nil {
                guard let p = profile, let a = p.invitationHash, let r = p.requestHash, let w = p.welcomeHash else { throw PrototypeFailure.unavailable }
                let unsigned = Receipt(v: 1, session: id, invitationHash: a, requestHash: r, welcomeHash: w, signature: Data())
                let hex = try signing.sign(unsigned.transcript)
                let signature = Data(stride(from: 0, to: hex.count, by: 2).compactMap { i in UInt8(hex[hex.index(hex.startIndex, offsetBy: i)..<hex.index(hex.startIndex, offsetBy: i+2)], radix: 16) })
                profile?.receipt = try JSONEncoder().encode(Receipt(v: 1, session: id, invitationHash: a, requestHash: r, welcomeHash: w, signature: signature)); try await persist()
            }
            _ = try await relay.exchange(relay: server, id: id, kind: "receipt", put: profile!.receipt!)
        }
        if out.kind == "welcome", let bytes = try await relay.exchange(relay: server, id: id, kind: "receipt") {
            guard let p = profile, let peer = p.peerKey,
                  let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], Set(object.keys) == Set(["v","session","invitationHash","requestHash","welcomeHash","signature"]) else { throw PrototypeFailure.invalid }
            let receipt = try JSONDecoder().decode(Receipt.self, from: bytes)
            guard receipt.v == 1, receipt.session == id, receipt.invitationHash == p.invitationHash, receipt.requestHash == p.requestHash, receipt.welcomeHash == p.welcomeHash,
                  (object["signature"] as? String) == receipt.signature.base64EncodedString(),
                  try P256.Signing.PublicKey(x963Representation: peer).isValidSignature(P256.Signing.ECDSASignature(derRepresentation: receipt.signature), for: receipt.transcript) else { throw PrototypeFailure.invalid }
            profile?.contactConfirmed = true; try await persist()
        }
        return try await snapshot()
    }
    func snapshot() async throws -> PrototypeSnapshot {
        guard let p = profile else { return PrototypeSnapshot(profile: nil) }
        var result = PrototypeSnapshot(profile: p); result.phase = p.bootstrap == nil ? "" : "ready"
        if let text = p.pendingCode {
            let code = try PairCode.parse(text); result.fingerprint = digest(code.key)
            result.status = "Confirm \(code.label)'s test key and selected relay: \(code.relay)"
        }
        if let admission, let server = p.bootstrap, let session = p.session {
            let out = try await admission.outbox(); result.phase = out.kind
            if ["invitation","request"].contains(out.kind), let expiry = p.expiresAt {
                result.code = try PairCode(v: 1, type: out.kind == "invitation" ? "invite" : "request", relay: server, session: session, key: out.nativePublicKey, hash: digest(out.outbox), expiresAt: expiry, label: p.nickname).text()
            }
            if p.pendingCode == nil {
                switch out.kind {
                case "invitation": result.status = "Show your code. Then scan the other device's request."
                case "request": result.status = "Show your request code to the first device, then check the relay."
                case "welcome": result.status = p.contactConfirmed ? "Both test devices confirmed." : "Encrypted test sent. Awaiting signed receipt."
                case "joined": result.status = (try await admission.pendingMessages()).isEmpty ? "Test contact connected." : "Encrypted test received. Stored securely on this device."
                default: result.status = "Local setup interrupted. Reopen to retry; explicit reset may be required."
                }
            }
            if out.kind == "welcome", p.contactConfirmed { result.phase = "done" }
            result.status += "\nYour key: \(digest(out.nativePublicKey))"
        }
        return result
    }
    func acknowledge() async throws -> PrototypeSnapshot {
        guard let admission else { throw PrototypeFailure.unavailable }
        for item in try await admission.pendingMessages() { try await admission.acknowledge(messageID: item.id) }
        return try await snapshot()
    }
    func reset() async throws -> PrototypeSnapshot {
        if let admission { await admission.close() }; admission = nil
        try await storage.reset(); profile = nil; return PrototypeSnapshot(profile: nil)
    }
    private func persist() async throws { guard let profile else { throw PrototypeFailure.invalid }; try await storage.save(profile) }
    private func now() -> Int64 { Int64(Date().timeIntervalSince1970) }
}

@Observable @MainActor
final class PrototypeModel {
    var profile: PrototypeProfile?
    var phase = ""
    var code = ""
    var peerFingerprint = ""
    var status = ""
    var busy = false
    var blocked = false
    var error: String?
    private let engine = PrototypeEngine()
    private func run(_ operation: () async throws -> PrototypeSnapshot, opening: Bool = false) async {
        guard !busy else { return }; busy = true; error = nil; defer { busy = false }
        do { apply(try await operation()); blocked = false }
        catch {
            self.error = "The operation could not complete. Check the test relay and retry. Close and reopen the app after a storage failure. No local keys were replaced."
            if opening { blocked = true }
            if !opening, let result = try? await engine.load() { apply(result) }
        }
    }
    private func apply(_ s: PrototypeSnapshot) { profile = s.profile; phase = s.phase; code = s.code; peerFingerprint = s.fingerprint; status = s.status }
    func load() async { await run({ try await engine.load() }, opening: true) }
    func create(nickname: String, avatar: String) async { await run { try await engine.create(nickname: nickname, avatar: avatar) } }
    func configure(_ input: String) async { await run { try await engine.configure(input) } }
    func start() async { await run { try await engine.start() } }
    func receive(_ text: String, manual: Bool) async { await run { try await engine.receive(text, manual: manual) } }
    func confirm() async { await run { try await engine.confirm() } }
    func refresh() async { await run { try await engine.refresh() } }
    func acknowledge() async { await run { try await engine.acknowledge() } }
    func reset() async { await run { try await engine.reset() } }
}
