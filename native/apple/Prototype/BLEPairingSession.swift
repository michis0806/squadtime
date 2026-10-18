import CryptoKit
import Foundation
import Security

enum BLEPairingRole: UInt8, Sendable { case owner = 0, joiner = 1 }
struct BLECeremonyUpdate: Sendable {
    var outbound: [Data] = []
    var code: String?
    var verified = false
    var pairCode: String?
}

/// Exact experimental v1 ceremony. Ephemeral material never enters persistence or native signing keys.
actor BLEPairingSession {
    private enum Phase { case fresh, ownerCommit, joinerCommit, ownerReveal, comparison, usable, failed }
    private let role: BLEPairingRole
    private let clock: @Sendable () -> ContinuousClock.Instant
    private var phase = Phase.fresh
    private var key: P256.KeyAgreement.PrivateKey?
    private var nonce = Data()
    private var sid = Data()
    private var ownCommit = Data()
    private var peerCommit = Data()
    private var peerPoint = Data()
    private var peerNonce = Data()
    private var transcriptHash = Data()
    private var keys: [SymmetricKey] = []
    private var sas: String?
    private var approved = false
    private var ownConfirmationSent = false
    private var peerConfirmed = false
    private var sealed: Data?
    private var sealedPlaintext: Data?
    private var receivedPayload = false
    private var overallDeadline: ContinuousClock.Instant?
    private var phaseDeadline: ContinuousClock.Instant?

    init(role: BLEPairingRole, clock: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) {
        self.role = role; self.clock = clock
    }
    func begin() throws -> BLECeremonyUpdate {
        do {
            guard phase == .fresh else { throw PrototypeFailure.invalid }
            key = P256.KeyAgreement.PrivateKey(); nonce = try random(32)
            overallDeadline = clock().advanced(by: .seconds(180)); phaseDeadline = clock().advanced(by: .seconds(15))
            if role == .owner {
                sid = try random(16); ownCommit = commitment(role: role, point: key!.publicKey.x963Representation, nonce: nonce)
                phase = .ownerCommit
                return BLECeremonyUpdate(outbound: [message(1, ownCommit)])
            }
            phase = .joinerCommit
            return BLECeremonyUpdate()
        } catch { destroy(); throw error }
    }
    func receive(_ packet: Data) throws -> BLECeremonyUpdate {
        do { try checkTime(); return try process(packet) }
        catch { destroy(); throw error }
    }
    private func process(_ packet: Data) throws -> BLECeremonyUpdate {
        guard (17...2092).contains(packet.count), let type = packet.first else { throw PrototypeFailure.invalid }
        let incomingSID = Data(packet.dropFirst().prefix(16))
        if role == .joiner, phase == .joinerCommit, peerCommit.isEmpty {
            guard type == 1, packet.count == 49 else { throw PrototypeFailure.invalid }
            sid = incomingSID; peerCommit = Data(packet.dropFirst(17))
            ownCommit = commitment(role: role, point: key!.publicKey.x963Representation, nonce: nonce)
            guard ownCommit != peerCommit else { throw PrototypeFailure.invalid }
            phaseDeadline = clock().advanced(by: .seconds(15))
            return BLECeremonyUpdate(outbound: [message(2, ownCommit)])
        }
        guard incomingSID == sid else { throw PrototypeFailure.invalid }
        if role == .owner, phase == .ownerCommit {
            guard type == 2, packet.count == 49 else { throw PrototypeFailure.invalid }
            peerCommit = Data(packet.dropFirst(17))
            guard ownCommit != peerCommit else { throw PrototypeFailure.invalid }
            phase = .ownerReveal; phaseDeadline = clock().advanced(by: .seconds(15))
            return BLECeremonyUpdate(outbound: [message(3, key!.publicKey.x963Representation + nonce)])
        }
        if (role == .joiner && phase == .joinerCommit) || (role == .owner && phase == .ownerReveal) {
            guard !peerCommit.isEmpty, type == (role == .owner ? 4 : 3), packet.count == 114 else { throw PrototypeFailure.invalid }
            peerPoint = Data(packet.dropFirst(17).prefix(65)); peerNonce = Data(packet.suffix(32))
            guard peerPoint != key!.publicKey.x963Representation, peerNonce != nonce,
                  commitment(role: peerRole, point: peerPoint, nonce: peerNonce) == peerCommit else { throw PrototypeFailure.invalid }
            try derive()
            phase = .comparison; phaseDeadline = clock().advanced(by: .seconds(90))
            return BLECeremonyUpdate(outbound: role == .joiner ? [message(4, key!.publicKey.x963Representation + nonce)] : [], code: sas)
        }
        if type == (role == .owner ? 6 : 5) {
            guard phase == .comparison, packet.count == 49, !peerConfirmed, keys.count == 5 else { throw PrototypeFailure.invalid }
            let mac = Data(packet.dropFirst(17))
            guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: confirmationInput(peerRole), using: keys[peerRole == .owner ? 1 : 2]) else { throw PrototypeFailure.invalid }
            peerConfirmed = true; updateUsability()
            return update()
        }
        guard type == 0x10, phase == .usable, !receivedPayload, role == .joiner || sealed != nil, packet.count >= 45, packet[packet.startIndex + 17] == peerRole.rawValue else { throw PrototypeFailure.invalid }
        let plaintext = try BLEPairingCrypto.open(packet, sender: peerRole, sid: sid, hash: transcriptHash, key: keys[peerRole == .owner ? 3 : 4])
        guard (1...2048).contains(plaintext.count), let text = String(data: plaintext, encoding: .utf8) else { throw PrototypeFailure.invalid }
        let code = try PairCode.parse(text)
        guard code.type == (role == .owner ? "request" : "invite") else { throw PrototypeFailure.invalid }
        receivedPayload = true; phaseDeadline = clock().advanced(by: .seconds(60))
        return BLECeremonyUpdate(code: sas, verified: true, pairCode: text)
    }
    func approve() throws -> BLECeremonyUpdate {
        do {
            try checkTime()
            guard phase == .comparison, !approved, keys.count == 5 else { throw PrototypeFailure.invalid }
            approved = true
            let mac = Data(HMAC<SHA256>.authenticationCode(for: confirmationInput(role), using: keys[role == .owner ? 1 : 2]))
            return BLECeremonyUpdate(outbound: [message(role == .owner ? 5 : 6, mac)], code: sas)
        } catch { destroy(); throw error }
    }
    /// Called only after the exact confirmation has entered the serialized transport queue.
    func confirmationQueued() throws -> BLECeremonyUpdate {
        do {
            try checkTime(); guard approved, !ownConfirmationSent else { throw PrototypeFailure.invalid }
            ownConfirmationSent = true; updateUsability(); return update()
        } catch { destroy(); throw error }
    }
    func sealPairCode(_ text: String) throws -> Data {
        do {
            try checkTime(); guard phase == .usable, let plaintext = text.data(using: .utf8), (1...2048).contains(plaintext.count) else { throw PrototypeFailure.invalid }
            let parsed = try PairCode.parse(text)
            guard parsed.type == (role == .owner ? "invite" : "request"), role == .owner || receivedPayload else { throw PrototypeFailure.invalid }
            if let sealed { guard sealedPlaintext == plaintext else { throw PrototypeFailure.invalid }; return sealed }
            let frame = try BLEPairingCrypto.seal(plaintext, role: role, sid: sid, hash: transcriptHash, key: keys[role == .owner ? 3 : 4])
            sealedPlaintext = plaintext; sealed = frame
            phaseDeadline = clock().advanced(by: .seconds(60))
            return frame
        } catch { destroy(); throw error }
    }
    func tick() throws { do { try checkTime() } catch { destroy(); throw error } }
    func destroy() {
        phase = .failed; key = nil; keys.removeAll(); sas = nil
        nonce.resetBytes(in: 0..<nonce.count); nonce.removeAll(keepingCapacity: false)
        sid.removeAll(keepingCapacity: false); ownCommit.removeAll(keepingCapacity: false); peerCommit.removeAll(keepingCapacity: false)
        peerPoint.removeAll(keepingCapacity: false); peerNonce.removeAll(keepingCapacity: false); transcriptHash.removeAll(keepingCapacity: false)
        sealed = nil; sealedPlaintext = nil; approved = false; ownConfirmationSent = false; peerConfirmed = false
        overallDeadline = nil; phaseDeadline = nil
    }
    private var peerRole: BLEPairingRole { role == .owner ? .joiner : .owner }
    private func updateUsability() {
        if approved && ownConfirmationSent && peerConfirmed { phase = .usable; phaseDeadline = clock().advanced(by: .seconds(60)) }
    }
    private func update() -> BLECeremonyUpdate { BLECeremonyUpdate(code: sas, verified: phase == .usable) }
    private func checkTime() throws {
        guard phase != .fresh, phase != .failed, let overallDeadline, let phaseDeadline, clock() < overallDeadline, clock() < phaseDeadline else { throw PrototypeFailure.unavailable }
    }
    private func commitment(role: BLEPairingRole, point: Data, nonce: Data) -> Data {
        BLEPairingCrypto.commitment(sid: sid, role: role, point: point, nonce: nonce)
    }
    private func confirmationInput(_ role: BLEPairingRole) -> Data { Data("squadtime-ble-confirm-v1\n".utf8) + transcriptHash + Data([role.rawValue]) }
    private func message(_ type: UInt8, _ value: Data) -> Data { Data([type]) + sid + value }
    private func derive() throws {
        guard let key else { throw PrototypeFailure.invalid }
        let material = try BLEPairingCrypto.derive(role: role, key: key, nonce: nonce, peerPoint: peerPoint, peerNonce: peerNonce, sid: sid, ownCommit: ownCommit, peerCommit: peerCommit)
        transcriptHash = material.transcriptHash; keys = material.keys; sas = material.sas
    }
    private func random(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw PrototypeFailure.unavailable }
        return bytes
    }
}
