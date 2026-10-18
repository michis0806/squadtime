import Foundation
import Observation

/// Serializes protocol frames and explicit UI decisions. A generation invalidates all suspended work on cancellation.
@Observable @MainActor
final class BLEPairingCoordinator {
    let transport = BLEPrototypeTransport()
    weak var model: PrototypeModel?
    private(set) var generation = UUID()
    private(set) var code: String?
    private(set) var verified = false
    private(set) var approved = false
    private(set) var status = "Choose Advertise on one device and Find nearby on the other."
    private var session: BLEPairingSession?
    private var role: BLEPairingRole?
    private var ownerPayloadSent = false
    private var requestSent = false
    private var nativeDeadline: Int64?
    private var queue: [Operation] = []
    private var queuedBytes = 0
    private var pumping = false
    private var work: Task<Void, Never>?
    private var timer: Task<Void, Never>?
    private enum Operation { case begin, receive(Data), approve }

    init(model: PrototypeModel? = nil) {
        self.model = model
        transport.onReady = { [weak self] in self?.enqueue(.begin) }
        transport.onMessage = { [weak self] bytes in self?.enqueue(.receive(bytes)) }
        transport.onStop = { [weak self] in self?.cancel(stopTransport: false) }
    }
    func start(_ selectedRole: BLEPairingRole) {
        guard let model, model.profile?.bootstrap != nil else { status = "Approve the local test relay first."; return }
        if selectedRole == .owner { guard ["ready", "invitation"].contains(model.phase) else { status = "Use the existing QR fallback for this admission phase."; return } }
        else { guard ["ready", "request"].contains(model.phase) else { status = "Use the existing QR fallback for this admission phase."; return } }
        cancel()
        let id = generation
        role = selectedRole; session = BLEPairingSession(role: selectedRole)
        status = "Preparing Bluetooth pairing…"
        work = Task { [weak self] in
            guard let self else { return }
            if selectedRole == .owner && model.phase == "ready" { await model.start() }
            guard self.generation == id, !Task.isCancelled else { return }
            guard selectedRole != .owner || (model.phase == "invitation" && !model.code.isEmpty) else { self.cancel(); return }
            if selectedRole == .owner {
                guard let parsed = try? PairCode.parse(model.code) else { self.cancel(); self.status = "The existing invitation expired. Use the retained QR fallback or explicitly reset this test profile."; return }
                self.nativeDeadline = parsed.expiresAt
            } else { self.nativeDeadline = model.profile?.expiresAt }
            await model.beginBluetooth(id)
            guard self.generation == id, !Task.isCancelled else { return }
            if selectedRole == .owner { self.transport.advertise() } else { self.transport.findNearby() }
        }
    }
    func codesMatch() { guard code != nil, !approved, transport.ready else { return }; enqueue(.approve) }
    func cancel(stopTransport: Bool = true) {
        let previous = generation; generation = UUID()
        let previousSession = session; session = nil
        work?.cancel(); timer?.cancel(); work = nil; timer = nil
        queue.removeAll(); queuedBytes = 0; pumping = false
        code = nil; verified = false; approved = false; role = nil; ownerPayloadSent = false; requestSent = false; nativeDeadline = nil
        if stopTransport { transport.stop() }
        status = "Pairing ended. Choose a role for a fresh attempt, or use QR."
        Task { [weak self] in await previousSession?.destroy(); await self?.model?.clearBluetooth(previous) }
    }
    private func enqueue(_ operation: Operation) {
        guard session != nil, transport.ready else { return }
        if case .receive(let data) = operation {
            guard queuedBytes + data.count <= 65536, queue.count < 128 else { cancel(); return }
            queuedBytes += data.count
        }
        queue.append(operation)
        guard !pumping else { return }
        pumping = true
        let id = generation
        work = Task { [weak self] in
            guard let self else { return }
            do {
                while self.generation == id, !self.queue.isEmpty, let session = self.session {
                    let next = self.queue.removeFirst()
                    let update: BLECeremonyUpdate
                    switch next {
                    case .begin:
                        update = try await session.begin(); self.startTimer(id)
                    case .receive(let bytes):
                        self.queuedBytes -= bytes.count; update = try await session.receive(bytes)
                    case .approve:
                        update = try await session.approve(); self.approved = true
                    }
                    guard self.generation == id, !Task.isCancelled else { return }
                    try await self.apply(update, id: id)
                    if case .approve = next {
                        let confirmed = try await session.confirmationQueued()
                        guard self.generation == id else { return }
                        try await self.apply(confirmed, id: id)
                    }
                }
                if self.generation == id { self.pumping = false }
            } catch { if self.generation == id { self.cancel(); self.status = "Bluetooth verification failed or timed out. Start a fresh attempt or use QR." } }
        }
    }
    private func startTimer(_ id: UUID) {
        timer?.cancel()
        timer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, let self, self.generation == id, let session = self.session else { return }
                if let expiry = self.nativeDeadline, Int64(Date().timeIntervalSince1970) >= expiry {
                    self.cancel(); self.status = "The native invitation expired. Committed state and QR fallback are retained."; return
                }
                do { try await session.tick() }
                catch { guard self.generation == id else { return }; self.cancel(); self.status = "Bluetooth pairing timed out. Start a fresh attempt or use QR."; return }
            }
        }
    }
    private func apply(_ update: BLECeremonyUpdate, id: UUID) async throws {
        guard generation == id, let session else { throw PrototypeFailure.unavailable }
        for bytes in update.outbound { try transport.send(bytes) }
        if let code = update.code { self.code = code; status = approved ? "Waiting for the other device to confirm the complete code." : "Compare all six digits on the intended devices, then select Codes match on both." }
        if update.verified {
            verified = true; status = "Bluetooth code verified on both devices. Review the intended contact before native admission."
            if role == .owner, !ownerPayloadSent, let text = model?.code, !text.isEmpty {
                let packet = try await session.sealPairCode(text)
                guard generation == id, transport.ready else { throw PrototypeFailure.unavailable }
                try transport.send(packet); ownerPayloadSent = true
            }
        }
        if let pairCode = update.pairCode {
            guard generation == id, verified, let model else { throw PrototypeFailure.invalid }
            let parsed = try PairCode.parse(pairCode)
            nativeDeadline = min(nativeDeadline ?? parsed.expiresAt, parsed.expiresAt)
            try await model.receiveBluetooth(pairCode, generation: id)
            guard generation == id, verified else { throw PrototypeFailure.unavailable }
            if role == .joiner, model.phase == "request", !model.bluetoothReview { try await sendRequest(id: id) }
        }
    }
    func nativeConfirmationCompleted() async {
        let id = generation
        guard verified else { return }
        do {
            if role == .joiner, model?.phase == "request" { try await sendRequest(id: id) }
            else if role == .owner, ["welcome", "done"].contains(model?.phase ?? "") { cancel() }
        } catch { if generation == id { cancel(); status = "The committed request is retained. Retry with a fresh Bluetooth attempt or use QR." } }
    }
    private func sendRequest(id: UUID) async throws {
        guard generation == id, !requestSent, let session, let text = model?.code, !text.isEmpty else { throw PrototypeFailure.invalid }
        let packet = try await session.sealPairCode(text)
        guard generation == id, transport.ready else { throw PrototypeFailure.unavailable }
        try transport.send(packet); requestSent = true
        status = "Committed request sent. Confirm it on the first device; relay delivery continues independently."
    }
}
