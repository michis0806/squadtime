import CoreImage.CIFilterBuiltins
import Observation
import SwiftUI

@main
struct SquadtimePrototypeApp: App {
    var body: some Scene { WindowGroup { PrototypeView() } }
}

struct PrototypeView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var model = PrototypeModel()
    @State private var nickname = ""
    @State private var avatar = "fox"
    @State private var input = ""
    @State private var relayOrigin = Self.defaultRelayOrigin
    @State private var scanner = false
    @State private var resetting = false
    @State private var confirmed = false
    private let avatars = ["fox", "cat", "dog", "panda"]
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label("Synthetic test data only", systemImage: "flask")
                    Text("Development prototype. Do not enter real child data. Pairing does not prove physical presence, age, identity or parental approval.").font(.footnote).foregroundStyle(.secondary)
                }
                if let profile = model.profile {
                    Section("Local profile") { Label(profile.nickname, systemImage: "person.crop.circle.fill"); Text("Avatar: \(profile.avatar)") }
                    if model.phase.isEmpty {
                        Section("Test relay configuration") {
                            Text("Paste the local test relay HTTP origin supplied for this device. It stays encrypted on this device. Approving permits network access to this local test server.").font(.footnote)
                            TextField("http://192.168.1.2:8789", text: $relayOrigin).textInputAutocapitalization(.never).autocorrectionDisabled()
                            Button("Approve test relay origin") { act { await model.configure(relayOrigin) } }.disabled(relayOrigin.isEmpty)
                        }
                    }
                    Section("One direct test contact") {
                        Text(model.status)
                        if model.phase == "joined" { Button("Acknowledge encrypted test") { act { await model.acknowledge() } } }
                        if profile.manual { Text("Manual transfer · no proximity verification").font(.footnote).foregroundStyle(.orange) }
                        if model.phase == "ready" {
                            Button("Create pairing code") { act { await model.start() } }
                            Button("Scan pairing code") { model.bluetooth.cancel(); scanner = true }
                        } else if !model.phase.isEmpty {
                            if !model.code.isEmpty { QRCodeView(code: model.code); ShareLink("Share public pairing code", item: model.code) }
                            Button("Scan other device code") { model.bluetooth.cancel(); scanner = true }
                            Button("Check relay / retry stored outbox") { act { await model.refresh() } }
                        }
                        if !model.peerFingerprint.isEmpty {
                            Text("Other device fingerprint").font(.caption)
                            Text(model.peerFingerprint).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                            Text(model.bluetoothReview ? "The complete Bluetooth code was confirmed on both devices. Review this intended contact and relay. The full native fingerprint remains available." : "Compare this fingerprint with the intended other device using a separate trusted channel. The code itself is not proof of identity.").font(.footnote)
                            Toggle(model.bluetoothReview ? "I approve this Bluetooth-verified test contact" : "I compared the intended device key", isOn: $confirmed)
                            Button("Confirm this direct test contact") { act { await model.confirm(); confirmed = false } }.disabled(!confirmed)
                        }
                    }
                    BLEPairingSection(coordinator: model.bluetooth)
                    Section("Manual fallback") {
                        Text("Pasted or forwarded codes are manual transfer, not proximity verification.").font(.footnote)
                        TextField("Public pairing code", text: $input, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("Use pasted public code") { act { confirmed = false; await model.receive(input, manual: true); input = "" } }.disabled(input.isEmpty)
                    }
                    Section { Button("Reset this prototype", role: .destructive) { resetting = true } }
                } else if !model.blocked {
                    Section("Create a local test profile") {
                        TextField("Synthetic nickname", text: $nickname).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Picker("Built-in avatar", selection: $avatar) { ForEach(avatars, id: \.self) { Text($0.capitalized).tag($0) } }
                        Button("Create local profile") { act { await model.create(nickname: nickname, avatar: avatar) } }.disabled(nickname.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                if model.blocked { Section { Text("Stored data could not be opened. No keys or state were replaced. Reopen the app to retry, or explicitly reset this prototype."); Button("Reset this prototype", role: .destructive) { resetting = true } } }
                if model.busy { Section { ProgressView("Working…") } }
                if let error = model.error { Section { Text(error).foregroundStyle(.red) } }
            }
            .navigationTitle("Squadtime DEV")
            .disabled(model.busy)
            .task { await model.load() }
            .onChange(of: model.bluetoothReview) { _, _ in confirmed = false }
            .onChange(of: model.peerFingerprint) { _, _ in confirmed = false }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { model.bluetooth.cancel() }
            }
            .task(id: scenePhase) {
                guard scenePhase == .active else { return }
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(2))
                    guard !Task.isCancelled else { break }
                    if ["request", "welcome"].contains(model.phase), !model.busy { await model.refresh() }
                }
            }
            .sheet(isPresented: $scanner) {
                NavigationStack { QRScanner { code in scanner = false; act { confirmed = false; await model.receive(code, manual: false) } }.navigationTitle("Scan public pairing code").toolbar { Button("Cancel") { scanner = false } } }
            }
            .confirmationDialog("Delete only this prototype's local profile, keys and contact state? This cannot be recovered.", isPresented: $resetting, titleVisibility: .visible) {
                Button("Delete prototype data", role: .destructive) { act { await model.reset(); if model.profile == nil { relayOrigin = Self.defaultRelayOrigin } } }
            }
        }
    }
    private static var defaultRelayOrigin: String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "SquadtimePrototypeRelayOrigin") as? String else { return "" }
        return (try? origin(value)) ?? ""
    }
    private func act(_ action: @escaping @MainActor () async -> Void) { Task { await action() } }
}

private struct QRCodeView: View {
    let code: String
    var body: some View {
        if let image = makeImage() { Image(uiImage: image).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 280).padding(12).background(.white).accessibilityLabel("Public pairing QR code") }
    }
    private func makeImage() -> UIImage? {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(code.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage, let cg = CIContext().createCGImage(output.transformed(by: CGAffineTransform(scaleX: 8, y: 8)), from: output.extent.applying(CGAffineTransform(scaleX: 8, y: 8))) else { return nil }
        return UIImage(cgImage: cg)
    }
}
