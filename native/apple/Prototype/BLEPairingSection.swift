import SwiftUI

struct BLEPairingSection: View {
    let coordinator: BLEPairingCoordinator
    var body: some View {
        Section("Bluetooth pairing") {
            Text("Keep both test apps open. Bluetooth discovery does not prove physical presence or identity.").font(.footnote)
            Text(coordinator.status)
            if coordinator.transport.active {
                Text(coordinator.transport.status).font(.footnote)
                ForEach(coordinator.transport.devices) { device in Button(device.label) { coordinator.transport.connect(device.id) } }
                if let code = coordinator.code, !coordinator.verified {
                    Text(code).font(.system(.largeTitle, design: .monospaced)).accessibilityLabel("Comparison code \(code)")
                    Button("Codes match") { coordinator.codesMatch() }.disabled(coordinator.approved)
                    Button("Codes do not match", role: .destructive) { coordinator.cancel() }
                }
                Button("Cancel Bluetooth pairing", role: .cancel) { coordinator.cancel() }
            } else {
                Button("Advertise on this device") { coordinator.start(.owner) }
                Button("Find nearby test device") { coordinator.start(.joiner) }
            }
        }
    }
}
