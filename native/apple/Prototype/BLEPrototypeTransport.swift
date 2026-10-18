import CoreBluetooth
import Foundation
import Observation

struct NearbyPrototypeDevice: Identifiable, Equatable {
    let id: UUID
    let label: String
}

/// Foreground transport only. Incoming bytes are never device trust until the separate ceremony succeeds.
@Observable @MainActor
final class BLEPrototypeTransport: NSObject {
    private(set) var status = "Bluetooth is off until you choose a pairing role."
    private(set) var devices: [NearbyPrototypeDevice] = []
    private(set) var active = false
    private(set) var ready = false
    var onMessage: ((Data) -> Void)?
    var onReady: (() -> Void)?
    var onStop: (() -> Void)?
    private static let serviceID = CBUUID(string: "9B0A1000-6E7D-4C56-9E2A-4D6E53515431")
    private static let rxID = CBUUID(string: "9B0A1001-6E7D-4C56-9E2A-4D6E53515431")
    private static let txID = CBUUID(string: "9B0A1002-6E7D-4C56-9E2A-4D6E53515431")
    private var central: CBCentralManager?
    private var peripheralManager: CBPeripheralManager?
    private var discovered: [UUID: CBPeripheral] = [:]
    private var peerPeripheral: CBPeripheral?
    private var peerCentral: CBCentral?
    private var rx: CBCharacteristic?
    private var tx: CBCharacteristic?
    private var peripheralTX: CBMutableCharacteristic?
    private var decoder = BLEFrameDecoder()
    private var outgoing = BLEFrameQueue()
    private var inFlight = 0
    private var earlyTX: [Data] = []
    private var earlyTXBytes = 0
    private var partialTimer: Task<Void, Never>?
    private var fragmentCount = 0
    private var scanTimer: Task<Void, Never>?
    private var sessionTimer: Task<Void, Never>?

    func advertise() {
        begin()
        status = "Starting Bluetooth advertising…"
        peripheralManager = CBPeripheralManager(delegate: self, queue: .main)
    }
    func findNearby() {
        begin()
        status = "Starting Bluetooth scan…"
        central = CBCentralManager(delegate: self, queue: .main)
    }
    private func begin() {
        stop(message: "")
        active = true
        sessionTimer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(180))
            guard !Task.isCancelled else { return }
            self?.stop(message: "Bluetooth pairing timed out. Choose a role to retry.")
        }
    }
    func connect(_ id: UUID) {
        guard active, peerPeripheral == nil, let device = discovered[id], let central else { return }
        central.stopScan(); scanTimer?.cancel(); scanTimer = nil
        peerPeripheral = device; device.delegate = self
        status = "Connecting to selected test device…"
        central.connect(device, options: nil)
        discovered.removeAll(); devices.removeAll()
    }
    func send(_ message: Data) throws {
        guard active, ready, message.count <= 2092 else { throw PrototypeFailure.unavailable }
        try outgoing.append(message)
        pump()
    }
    private func pump() {
        guard active, ready, !outgoing.buffered.isEmpty else { return }
        if let peerPeripheral, let rx {
            guard inFlight == 0 else { return }
            let chunk = outgoing.nextChunk
            inFlight = chunk.count
            peerPeripheral.writeValue(chunk, for: rx, type: .withResponse)
        } else if let peripheralManager, let peerCentral, let peripheralTX {
            while !outgoing.buffered.isEmpty {
                let chunk = outgoing.nextChunk
                guard peripheralManager.updateValue(chunk, for: peripheralTX, onSubscribedCentrals: [peerCentral]) else { return }
                outgoing.acknowledge(chunk.count)
            }
        }
    }
    private func receive(_ bytes: Data) throws {
        fragmentCount += 1
        guard fragmentCount <= 2096 else { throw PrototypeFailure.invalid }
        if decoder.buffered.isEmpty {
            partialTimer?.cancel()
            partialTimer = Task { [weak self] in
                try? await Task.sleep(for: .seconds(10))
                guard !Task.isCancelled, let self, !self.decoder.buffered.isEmpty else { return }
                self.stop(message: "Incomplete Bluetooth message timed out.")
            }
        }
        let messages = try decoder.consume(bytes)
        for message in messages { onMessage?(message) }
        if !messages.isEmpty { fragmentCount = decoder.buffered.isEmpty ? 0 : 1 }
        if decoder.buffered.isEmpty { partialTimer?.cancel(); partialTimer = nil }
    }
    func stop(message: String = "Bluetooth pairing cancelled.") {
        let wasActive = active
        active = false; ready = false
        scanTimer?.cancel(); sessionTimer?.cancel(); partialTimer?.cancel(); scanTimer = nil; sessionTimer = nil; partialTimer = nil
        central?.stopScan()
        if let peerPeripheral { central?.cancelPeripheralConnection(peerPeripheral); peerPeripheral.delegate = nil }
        peripheralManager?.stopAdvertising(); peripheralManager?.removeAllServices()
        central?.delegate = nil; peripheralManager?.delegate = nil
        central = nil; peripheralManager = nil; peerPeripheral = nil; peerCentral = nil
        rx = nil; tx = nil; peripheralTX = nil; discovered.removeAll(); devices.removeAll()
        decoder.clear(); outgoing.clear(); inFlight = 0; fragmentCount = 0
        earlyTX.removeAll(); earlyTXBytes = 0
        status = message
        if wasActive { onStop?() }
    }
    private func becameReady() {
        guard active, !ready else { return }
        ready = true; status = "Bluetooth connected."
        onReady?()
    }
    private func unavailable(_ state: CBManagerState) {
        switch state {
        case .unknown: return
        case .resetting: stop(message: "Bluetooth reset. Choose a role for a fresh attempt.")
        case .poweredOn: return
        case .unauthorized: stop(message: "Bluetooth access is unavailable. Allow Bluetooth in Settings, then choose a role again.")
        case .poweredOff: stop(message: "Turn on Bluetooth, then choose a pairing role again.")
        default: stop(message: "Bluetooth is unavailable on this device. Use the QR fallback.")
        }
    }
}

extension BLEPrototypeTransport: @preconcurrency CBCentralManagerDelegate, @preconcurrency CBPeripheralDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard self.central === central, active else { return }
        guard central.state == .poweredOn else { unavailable(central.state); return }
        central.scanForPeripherals(withServices: [Self.serviceID], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        status = "Finding nearby test devices…"
        scanTimer?.cancel()
        scanTimer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(60))
            guard !Task.isCancelled, let self, self.active else { return }
            self.central?.stopScan(); self.status = "Scan ended. Choose a listed device, or cancel and retry."
        }
    }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard self.central === central, active, peerPeripheral == nil, discovered[peripheral.identifier] == nil, devices.count < 8 else { return }
        discovered[peripheral.identifier] = peripheral
        devices.append(NearbyPrototypeDevice(id: peripheral.identifier, label: "Nearby test device \(devices.count + 1)"))
    }
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard self.central === central, active, peerPeripheral === peripheral else { return }
        peripheral.discoverServices([Self.serviceID])
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
        guard peerPeripheral === peripheral else { return }; stop(message: "Connection failed. Choose a pairing role to retry.")
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: (any Error)?) {
        guard peerPeripheral === peripheral else { return }; stop(message: "Bluetooth disconnected. Choose a pairing role to retry.")
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard active, peerPeripheral === peripheral else { return }
        guard error == nil, let services = peripheral.services, services.count == 1, services[0].uuid == Self.serviceID else { stop(message: "Test-device service unavailable."); return }
        peripheral.discoverCharacteristics([Self.rxID, Self.txID], for: services[0])
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        guard active, peerPeripheral === peripheral else { return }
        guard error == nil, service.uuid == Self.serviceID, let characteristics = service.characteristics,
              let incoming = characteristics.first(where: { $0.uuid == Self.txID && $0.properties.contains(.notify) }),
              let outgoing = characteristics.first(where: { $0.uuid == Self.rxID && $0.properties.contains(.write) }) else { stop(message: "Test-device characteristics unavailable."); return }
        tx = incoming; rx = outgoing; peripheral.setNotifyValue(true, for: incoming)
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard active, peerPeripheral === peripheral, characteristic === tx else { return }
        guard error == nil, characteristic.isNotifying else { stop(message: "Bluetooth notifications unavailable."); return }
        becameReady()
        let pending = earlyTX; earlyTX.removeAll(); earlyTXBytes = 0
        do { for bytes in pending { try receive(bytes) } }
        catch { stop(message: "Invalid early Bluetooth message. Pairing stopped.") }
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard active, peerPeripheral === peripheral, characteristic === tx else { return }
        guard error == nil, let bytes = characteristic.value, !bytes.isEmpty, bytes.count <= 20 else { stop(message: "Bluetooth message unavailable."); return }
        if !ready {
            guard earlyTXBytes + bytes.count <= 2096, earlyTX.count < 2096 else { stop(message: "Early Bluetooth data exceeded its bound."); return }
            earlyTX.append(bytes); earlyTXBytes += bytes.count; return
        }
        do { try receive(bytes) } catch { stop(message: "Invalid Bluetooth message. Pairing stopped.") }
    }
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard active, ready, peerPeripheral === peripheral, characteristic === rx, inFlight > 0 else { return }
        guard error == nil else { stop(message: "Bluetooth write failed. Pairing stopped."); return }
        outgoing.acknowledge(inFlight); inFlight = 0; pump()
    }
}

extension BLEPrototypeTransport: @preconcurrency CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheralManager === peripheral, active else { return }
        guard peripheral.state == .poweredOn else { unavailable(peripheral.state); return }
        let service = CBMutableService(type: Self.serviceID, primary: true)
        let incoming = CBMutableCharacteristic(type: Self.rxID, properties: [.write], value: nil, permissions: [.writeable])
        let outgoing = CBMutableCharacteristic(type: Self.txID, properties: [.notify], value: nil, permissions: [])
        peripheralTX = outgoing; service.characteristics = [incoming, outgoing]; peripheral.add(service)
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: (any Error)?) {
        guard peripheralManager === peripheral, active else { return }
        guard error == nil else { stop(message: "Bluetooth advertising unavailable."); return }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceID]])
    }
    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: (any Error)?) {
        guard peripheralManager === peripheral, active else { return }
        guard error == nil else { stop(message: "Bluetooth advertising failed."); return }
        status = "Advertising a test pairing service. Find it on the other device."
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard peripheralManager === peripheral, active, characteristic.uuid == Self.txID else { return }
        guard peerCentral == nil || peerCentral?.identifier == central.identifier else { stop(message: "More than one peer attempted pairing. Choose a role to retry."); return }
        peerCentral = central; peripheral.stopAdvertising(); becameReady()
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard peerCentral?.identifier == central.identifier else { return }; stop(message: "Bluetooth disconnected. Choose a pairing role to retry.")
    }
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        guard peripheralManager === peripheral, active, ready, let peerCentral else {
            for request in requests { peripheral.respond(to: request, withResult: .writeNotPermitted) }; return
        }
        for request in requests {
            guard request.central.identifier == peerCentral.identifier, request.characteristic.uuid == Self.rxID, request.offset == 0, let bytes = request.value else { peripheral.respond(to: request, withResult: .writeNotPermitted); stop(message: "Unexpected Bluetooth write. Pairing stopped."); return }
            do { try receive(bytes); peripheral.respond(to: request, withResult: .success) }
            catch { peripheral.respond(to: request, withResult: .invalidAttributeValueLength); stop(message: "Invalid Bluetooth message. Pairing stopped."); return }
        }
    }
    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        guard peripheralManager === peripheral else { return }; pump()
    }
}
