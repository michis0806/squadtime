package dev.squadtime.prototype

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Foreground-only transport. Its bytes are untrusted until the separate ceremony authenticates them. */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION")
class NearbyBleTransport(context: Context, private val listener: Listener) {
    interface Listener {
        fun state(message: String)
        fun devices(labels: List<String>)
        fun ready(owner: Boolean)
        fun message(bytes: ByteArray)
        fun stopped(reason: String)
    }
    companion object {
        val SERVICE: UUID = UUID.fromString("9B0A1000-6E7D-4C56-9E2A-4D6E53515431")
        val RX: UUID = UUID.fromString("9B0A1001-6E7D-4C56-9E2A-4D6E53515431")
        val TX: UUID = UUID.fromString("9B0A1002-6E7D-4C56-9E2A-4D6E53515431")
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
    private val appContext = context.applicationContext
    private val manager = appContext.getSystemService(BluetoothManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val reader = BleFrameReader()
    private val writer = BleFrameWriter()
    private val discovered = mutableListOf<BluetoothDevice>()
    private var server: BluetoothGattServer? = null
    private var gatt: BluetoothGatt? = null
    private var peer: BluetoothDevice? = null
    private var rx: BluetoothGattCharacteristic? = null
    private var tx: BluetoothGattCharacteristic? = null
    private var started = false
    private var closed = false
    private var owner = false
    private var ready = false
    private var writing = false
    private var scanning = false
    private var advertising = false
    private var subscribing = false
    private val earlyNotifications = mutableListOf<ByteArray>()
    private var earlyBytes = 0
    private val pendingIngress = AtomicInteger(0)
    private val ingressRejected = AtomicBoolean(false)
    private val scanPosted = AtomicBoolean(false)
    private var flushStop: String? = null
    private val sessionTimeout = Runnable { stop("Nearby session expired. Start a new attempt or use QR.") }
    private val scanTimeout = Runnable { stop("Nearby search ended after 60 seconds. Try again or use QR.") }
    private val partialTimeout = Runnable { stop("Nearby frame did not finish in time. Start a new attempt or use QR.") }
    private fun guard(block: () -> Unit) {
        if (closed) return
        try { block() } catch (_: Exception) { stop("Nearby connection failed. Try a new attempt or use QR.") }
    }
    private fun incoming(value: ByteArray, action: (ByteArray) -> Unit) {
        if (ingressRejected.get()) return
        if (value.size !in 1..20 || pendingIngress.incrementAndGet() > 64) {
            if (value.size in 1..20) pendingIngress.decrementAndGet()
            if (ingressRejected.compareAndSet(false,true)) main.post { stop("Nearby input exceeded the test limits. Use a new attempt or QR.") }
            return
        }
        val bytes = value.copyOf()
        main.post {
            try { guard { action(bytes) } } finally { bytes.fill(0); pendingIngress.decrementAndGet() }
        }
    }
    private fun start(asOwner: Boolean) {
        check(Looper.myLooper() == Looper.getMainLooper())
        check(!started && !closed)
        started = true; owner = asOwner
        check(manager?.adapter?.isEnabled == true)
        main.postDelayed(sessionTimeout,180_000)
    }
    fun advertise() = guard {
        start(true)
        check(manager.adapter.isMultipleAdvertisementSupported)
        server = manager.openGattServer(appContext,serverCallback) ?: error("No GATT server")
        rx = BluetoothGattCharacteristic(RX,BluetoothGattCharacteristic.PROPERTY_WRITE,BluetoothGattCharacteristic.PERMISSION_WRITE)
        tx = BluetoothGattCharacteristic(TX,BluetoothGattCharacteristic.PROPERTY_NOTIFY,0).apply {
            addDescriptor(BluetoothGattDescriptor(CCCD,BluetoothGattDescriptor.PERMISSION_WRITE))
        }
        val service = BluetoothGattService(SERVICE,BluetoothGattService.SERVICE_TYPE_PRIMARY).apply { addCharacteristic(rx); addCharacteristic(tx) }
        check(server!!.addService(service))
        listener.state("Preparing nearby advertisement…")
    }
    fun find() = guard {
        start(false)
        val scanner = manager.adapter.bluetoothLeScanner ?: error("No scanner")
        scanning = true
        scanner.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE)).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),scanCallback)
        main.postDelayed(scanTimeout,60_000)
        listener.state("Looking for nearby Squadtime test devices…")
    }
    fun connect(index: Int) = guard {
        check(!owner && scanning && peer == null)
        val selected = discovered[index]
        manager.adapter.bluetoothLeScanner?.stopScan(scanCallback); scanning = false
        main.removeCallbacks(scanTimeout)
        peer = selected
        gatt = selected.connectGatt(appContext,false,clientCallback,BluetoothDevice.TRANSPORT_LE) ?: error("No connection")
        listener.state("Connecting to the selected test device…")
    }
    fun send(bytes: ByteArray): Boolean {
        if (closed) return false
        return try { check(ready && flushStop == null); writer.enqueue(bytes); pump(); !closed }
        catch (_: Exception) { stop("Nearby connection failed. Try a new attempt or use QR."); false }
    }
    fun finishAfterSending(reason: String) = guard { flushStop = reason; if (writer.isIdle()) stop(reason) }
    private fun pump() {
        if (!ready || writing || closed) return
        val chunk = writer.next() ?: run { flushStop?.let { stop(it) }; return }
        writing = true
        try {
            if (owner) {
                if (android.os.Build.VERSION.SDK_INT >= 33) check(server!!.notifyCharacteristicChanged(peer!!,tx!!,false,chunk) == BluetoothStatusCodes.SUCCESS)
                else { tx!!.value = chunk; check(server!!.notifyCharacteristicChanged(peer,tx,false)) }
            } else {
                if (android.os.Build.VERSION.SDK_INT >= 33) check(gatt!!.writeCharacteristic(rx!!,chunk,BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS)
                else {
                    rx!!.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    rx!!.value = chunk; check(gatt!!.writeCharacteristic(rx))
                }
            }
        } finally { chunk.fill(0) }
    }
    private fun sent(status: Int) = guard {
        check(writing && status == BluetoothGatt.GATT_SUCCESS)
        writer.acknowledge(); writing = false; pump()
    }
    private fun receive(bytes: ByteArray) = guard {
        try {
            if (!reader.hasPartial) main.postDelayed(partialTimeout,15_000)
            reader.accept(bytes).forEach { try { listener.message(it) } finally { it.fill(0) } }
            if (!reader.hasPartial) main.removeCallbacks(partialTimeout)
        } finally { bytes.fill(0) }
    }
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) { if (!scanPosted.compareAndSet(false,true)) return; main.post { try { guard {
            if (!scanning) return@guard
            if (result.scanRecord?.serviceUuids?.contains(ParcelUuid(SERVICE)) != true) return@guard
            if (discovered.none { it.address == result.device.address } && discovered.size < 8) {
                discovered.add(result.device)
                listener.devices(discovered.indices.map { "Nearby test device ${it + 1}" })
            }
        } } finally { scanPosted.set(false) } } }
        override fun onScanFailed(errorCode: Int) { main.post { stop("Nearby search failed. Check Bluetooth permission or use QR.") } }
    }
    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) { main.post { guard { listener.state("Advertising this test device. Ask your contact to choose Find nearby.") } } }
        override fun onStartFailure(errorCode: Int) { main.post { stop("This device could not advertise over Bluetooth. Use QR instead.") } }
    }
    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) { main.post { guard {
            check(status == BluetoothGatt.GATT_SUCCESS && service.uuid == SERVICE)
            val advertiser = manager.adapter.bluetoothLeAdvertiser ?: error("No advertiser")
            advertising = true
            advertiser.startAdvertising(AdvertiseSettings.Builder().setConnectable(true).setTimeout(0)
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY).build(),
                AdvertiseData.Builder().setIncludeDeviceName(false).setIncludeTxPowerLevel(false).addServiceUuid(ParcelUuid(SERVICE)).build(),advertiseCallback)
        } } }
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) { main.post { guard {
            if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                if (peer != null && peer != device) { server?.cancelConnection(device); return@guard }
                check(peer == null)
                peer = device
                manager.adapter.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback); advertising = false
                listener.state("Connected. Waiting for the test channel subscription…")
            } else if (peer == device) stop("Nearby device disconnected. Start a new attempt or use QR.")
        } } }
        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            incoming(value) { bytes ->
                    val valid = peer == device && descriptor.uuid == CCCD && descriptor.characteristic.uuid == TX && !ready && !preparedWrite && offset == 0 && responseNeeded && bytes.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                    server?.sendResponse(device,requestId,if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,0,null)
                    check(valid)
                    ready = true; listener.ready(true)
            }
        }
        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            incoming(value) { bytes ->
                val valid = peer == device && ready && characteristic.uuid == RX && !preparedWrite && offset == 0 && responseNeeded && bytes.size in 1..20
                server?.sendResponse(device,requestId,if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED,0,null)
                if (!valid) { bytes.fill(0); error("Invalid write") }
                receive(bytes)
            }
        }
        override fun onNotificationSent(device: BluetoothDevice, status: Int) { main.post { if (device == peer) sent(status) } }
    }
    private val clientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(connection: BluetoothGatt, status: Int, newState: Int) { main.post { guard {
            check(connection == gatt && status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED)
            check(connection.discoverServices())
        } } }
        override fun onServicesDiscovered(connection: BluetoothGatt, status: Int) { main.post { guard {
            check(connection == gatt && status == BluetoothGatt.GATT_SUCCESS)
            val service = connection.getService(SERVICE) ?: error("Missing service")
            rx = service.getCharacteristic(RX); tx = service.getCharacteristic(TX)
            check(rx != null && tx != null && rx!!.properties and BluetoothGattCharacteristic.PROPERTY_WRITE != 0 && tx!!.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0)
            check(connection.setCharacteristicNotification(tx,true))
            val descriptor = tx!!.getDescriptor(CCCD) ?: error("Missing subscription")
            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            subscribing = true
            check(connection.writeDescriptor(descriptor))
        } } }
        override fun onDescriptorWrite(connection: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) { main.post { guard {
            check(connection == gatt && !ready && descriptor.uuid == CCCD && descriptor.characteristic.uuid == TX && status == BluetoothGatt.GATT_SUCCESS)
            subscribing = false; ready = true; listener.ready(false)
            val pending = earlyNotifications.toList(); earlyNotifications.clear(); earlyBytes = 0
            pending.forEach { try { receive(it) } finally { it.fill(0) } }
        } } }
        override fun onCharacteristicWrite(connection: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) { main.post { if (connection == gatt && characteristic.uuid == RX) sent(status) } }
        override fun onCharacteristicChanged(connection: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (android.os.Build.VERSION.SDK_INT < 33) changed(connection,characteristic,characteristic.value)
        }
        override fun onCharacteristicChanged(connection: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) { changed(connection,characteristic,value) }
        private fun changed(connection: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            incoming(value) { bytes ->
                if (connection != gatt || characteristic.uuid != TX) return@incoming
                if (ready) receive(bytes)
                else if (subscribing) {
                    require(bytes.size in 1..20 && earlyBytes + bytes.size <= 2096)
                    earlyNotifications.add(bytes.copyOf()); earlyBytes += bytes.size
                } else { bytes.fill(0); error("Premature notification") }
            }
        }
    }
    fun stop(reason: String = "Nearby connection cancelled. QR remains available.") {
        if (closed) return
        closed = true; ready = false
        ingressRejected.set(true)
        main.removeCallbacks(sessionTimeout); main.removeCallbacks(scanTimeout); main.removeCallbacks(partialTimeout)
        runCatching { if (scanning) manager?.adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        runCatching { if (advertising) manager?.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        runCatching { gatt?.disconnect() }; runCatching { gatt?.close() }
        runCatching { peer?.let { server?.cancelConnection(it) } }; runCatching { server?.clearServices(); server?.close() }
        reader.clear(); writer.clear(); discovered.clear(); peer = null; rx = null; tx = null; gatt = null; server = null
        earlyNotifications.forEach { it.fill(0) }; earlyNotifications.clear(); earlyBytes = 0; subscribing = false
        listener.stopped(reason)
    }
}
