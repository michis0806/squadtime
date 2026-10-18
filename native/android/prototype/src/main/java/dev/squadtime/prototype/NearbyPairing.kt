package dev.squadtime.prototype

import android.content.Context
import android.os.Handler
import android.os.Looper

/** Holds only volatile ceremony state; callbacks and explicit native review remain on the foreground UI. */
class NearbyPairing(context: Context, private val owner: Boolean, private val invitation: String?, private val listener: Listener) {
    data class State(val message: String, val devices: List<String> = emptyList(), val sas: String? = null, val localApproved: Boolean = false, val authenticated: Boolean = false)
    interface Listener {
        fun changed(state: State)
        fun pairCode(code: String)
        fun stopped(reason: String)
    }
    private val main = Handler(Looper.getMainLooper())
    private var ceremony: BleCeremony? = null
    private var closed = false
    private var comparisonStarted = false
    private var authenticated = false
    private var receivedCode = false
    private var sentCode = false
    private var stage = "handshake"
    private val stageTimeout = Runnable { stop("Nearby $stage timed out. Start a new attempt or use QR.") }
    private val invitationTimeout = Runnable { stop("The native invitation expired. Use QR to inspect the saved exchange or explicitly reset for a new one.") }
    private fun invitationDeadline(code: String) {
        val qr = PrototypeProtocol.parseQr(code)
        val remaining = qr.getLong("expiresAt") * 1000 - System.currentTimeMillis()
        require(remaining > 0)
        main.removeCallbacks(invitationTimeout); main.postDelayed(invitationTimeout,remaining)
    }
    private fun deadline(name: String, millis: Long) { stage = name; main.removeCallbacks(stageTimeout); main.postDelayed(stageTimeout,millis) }
    private val transport = NearbyBleTransport(context,object : NearbyBleTransport.Listener {
        override fun state(message: String) { if (!closed) listener.changed(State(message)) }
        override fun devices(labels: List<String>) { if (!closed) listener.changed(State("Choose the intended nearby test device. Discovery order does not verify identity.",labels)) }
        override fun ready(owner: Boolean) = protect {
            ceremony = BleCeremony(owner)
            deadline("handshake",15_000)
            if (owner) send(ceremony!!.start())
            update()
        }
        override fun message(bytes: ByteArray) = protect {
            val session = checkNotNull(ceremony)
            val result = session.receive(bytes)
            result.outgoing?.let { send(it) }
            if (session.awaitingHandshake) deadline("handshake",15_000)
            else if (!comparisonStarted) { comparisonStarted = true; deadline("code comparison",90_000) }
            update()
            result.pairCode?.let { code ->
                val qr = PrototypeProtocol.parseQr(code)
                require(qr.getString("type") == if (owner) "request" else "invite")
                require(!receivedCode)
                if (!owner) invitationDeadline(code)
                receivedCode = true; main.removeCallbacks(stageTimeout)
                listener.pairCode(code)
            }
        }
        override fun stopped(reason: String) {
            if (closed) return
            closed = true; main.removeCallbacksAndMessages(null); ceremony?.close(); ceremony = null
            listener.stopped(reason)
        }
    })
    private fun protect(block: () -> Unit) {
        if (closed) return
        try { block() } catch (_: Exception) { stop("Nearby verification failed. Start a new attempt or use QR. No unconfirmed native pin was accepted.") }
    }
    private fun send(bytes: ByteArray) {
        try { check(transport.send(bytes)) } finally { bytes.fill(0) }
    }
    fun start() = protect { if (owner) { invitationDeadline(checkNotNull(invitation)); transport.advertise() } else transport.find() }
    fun choose(index: Int) { if (!closed) transport.connect(index) }
    fun codesMatch() = protect {
        val session = checkNotNull(ceremony)
        send(session.approve())
        session.confirmationQueued()
        update()
    }
    private fun update() {
        val session = ceremony ?: return
        listener.changed(State(when {
            session.authenticated -> "Bluetooth code confirmed on both devices. Review the intended contact and relay before native admission."
            session.localApproved -> "You confirmed the code. Waiting for the other device’s confirmation…"
            session.sas != null -> "Compare all six digits on the intended devices, then both select Codes match. Bluetooth does not prove proximity or identity."
            else -> "Exchanging commitments and ephemeral keys…"
        },sas = session.sas,localApproved = session.localApproved,authenticated = session.authenticated))
        if (session.authenticated && !authenticated) {
            authenticated = true; deadline("public code transfer",60_000)
            if (owner) sendPairCode(checkNotNull(invitation))
        }
    }
    fun sendPairCode(code: String) = protect {
        check(authenticated && !sentCode && (owner || receivedCode))
        val qr = PrototypeProtocol.parseQr(code)
        require(qr.getString("type") == if (owner) "invite" else "request")
        send(checkNotNull(ceremony).seal(code)); sentCode = true
        // Stay connected while the owner explicitly reviews the authenticated request.
        // A disconnect must discard an unconfirmed peer candidate on the other device.
    }
    fun acceptedRequest() { if (owner) stop("Bluetooth contact review complete. The encrypted test continues through the local relay.") }
    fun stop(reason: String = "Nearby connection cancelled. QR remains available.") { if (!closed) transport.stop(reason) }
}
