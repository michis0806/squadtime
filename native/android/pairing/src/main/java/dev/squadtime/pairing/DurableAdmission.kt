package dev.squadtime.pairing

import android.content.Context
import org.json.JSONObject
import java.io.Closeable
import java.util.UUID

/** Public transport only: never contains secret Rust state or plaintext. */
class AdmissionPublicResult(val kind: String, val outbox: String, val nativePublicKey: String) {
    fun json(): JSONObject = JSONObject().put("kind", kind).put("outbox", outbox).put("nativePublicKey", nativePublicKey)
}

/** Independent-client proof. Secret role state, exact outbox and inbox share one encrypted CAS row. */
class DurableAdmission private constructor(private val store: AdmissionStore) : Closeable {
    companion object {
        fun createOwner(context: Context, id: String): DurableAdmission = try {
            DurableAdmission(AdmissionStore.create(context, id, "owner"))
        } catch (_: Exception) { throw AdmissionRejected() }
        fun createJoiner(context: Context, id: String, independentlyTrustedAdminPublicKey: String): DurableAdmission = try {
            DurableAdmission(AdmissionStore.create(context, id, "joiner", independentlyTrustedAdminPublicKey))
        } catch (_: Exception) { throw AdmissionRejected() }
        fun open(context: Context, id: String): DurableAdmission = try { DurableAdmission(AdmissionStore.open(context, id)) }
        catch (_: Exception) { throw AdmissionRejected() }
        fun deleteSynthetic(context: Context, id: String) { AdmissionStore.deleteSynthetic(context, id) }
        fun signingAliasForProof(id: String) = AdmissionStore.signingAlias(id)
        fun encryptionAliasForProof(id: String) = AdmissionStore.encryptionAlias(id)
        fun databaseFileForProof(context: Context, id: String) = AdmissionStore.file(context, id)
    }
    private fun call(op: String, fields: JSONObject): JSONObject = NativeMls.call(fields.put("op", op))
    private fun text(json: JSONObject, name: String): String = json.get(name) as? String ?: throw AdmissionRejected()
    private fun sign(bytes: ByteArray): String {
        val signer = DeviceSigningKey(AdmissionStore.signingAlias(store.id))
        if (!signer.exists()) throw AdmissionRejected()
        val hex = signer.sign(bytes)
        return NativeEnrollment.encode(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    }
    private fun resume(record: AdmissionRecord): AdmissionPublicResult {
        if (record.phase == "created" || record.outbox == null) throw AdmissionRejected()
        val native = call("admissionresume", JSONObject().put("state", record.state))
        if (text(native, "kind") != record.phase || text(native, "outbox") != record.outbox) throw AdmissionRejected()
        return AdmissionPublicResult(record.phase, record.outbox, record.publicKey)
    }
    private fun staged(record: AdmissionRecord, response: JSONObject, phase: String, inputDigest: String? = null,
                       inbox: List<InboxMessage> = record.inbox, acceptedInput: String? = record.acceptedInput): AdmissionRecord {
        if (text(response, "kind") != phase) throw AdmissionRejected()
        return record.next(phase, text(response, "state"), text(response, "outbox"), inbox, inputDigest, acceptedInput)
    }
    @Synchronized fun nativePublicKey(): String {
        val record = store.current()
        try { return record.publicKey } finally { record.clear() }
    }
    @Synchronized fun trustedAdminPublicKey(): String {
        val record = store.current()
        try { return record.trustedPin } finally { record.clear() }
    }
    @Synchronized fun consumedProbeForProof(): String {
        val record = store.current()
        try {
            if (record.role != "joiner" || record.phase != "joined") throw AdmissionRejected()
            return AdmissionProtocol.welcome(record.acceptedInput ?: throw AdmissionRejected(), record.trustedPin, record.publicKey).json.getString("probe")
        } finally { record.clear() }
    }
    @Synchronized fun resume(): AdmissionPublicResult {
        val record = store.current()
        try { return resume(record) } catch (_: Exception) { throw AdmissionRejected() } finally { record.clear() }
    }
    @Synchronized fun ownerStart(now: Long, fault: VaultFault = VaultFault.NONE, testBeforeCas: (() -> Unit)? = null): AdmissionPublicResult {
        val expected = store.expectedRevision()
        val record = store.current()
        try {
            NativeEnrollment.validClock(now)
            if (record.role != "owner") throw AdmissionRejected()
            if (record.phase == "invitation") return resume(record)
            if (record.phase != "created") throw AdmissionRejected()
            val draft = call("admissioncreateadmin", JSONObject().put("adminPublicKey", record.publicKey).put("now", now))
            val transcript = AdmissionProtocol.invitationDraft(text(draft, "transcript"), record.publicKey, now)
            val reply = call("admissionpublishinvitation", JSONObject().put("state", text(draft, "state")).put("signature", sign(transcript)).put("now", now))
            val next = staged(record, reply, "invitation")
            val invite = AdmissionProtocol.invitation(next.outbox ?: throw AdmissionRejected(), record.publicKey, now)
            if (!invite.transcript.contentEquals(transcript)) throw AdmissionRejected()
            store.commit(expected, next, fault, testBeforeCas)
            return resume(next)
        } catch (_: Exception) { throw AdmissionRejected() } finally { record.clear() }
    }
    @Synchronized fun joinerStart(invitation: String, now: Long, fault: VaultFault = VaultFault.NONE,
                                  testBeforeCas: (() -> Unit)? = null): AdmissionPublicResult {
        val expected = store.expectedRevision()
        val record = store.current()
        try {
            NativeEnrollment.validClock(now)
            if (record.role != "joiner") throw AdmissionRejected()
            val digest = AdmissionProtocol.digest(invitation)
            if (record.phase == "request" && record.inputDigest == digest) return resume(record)
            if (record.phase != "created") throw AdmissionRejected()
            val invite = AdmissionProtocol.invitation(invitation, record.trustedPin, now)
            val draft = call("admissioncreatejoiner", JSONObject().put("invitation", invitation).put("trustedAdminPublicKey", record.trustedPin)
                .put("devicePublicKey", record.publicKey).put("now", now))
            val transcript = AdmissionProtocol.requestDraft(text(draft, "transcript"), invite, record.publicKey, record.trustedPin, now)
            val reply = call("admissionpublishrequest", JSONObject().put("state", text(draft, "state")).put("signature", sign(transcript)).put("now", now))
            val next = staged(record, reply, "request", digest, acceptedInput = invitation)
            val request = AdmissionProtocol.request(next.outbox ?: throw AdmissionRejected(), record.trustedPin, record.publicKey, now)
            if (request.invitation.encoded != invitation || !request.transcript.contentEquals(transcript)) throw AdmissionRejected()
            store.commit(expected, next, fault, testBeforeCas)
            return resume(next)
        } catch (_: Exception) { throw AdmissionRejected() } finally { record.clear() }
    }
    @Synchronized fun ownerAdmit(request: String, independentlyTrustedDevicePublicKey: String, userConfirmed: Boolean,
                                 now: Long, fault: VaultFault = VaultFault.NONE,
                                 testBeforeCas: (() -> Unit)? = null): AdmissionPublicResult {
        val expected = store.expectedRevision()
        val record = store.current()
        try {
            NativeEnrollment.validClock(now)
            if (record.role != "owner" || !userConfirmed) throw AdmissionRejected()
            val digest = AdmissionProtocol.digest(request)
            if (record.phase == "welcome" && record.inputDigest == digest) {
                AdmissionProtocol.welcome(record.outbox ?: throw AdmissionRejected(), record.publicKey, independentlyTrustedDevicePublicKey)
                return resume(record)
            }
            if (record.phase != "invitation") throw AdmissionRejected()
            val inspected = AdmissionProtocol.request(request, record.publicKey, independentlyTrustedDevicePublicKey, now)
            if (inspected.invitation.encoded != record.outbox) throw AdmissionRejected()
            val native = call("admissioninspectrequest", JSONObject().put("state", record.state).put("request", request)
                .put("trustedDevicePublicKey", independentlyTrustedDevicePublicKey).put("now", now))
            if (!NativeEnrollment.decode(text(native, "transcript"), 4096).contentEquals(inspected.approval)) throw AdmissionRejected()
            val reply = call("admissionadmit", JSONObject().put("state", record.state).put("request", request)
                .put("trustedDevicePublicKey", independentlyTrustedDevicePublicKey).put("approvalSignature", sign(inspected.approval)).put("now", now))
            val next = staged(record, reply, "welcome", digest, acceptedInput = request)
            val welcome = AdmissionProtocol.welcome(next.outbox ?: throw AdmissionRejected(), record.publicKey, independentlyTrustedDevicePublicKey)
            if (welcome.request.encoded != request) throw AdmissionRejected()
            store.commit(expected, next, fault, testBeforeCas)
            return resume(next)
        } catch (_: Exception) { throw AdmissionRejected() } finally { record.clear() }
    }
    @Synchronized fun joinerFinish(welcome: String, now: Long, fault: VaultFault = VaultFault.NONE,
                                   testBeforeCas: (() -> Unit)? = null): AdmissionPublicResult {
        val expected = store.expectedRevision()
        val record = store.current()
        var message: InboxMessage? = null
        try {
            NativeEnrollment.validClock(now)
            if (record.role != "joiner") throw AdmissionRejected()
            val digest = AdmissionProtocol.digest(welcome)
            if (record.phase == "joined" && record.inputDigest == digest) return resume(record)
            if (record.phase != "request") throw AdmissionRejected()
            val verified = AdmissionProtocol.welcome(welcome, record.trustedPin, record.publicKey)
            if (verified.request.encoded != record.outbox) throw AdmissionRejected()
            val joined = call("admissionjoin", JSONObject().put("state", record.state).put("welcome", welcome).put("now", now))
            if (text(joined, "kind") != "joined" || text(joined, "outbox") != "") throw AdmissionRejected()
            val received = call("admissionreceive", JSONObject().put("state", text(joined, "state")).put("packet", verified.json.getString("probe")))
            val sender = received.getLong("senderIndex")
            if (sender !in 0..4_294_967_295L) throw AdmissionRejected()
            message = InboxMessage(UUID.randomUUID().toString(), NativeEnrollment.decode(text(received, "plaintext"), 1024 * 1024), sender)
            val next = record.next("joined", text(received, "state"), "", record.inbox + message, digest, welcome)
            store.commit(expected, next, fault, testBeforeCas)
            return resume(next)
        } catch (_: Exception) { throw AdmissionRejected() }
        finally { record.clear(); message?.clear() }
    }
    @Synchronized fun receive(packet: String, fault: VaultFault = VaultFault.NONE): InboxMessage {
        val expected = store.expectedRevision()
        val record = store.current()
        var message: InboxMessage? = null
        try {
            if (record.phase !in setOf("welcome", "joined") || record.inbox.size >= 128) throw AdmissionRejected()
            val received = call("admissionreceive", JSONObject().put("state", record.state).put("packet", packet))
            val sender = received.getLong("senderIndex")
            if (sender !in 0..4_294_967_295L) throw AdmissionRejected()
            message = InboxMessage(UUID.randomUUID().toString(), NativeEnrollment.decode(text(received, "plaintext"), 1024 * 1024), sender)
            store.commit(expected, record.next(record.phase, text(received, "state"), record.outbox, record.inbox + message), fault)
            return InboxMessage(message.id, message.plaintext.copyOf(), message.senderIndex)
        } catch (_: Exception) { throw AdmissionRejected() }
        finally { record.clear(); message?.clear() }
    }
    @Synchronized fun pending(): List<InboxMessage> {
        val record = store.current()
        try { return record.inbox.map { InboxMessage(it.id, it.plaintext.copyOf(), it.senderIndex) } } finally { record.clear() }
    }
    @Synchronized fun acknowledge(messageId: String, fault: VaultFault = VaultFault.NONE) {
        val expected = store.expectedRevision()
        val record = store.current()
        try {
            if (record.inbox.none { it.id == messageId }) throw AdmissionRejected()
            val remaining = record.inbox.filter { it.id != messageId }
            store.commit(expected, record.next(record.phase, record.state, record.outbox, remaining), fault)
        } catch (_: Exception) { throw AdmissionRejected() } finally { record.clear() }
    }
    override fun close() { store.close() }
}
