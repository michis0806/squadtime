package dev.squadtime.pairing

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.Closeable
import java.security.MessageDigest

class EnrollmentRejected : IllegalStateException("Local enrollment proof rejected")

/** Public-only synthetic transcript evidence; byte-valued fields use canonical Base64. */
data class EnrollmentProof(
    val pendingId: String,
    val groupId: String,
    val keyPackage: String,
    val request: String,
    val approval: String,
    val requestSignature: String,
    val approvalSignature: String,
    val devicePublicKey: String,
    val trustedApproverPublicKey: String,
    val now: Long,
) {
    fun publicJson(): JSONObject = JSONObject().put("pendingId", pendingId).put("groupId", groupId)
        .put("keyPackage", keyPackage).put("request", request).put("approval", approval)
        .put("requestSignature", requestSignature).put("approvalSignature", approvalSignature)
        .put("devicePublicKey", devicePublicKey).put("trustedApproverPublicKey", trustedApproverPublicKey).put("now", now)
}

class EnrolledVaultProof(
    val vault: MlsVault,
    val packets: List<ByteArray>,
    val expected: List<ByteArray>,
) : Closeable {
    override fun close() { vault.close(); packets.forEach { it.fill(0) }; expected.forEach { it.fill(0) } }
}

/** Local proof only: Rust holds the synthetic admin, joiner and pending state in one process. */
object NativeEnrollment {
    internal fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    internal fun decode(value: String, maximum: Int): ByteArray {
        if (value.isEmpty() || value.length > ((maximum + 2L) / 3L) * 4L) throw EnrollmentRejected()
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        if (bytes.size > maximum || encode(bytes) != value) { bytes.fill(0); throw EnrollmentRejected() }
        return bytes
    }
    internal fun publicBytes(hex: String): ByteArray {
        validateDevicePublicKey(hex)
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    internal fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    internal fun validClock(now: Long) { if (now !in 0..9_007_199_254_740_991L) throw EnrollmentRejected() }

    fun prepare(deviceKey: DeviceSigningKey, trustedApproverPublicKey: String, now: Long): PendingEnrollment {
        var createdPending: String? = null
        try {
            validClock(now)
            if (now > 9_007_199_254_740_691L) throw EnrollmentRejected()
            val devicePublicKey = encode(publicBytes(deviceKey.publicKeyHex()))
            val trusted = encode(publicBytes(trustedApproverPublicKey))
            if (devicePublicKey == trusted) throw EnrollmentRejected()
            val json = NativeMls.call(JSONObject().put("op", "enrollmentprepare")
                .put("devicePublicKey", devicePublicKey).put("approverPublicKey", trusted).put("now", now))
            createdPending = json.getString("pendingId")
            return PendingEnrollment(deviceKey, trustedApproverPublicKey, now, devicePublicKey, trusted,
                createdPending, json.getString("groupId"), json.getString("keyPackage"),
                json.getString("request"), json.getString("approval"))
        } catch (_: Exception) {
            createdPending?.let { try { cancel(it) } catch (_: Exception) { /* Nothing remains pending. */ } }
            throw EnrollmentRejected()
        }
    }

    /** Direct candidate boundary: Rust validates against its stored, trusted local pending context. */
    fun completeCandidate(proof: EnrollmentProof, now: Long): MlsFixture = try {
        validClock(now)
        NativeMls.fixtureResult(NativeMls.call(JSONObject().put("op", "enrollmentcomplete")
            .put("pendingId", proof.pendingId).put("groupId", proof.groupId).put("keyPackage", proof.keyPackage)
            .put("requestSignature", proof.requestSignature).put("approvalSignature", proof.approvalSignature).put("now", now)))
    } catch (_: Exception) { throw EnrollmentRejected() }

    internal fun cancel(pendingId: String) {
        NativeMls.call(JSONObject().put("op", "enrollmentcancel").put("pendingId", pendingId))
    }
}

/** One-shot, memory-only coordinator; it makes no restart-persistent admission guarantee. */
class PendingEnrollment internal constructor(
    private val deviceKey: DeviceSigningKey,
    private val trustedApproverHex: String,
    private val issuedAt: Long,
    val devicePublicKey: String,
    val trustedApproverPublicKey: String,
    val pendingId: String,
    val groupId: String,
    val keyPackage: String,
    val request: String,
    val approval: String,
) : Closeable {
    private var consumed = false
    private var closed = false
    init { validateContext(issuedAt) }

    private fun validateContext(now: Long) {
        NativeEnrollment.validClock(now)
        if (closed || consumed || now < issuedAt || now >= issuedAt + 300) throw EnrollmentRejected()
        if (NativeEnrollment.decode(pendingId, 32).size != 32) throw EnrollmentRejected()
        if (NativeEnrollment.decode(groupId, 256).isEmpty()) throw EnrollmentRejected()
        if (NativeEnrollment.encode(NativeEnrollment.publicBytes(deviceKey.publicKeyHex())) != devicePublicKey ||
            NativeEnrollment.encode(NativeEnrollment.publicBytes(trustedApproverHex)) != trustedApproverPublicKey) throw EnrollmentRejected()
        val requestBytes = NativeEnrollment.decode(request, 4096)
        val approvalBytes = NativeEnrollment.decode(approval, 2048)
        val packageBytes = NativeEnrollment.decode(keyPackage, 1024 * 1024)
        val requestText = requestBytes.toString(Charsets.UTF_8)
        val lines = requestText.split('\n')
        if (lines.size != 11 || !lines[4].matches(Regex("[0-9a-f]{64}")) || !lines[5].matches(Regex("[0-9a-f]{64}"))) throw EnrollmentRejected()
        val expectedRequest = "squadtime-mls-device-request-v1\n$pendingId\n$groupId\n${NativeEnrollment.sha256(packageBytes)}\n${lines[4]}\n${lines[5]}\n$devicePublicKey\n$trustedApproverPublicKey\n$issuedAt\n${issuedAt + 300}\n"
        val expectedApproval = "squadtime-mls-device-approval-v1\n$pendingId\n${NativeEnrollment.sha256(requestBytes)}\n$trustedApproverPublicKey\n"
        if (!requestBytes.contentEquals(expectedRequest.toByteArray(Charsets.UTF_8)) ||
            !approvalBytes.contentEquals(expectedApproval.toByteArray(Charsets.UTF_8))) throw EnrollmentRejected()
    }

    @Synchronized
    fun authorize(approverKey: DeviceSigningKey, userConfirmed: Boolean, now: Long): EnrollmentProof = try {
        validateContext(now)
        if (!userConfirmed || approverKey.publicKeyHex() != trustedApproverHex) throw EnrollmentRejected()
        val requestSignature = deviceKey.sign(NativeEnrollment.decode(request, 4096))
        val approvalSignature = approverKey.sign(NativeEnrollment.decode(approval, 2048))
        EnrollmentProof(pendingId, groupId, keyPackage, request, approval,
            NativeEnrollment.encode(requestSignature.chunked(2).map { it.toInt(16).toByte() }.toByteArray()),
            NativeEnrollment.encode(approvalSignature.chunked(2).map { it.toInt(16).toByte() }.toByteArray()),
            devicePublicKey, trustedApproverPublicKey, now)
    } catch (_: Exception) { throw EnrollmentRejected() }

    @Synchronized
    fun complete(proof: EnrollmentProof, now: Long): MlsFixture = try {
        validateContext(now)
        if (proof.pendingId != pendingId || proof.groupId != groupId || proof.keyPackage != keyPackage ||
            proof.request != request || proof.approval != approval || proof.devicePublicKey != devicePublicKey ||
            proof.trustedApproverPublicKey != trustedApproverPublicKey) throw EnrollmentRejected()
        if (!verifyDeviceSignature(deviceKey.publicKeyHex(), NativeEnrollment.decode(request, 4096),
                NativeEnrollment.decode(proof.requestSignature, 72).hex()) ||
            !verifyDeviceSignature(trustedApproverHex, NativeEnrollment.decode(approval, 2048),
                NativeEnrollment.decode(proof.approvalSignature, 72).hex())) throw EnrollmentRejected()
        val fixture = NativeEnrollment.completeCandidate(proof, now)
        consumed = true
        fixture
    } catch (_: Exception) { throw EnrollmentRejected() }

    @Synchronized
    fun completeIntoVault(context: Context, vaultId: String, proof: EnrollmentProof, now: Long): EnrolledVaultProof {
        val fixture = complete(proof, now)
        try {
            val vault = MlsVault.create(context, vaultId, fixture.snapshot)
            return EnrolledVaultProof(vault, fixture.packets.map { it.copyOf() }, fixture.expected.map { it.copyOf() })
        } finally { fixture.clear() }
    }

    @Synchronized
    override fun close() {
        if (!closed && !consumed) {
            try { NativeEnrollment.cancel(pendingId) } catch (_: Exception) { /* Already expired or consumed. */ }
        }
        closed = true
    }
}
