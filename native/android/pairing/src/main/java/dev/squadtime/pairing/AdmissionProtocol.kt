package dev.squadtime.pairing

import org.json.JSONObject

/** Strict public-envelope validation before any native signing or admission transition. */
internal object AdmissionProtocol {
    class Invitation(val encoded: String, val json: JSONObject, val transcript: ByteArray)
    class Request(val encoded: String, val json: JSONObject, val invitation: Invitation, val transcript: ByteArray, val approval: ByteArray)
    class Welcome(val encoded: String, val json: JSONObject, val request: Request)
    fun digest(outbox: String) = NativeEnrollment.sha256(NativeEnrollment.decode(outbox, 128 * 1024))
    private fun fields(json: JSONObject, names: Set<String>) {
        if (json.keys().asSequence().toSet() != names || json.get("version") !is Int || json.getInt("version") != 1) throw AdmissionRejected()
    }
    private fun text(json: JSONObject, key: String): String = json.get(key) as? String ?: throw AdmissionRejected()
    private fun integer(json: JSONObject, key: String): Long = when (val value = json.get(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw AdmissionRejected()
    }.also { NativeEnrollment.validClock(it) }
    private fun identity(json: JSONObject, key: String, maximum: Int = 4096): String =
        NativeEnrollment.sha256(NativeEnrollment.decode(text(json, key), maximum))
    private fun publicKey(value: String): String {
        val bytes = NativeEnrollment.decode(value, 65)
        if (bytes.size != 65) throw AdmissionRejected()
        val hex = bytes.hex()
        validateDevicePublicKey(hex)
        return hex
    }
    private fun signature(key: String, transcript: ByteArray, encoded: String) {
        if (!verifyDeviceSignature(publicKey(key), transcript, NativeEnrollment.decode(encoded, 72).hex())) throw AdmissionRejected()
    }
    private fun decoded(outbox: String): JSONObject = JSONObject(NativeEnrollment.decode(outbox, 128 * 1024).toString(Charsets.UTF_8))
    fun invitation(outbox: String, trustedPin: String, now: Long?): Invitation {
        val json = decoded(outbox)
        fields(json, setOf("version", "invitationId", "groupId", "adminIdentity", "adminPublicKey", "issuedAt", "expiresAt", "signature"))
        if (text(json, "adminPublicKey") != trustedPin || NativeEnrollment.decode(text(json, "invitationId"), 32).size != 32) throw AdmissionRejected()
        NativeEnrollment.decode(text(json, "groupId"), 256)
        val issued = integer(json, "issuedAt")
        val expires = integer(json, "expiresAt")
        if (expires - issued != 300L || expires <= issued) throw AdmissionRejected()
        if (now != null) { NativeEnrollment.validClock(now); if (now < issued || now >= expires) throw AdmissionRejected() }
        val transcript = "squadtime-mls-invitation-v1\n${text(json, "invitationId")}\n${text(json, "groupId")}\n${identity(json, "adminIdentity")}\n$trustedPin\n$issued\n$expires\n".toByteArray(Charsets.UTF_8)
        signature(trustedPin, transcript, text(json, "signature"))
        return Invitation(outbox, json, transcript)
    }
    fun request(outbox: String, trustedAdmin: String, trustedDevice: String, now: Long?): Request {
        val json = decoded(outbox)
        fields(json, setOf("version", "requestId", "invitation", "keyPackage", "joinerIdentity", "devicePublicKey", "issuedAt", "expiresAt", "signature"))
        if (text(json, "devicePublicKey") != trustedDevice || trustedAdmin == trustedDevice || NativeEnrollment.decode(text(json, "requestId"), 32).size != 32) throw AdmissionRejected()
        publicKey(trustedDevice)
        val invitation = invitation(text(json, "invitation"), trustedAdmin, now)
        val issued = integer(json, "issuedAt")
        val expires = integer(json, "expiresAt")
        if (issued < integer(invitation.json, "issuedAt") || issued >= expires || expires != integer(invitation.json, "expiresAt")) throw AdmissionRejected()
        if (now != null && (now < issued || now >= expires)) throw AdmissionRejected()
        val group = text(invitation.json, "groupId")
        val invitationDigest = digest(invitation.encoded)
        val adminIdentity = identity(invitation.json, "adminIdentity")
        val transcript = "squadtime-mls-admission-request-v1\n${text(json, "requestId")}\n$invitationDigest\n$group\n${identity(json, "keyPackage", 128 * 1024)}\n${identity(json, "joinerIdentity")}\n$adminIdentity\n$trustedDevice\n$trustedAdmin\n$issued\n$expires\n".toByteArray(Charsets.UTF_8)
        signature(trustedDevice, transcript, text(json, "signature"))
        val approval = "squadtime-mls-admission-approval-v1\n${text(json, "requestId")}\n${NativeEnrollment.sha256(transcript)}\n$invitationDigest\n$group\n$adminIdentity\n$trustedDevice\n$trustedAdmin\n$expires\n".toByteArray(Charsets.UTF_8)
        return Request(outbox, json, invitation, transcript, approval)
    }
    fun welcome(outbox: String, trustedAdmin: String, trustedDevice: String): Welcome {
        val json = decoded(outbox)
        fields(json, setOf("version", "request", "approvalSignature", "welcome", "probe"))
        val request = request(text(json, "request"), trustedAdmin, trustedDevice, null)
        signature(trustedAdmin, request.approval, text(json, "approvalSignature"))
        NativeEnrollment.decode(text(json, "welcome"), 128 * 1024)
        NativeEnrollment.decode(text(json, "probe"), 1024 * 1024)
        return Welcome(outbox, json, request)
    }
    fun invitationDraft(encoded: String, ownKey: String, now: Long): ByteArray {
        NativeEnrollment.validClock(now)
        val bytes = NativeEnrollment.decode(encoded, 4096)
        val lines = bytes.toString(Charsets.UTF_8).split('\n')
        if (lines.size != 8 || lines[0] != "squadtime-mls-invitation-v1" || lines[4] != ownKey ||
            lines[5] != now.toString() || now > 9_007_199_254_740_691L || lines[6] != (now + 300).toString() ||
            lines[7] != "" || !lines[3].matches(Regex("[0-9a-f]{64}"))) throw AdmissionRejected()
        if (NativeEnrollment.decode(lines[1], 32).size != 32) throw AdmissionRejected()
        NativeEnrollment.decode(lines[2], 256)
        if (!bytes.contentEquals(lines.joinToString("\n").toByteArray(Charsets.UTF_8))) throw AdmissionRejected()
        return bytes
    }
    fun requestDraft(encoded: String, invitation: Invitation, ownKey: String, trustedPin: String, now: Long): ByteArray {
        val bytes = NativeEnrollment.decode(encoded, 4096)
        val lines = bytes.toString(Charsets.UTF_8).split('\n')
        val expires = integer(invitation.json, "expiresAt")
        if (lines.size != 12 || lines[0] != "squadtime-mls-admission-request-v1" ||
            NativeEnrollment.decode(lines[1], 32).size != 32 || lines[2] != digest(invitation.encoded) ||
            lines[3] != text(invitation.json, "groupId") || !lines[4].matches(Regex("[0-9a-f]{64}")) ||
            !lines[5].matches(Regex("[0-9a-f]{64}")) || lines[6] != identity(invitation.json, "adminIdentity") ||
            lines[7] != ownKey || lines[8] != trustedPin || lines[9] != now.toString() ||
            lines[10] != expires.toString() || lines[11] != "") throw AdmissionRejected()
        if (!bytes.contentEquals(lines.joinToString("\n").toByteArray(Charsets.UTF_8))) throw AdmissionRejected()
        return bytes
    }
}
