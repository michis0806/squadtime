package dev.squadtime.prototype

import android.util.Base64
import dev.squadtime.pairing.DeviceSigningKey
import dev.squadtime.pairing.DurableAdmission
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

object PrototypeProtocol {
    const val PREFIX = "squadtime-prototype-v1:"
    fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    fun decode(value: String): ByteArray {
        val result = Base64.decode(value, Base64.NO_WRAP)
        require(encode(result) == value)
        return result
    }
    fun hash(value: String) = digest(decode(value))
    fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    fun validLabel(value: String): Boolean = value.isNotBlank() && value.codePointCount(0, value.length) <= 32 && value.none { Character.isISOControl(it) }
    fun origin(value: String): String {
        val uri = URI(value)
        require(uri.scheme == "http" && uri.rawUserInfo == null && uri.rawPath.isNullOrEmpty() && uri.rawQuery == null && uri.rawFragment == null)
        val host = uri.host ?: error("Missing host")
        val components = host.split('.')
        require(components.size == 4 && components.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() in 0..255 })
        val ip = components.map { it.toInt() }
        require(ip[0] == 10 || ip[0] == 172 && ip[1] in 16..31 || ip[0] == 192 && ip[1] == 168)
        require(uri.port == -1 || uri.port in 1024..65535)
        require(value == "http://$host" + if (uri.port == -1) "" else ":${uri.port}")
        return value
    }
    fun objectFields(json: JSONObject, fields: Set<String>) { require(json.keys().asSequence().toSet() == fields) }
    private fun utf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    fun key(value: String): java.security.PublicKey {
        val raw = decode(value)
        require(raw.size == 65 && raw[0] == 4.toByte())
        val prefix = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x02,0x01,0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0x00)
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(prefix + raw))
    }
    fun qr(json: JSONObject): String = PREFIX + Base64.encodeToString(json.toString().toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    fun parseQr(text: String, now: Long = System.currentTimeMillis() / 1000): JSONObject {
        require(text.toByteArray().size <= 2048 && text.startsWith(PREFIX))
        val encoded = text.removePrefix(PREFIX)
        val raw = Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        require(Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) == encoded)
        val json = JSONObject(utf8(raw))
        objectFields(json, setOf("v","type","relay","session","key","hash","expiresAt","label"))
        require(json.get("v") == 1 && json.getString("type") in setOf("invite", "request"))
        for (field in listOf("type","relay","session","key","hash","label")) require(json.get(field) is String)
        require(json.get("expiresAt") is Long || json.get("expiresAt") is Int)
        origin(json.getString("relay")); key(json.getString("key"))
        require(json.getString("session").matches(Regex("[0-9a-f]{64}")) && json.getString("hash").matches(Regex("[0-9a-f]{64}")))
        require(json.getLong("expiresAt") in (now + 1)..(now + 300) && validLabel(json.getString("label")))
        return json
    }
    fun exchange(origin: String, session: String, kind: String, outbox: String? = null): String? {
        origin(origin)
        require(session.matches(Regex("[0-9a-f]{64}")) && kind in setOf("invitation","request","welcome","receipt"))
        val connection = URI("$origin/v1/sessions/$session/$kind").toURL().openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 5000; connection.readTimeout = 5000
        try {
            if (outbox != null) {
                require(outbox.length <= 192 * 1024); decode(outbox)
                connection.requestMethod = "PUT"; connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(JSONObject().put("outbox", outbox).toString().toByteArray()) }
            }
            val status = connection.responseCode
            if (outbox == null && status == 404) return null
            require(status in 200..201) { "Relay unavailable or conflicting exchange" }
            if (outbox != null) return outbox
            val bytes = connection.inputStream.use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= 192 * 1024)
                    output.write(buffer,0,count)
                }
                output.toByteArray()
            }
            val json = JSONObject(bytes.toString(Charsets.UTF_8)); objectFields(json, setOf("outbox"))
            return json.getString("outbox").also { decode(it) }
        } finally { connection.disconnect() }
    }
    private fun receiptTranscript(profile: JSONObject): ByteArray =
        "squadtime-prototype-receipt-v1\n${profile.getString("session")}\n${profile.getString("invitationHash")}\n${profile.getString("requestHash")}\n${profile.getString("welcomeHash")}\n".toByteArray()
    fun createReceipt(profile: JSONObject): String {
        val signatureHex = DeviceSigningKey(DurableAdmission.signingAliasForProof(profile.getString("id"))).sign(receiptTranscript(profile))
        return encode(JSONObject().put("v",1).put("session",profile.getString("session"))
            .put("invitationHash",profile.getString("invitationHash")).put("requestHash",profile.getString("requestHash"))
            .put("welcomeHash",profile.getString("welcomeHash"))
            .put("signature", encode(signatureHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())).toString().toByteArray())
    }
    fun verifyReceipt(profile: JSONObject, outbox: String) {
        val receipt = JSONObject(utf8(decode(outbox)))
        objectFields(receipt, setOf("v","session","invitationHash","requestHash","welcomeHash","signature"))
        require(receipt.get("v") == 1)
        for (field in listOf("session","invitationHash","requestHash","welcomeHash")) require(receipt.get(field) is String && receipt.getString(field) == profile.getString(field))
        require(receipt.get("signature") is String)
        val signature = decode(receipt.getString("signature"))
        require(signature.size in 8..72 && signature[0] == 0x30.toByte() && signature[1].toInt() == signature.size - 2)
        var offset = 2
        repeat(2) {
            require(offset + 2 <= signature.size && signature[offset++] == 2.toByte())
            val length = signature[offset++].toInt()
            require(length in 1..33 && offset + length <= signature.size && signature[offset].toInt() and 128 == 0)
            require(length == 1 || signature[offset] != 0.toByte() || signature[offset + 1].toInt() and 128 != 0)
            val scalar = java.math.BigInteger(1,signature.copyOfRange(offset,offset + length))
            require(scalar > java.math.BigInteger.ZERO && scalar < java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16))
            offset += length
        }
        require(offset == signature.size)
        require(Signature.getInstance("SHA256withECDSA").run { initVerify(key(profile.getString("peerKey"))); update(receiptTranscript(profile)); verify(signature) })
    }
}
