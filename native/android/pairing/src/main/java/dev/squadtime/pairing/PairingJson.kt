package dev.squadtime.pairing

import org.json.JSONObject

/** Exact v1 schema; reject coercions, extra fields and non-integer JSON numbers. */
object PairingJson {
    private fun schema(json: JSONObject, fields: Set<String>) { require(json.keys().asSequence().toSet() == fields) }
    private fun string(json: JSONObject, key: String): String = json.get(key) as? String ?: error("Invalid field type")
    private fun integer(json: JSONObject, key: String): Long = when (val v = json.get(key)) {
        is Int -> v.toLong()
        is Long -> v
        else -> error("Invalid integer type")
    }
    private fun version(json: JSONObject): Int { require(integer(json, "version") == 1L); return 1 }
    fun request(json: JSONObject): PairingRequest {
        schema(json, setOf("version", "requestId", "deviceId", "challenge", "publicKey", "issuedAt", "expiresAt", "signature"))
        return PairingRequest(version(json), string(json, "requestId"), string(json, "deviceId"), string(json, "challenge"),
            string(json, "publicKey"), integer(json, "issuedAt"), integer(json, "expiresAt"), string(json, "signature"))
    }
    fun approval(json: JSONObject): PairingApproval {
        schema(json, setOf("version", "requestId", "requestDigest", "approverPublicKey", "signature"))
        return PairingApproval(version(json), string(json, "requestId"), string(json, "requestDigest"),
            string(json, "approverPublicKey"), string(json, "signature"))
    }
    fun encode(request: PairingRequest): JSONObject = JSONObject().apply {
        put("version", request.version); put("requestId", request.requestId); put("deviceId", request.deviceId)
        put("challenge", request.challenge); put("publicKey", request.publicKey); put("issuedAt", request.issuedAt)
        put("expiresAt", request.expiresAt); put("signature", request.signature)
    }
    fun encode(approval: PairingApproval): JSONObject = JSONObject().apply {
        put("version", approval.version); put("requestId", approval.requestId); put("requestDigest", approval.requestDigest)
        put("approverPublicKey", approval.approverPublicKey); put("signature", approval.signature)
    }
}
