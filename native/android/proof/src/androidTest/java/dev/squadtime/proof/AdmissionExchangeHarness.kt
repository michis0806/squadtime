package dev.squadtime.proof

import android.content.Context
import org.json.JSONObject
import dev.squadtime.pairing.*
import java.io.File
import java.util.UUID

/** Public-only transport harness; all secret role state stays inside the encrypted admission store. */
internal object AdmissionExchangeHarness {
    private const val PROBE = "{\"v\":1,\"eventId\":\"independent-admission-probe\",\"type\":\"availability.set\"}"
    private fun schema(json: JSONObject, fields: Set<String>) { check(json.keys().asSequence().toSet() == fields) }
    private fun text(json: JSONObject, field: String): String = json.get(field) as? String ?: error("Invalid public field")
    private fun now(json: JSONObject): Long = when (val value = json.get("now")) {
        is Int -> value.toLong()
        is Long -> value
        else -> error("Invalid public clock")
    }.also { check(it in 0..9_007_199_254_740_991L) }
    fun run(context: Context, phase: String?) {
        check(phase in setOf("ownerStart", "joinerStart", "ownerAdmit", "joinerFinish", "resume", "verifyInbox", "cleanup"))
        val directory = File(context.filesDir, "admission-exchange").apply { mkdirs() }
        val inputFile = File(directory, "input.json")
        check(inputFile.isFile && inputFile.length() <= 256 * 1024)
        val input = JSONObject(inputFile.readText())
        val marker = File(context.noBackupFilesDir, "independent-admission-public-marker.json")
        val creating = phase in setOf("ownerStart", "joinerStart") && !marker.exists()
        if (creating) {
            if (phase == "ownerStart") schema(input, setOf("now"))
            else schema(input, setOf("now", "outbox", "trustedAdminPublicKey"))
            val id = UUID.randomUUID().toString()
            val role = if (phase == "ownerStart") "owner" else "joiner"
            val created = if (role == "owner") DurableAdmission.createOwner(context, id)
                else DurableAdmission.createJoiner(context, id, text(input, "trustedAdminPublicKey"))
            created.close()
            marker.writeText(JSONObject().put("id", id).put("role", role).toString())
        }
        check(marker.isFile)
        val metadata = JSONObject(marker.readText())
        schema(metadata, setOf("id", "role"))
        val id = text(metadata, "id")
        check(UUID.fromString(id).toString() == id)
        val role = text(metadata, "role")
        val result = DurableAdmission.open(context, id).use { client ->
            when (phase) {
                "ownerStart" -> { schema(input, setOf("now")); check(role == "owner"); client.ownerStart(now(input)) }
                "joinerStart" -> {
                    schema(input, setOf("now", "outbox", "trustedAdminPublicKey")); check(role == "joiner")
                    check(text(input, "trustedAdminPublicKey") == client.trustedAdminPublicKey())
                    client.joinerStart(text(input, "outbox"), now(input))
                }
                "ownerAdmit" -> {
                    schema(input, setOf("now", "outbox", "trustedDevicePublicKey", "userConfirmed")); check(role == "owner")
                    check(input.get("userConfirmed") == true)
                    client.ownerAdmit(text(input, "outbox"), text(input, "trustedDevicePublicKey"), true, now(input))
                }
                "joinerFinish" -> {
                    schema(input, setOf("now", "outbox")); check(role == "joiner")
                    client.joinerFinish(text(input, "outbox"), now(input))
                }
                "resume" -> { schema(input, emptySet()); client.resume() }
                "verifyInbox" -> {
                    schema(input, emptySet()); check(role == "joiner")
                    val inbox = client.pending()
                    try {
                        check(inbox.size == 1 && inbox.single().plaintext.contentEquals(PROBE.toByteArray(Charsets.UTF_8)))
                        var replayRejected = false
                        try { client.receive(client.consumedProbeForProof()).clear() } catch (_: AdmissionRejected) { replayRejected = true }
                        check(replayRejected)
                        client.acknowledge(inbox.single().id)
                    } finally { inbox.forEach { it.clear() } }
                    DurableAdmission.open(context, id).use { check(it.pending().isEmpty()) }
                    AdmissionPublicResult("joined", "", client.nativePublicKey())
                }
                "cleanup" -> { schema(input, emptySet()); AdmissionPublicResult("cleanup", "", client.nativePublicKey()) }
                else -> error("Missing admission phase")
            }
        }
        if (phase == "cleanup") { DurableAdmission.deleteSynthetic(context, id); check(marker.delete()) }
        File(directory, "output.json").writeText(result.json().toString())
    }
}
