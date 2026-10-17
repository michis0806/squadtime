package dev.squadtime.proof

import android.app.Activity
import android.os.Bundle
import androidx.test.runner.AndroidJUnitRunner
import android.util.Base64
import dev.squadtime.pairing.*
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Explicit phases fail when absent; only public ciphertext and digests form the marker. */
class VaultRestartInstrumentation : AndroidJUnitRunner() {
    private var phase: String? = null
    private var restartRequested = false
    private var admissionRequested = false
    override fun onCreate(arguments: Bundle?) {
        restartRequested = arguments?.getString("restartProof") == "true"
        admissionRequested = arguments?.getString("admissionProof") == "true"
        phase = arguments?.getString("phase")
        super.onCreate(arguments)
    }
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    override fun onStart() {
        if (admissionRequested) {
            var success = false
            try { AdmissionExchangeHarness.run(targetContext, phase); success = true }
            catch (_: Exception) { /* Return no state or provider diagnostic. */ }
            finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
                putString("admissionProof", if (success) "passed" else "rejected")
                putInt("processId", android.os.Process.myPid())
            })
            return
        }
        if (!restartRequested) { super.onStart(); return }
        val marker = File(targetContext.noBackupFilesDir, "mls-vault-restart-public-marker.json")
        var success = false
        try {
            when (phase) {
                "prepare" -> {
                    check(!marker.exists())
                    val fixture = NativeMls.fixture()
                    val id = UUID.randomUUID().toString()
                    try {
                        MlsVault.create(targetContext, id, fixture.snapshot).use { vault ->
                            vault.receive(fixture.packets[0]).clear()
                        }
                        marker.writeText(JSONObject().put("vaultId", id)
                            .put("packet", Base64.encodeToString(fixture.packets[0], Base64.NO_WRAP))
                            .put("plaintextDigest", digest(fixture.expected[0])).toString())
                    } catch (_: Exception) { MlsVault.deleteSynthetic(targetContext, id); throw IllegalStateException() }
                    finally { fixture.clear() }
                }
                "verify" -> {
                    check(marker.isFile)
                    val json = JSONObject(marker.readText())
                    val id = json.getString("vaultId")
                    val packet = Base64.decode(json.getString("packet"), Base64.NO_WRAP)
                    try {
                        MlsVault.open(targetContext, id).use { vault ->
                            val pending = vault.pending()
                            try {
                                check(pending.size == 1)
                                check(digest(pending.single().plaintext) == json.getString("plaintextDigest"))
                                var rejected = false
                                try { vault.receive(packet).clear() } catch (_: VaultRejected) { rejected = true }
                                check(rejected)
                                vault.acknowledge(pending.single().id)
                            } finally { pending.forEach { it.clear() } }
                        }
                        MlsVault.open(targetContext, id).use { check(it.pending().isEmpty()) }
                    } finally {
                        packet.fill(0)
                        MlsVault.deleteSynthetic(targetContext, id)
                        marker.delete()
                    }
                }
                else -> error("Missing restart proof phase")
            }
            success = true
        } catch (_: Exception) { /* Return only a generic result; never expose state. */ }
        finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED,
            Bundle().apply {
                putString("restartProof", if (success) "passed" else "rejected")
                putInt("processId", android.os.Process.myPid())
            })
    }
}
