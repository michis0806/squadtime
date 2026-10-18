package dev.squadtime.prototype

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import dev.squadtime.pairing.DurableAdmission
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The profile and admission pointer are authenticated and encrypted together. */
class ProfileStore(private val context: Context, private val scope: String = "main") {
    private val file = AtomicFile(File(context.noBackupFilesDir, "prototype-profile.bin"))
    private val alias = "dev.squadtime.prototype.profile.v1.$scope"
    init { require(scope.matches(Regex("[a-z0-9-]{1,64}"))) }
    private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun existingKey() = keys().getKey(alias, null) as? SecretKey ?: error("Local key unavailable")
    private fun createKey(): SecretKey {
        check(!keys().containsAlias(alias))
        return KeyGenerator.getInstance("AES", "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    @Synchronized fun read(): JSONObject? {
        if (!file.baseFile.exists()) {
            check(!keys().containsAlias(alias)) { "Incomplete local storage; reset required" }
            return null
        }
        val bytes = file.readFully()
        check(bytes.size in 29..65536)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        cipher.updateAAD("squadtime-prototype-profile-v1".toByteArray())
        val plaintext = cipher.doFinal(bytes.copyOfRange(12, bytes.size))
        return try { JSONObject(plaintext.toString(Charsets.UTF_8)) } finally { plaintext.fill(0) }
    }
    @Synchronized fun save(profile: JSONObject, initial: Boolean = false) {
        val key = if (initial) { check(!file.baseFile.exists()); createKey() } else existingKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD("squadtime-prototype-profile-v1".toByteArray())
        val plaintext = profile.toString().toByteArray()
        val sealed = try { cipher.iv + cipher.doFinal(plaintext) } finally { plaintext.fill(0) }
        val stream = file.startWrite()
        try { stream.write(sealed); file.finishWrite(stream) } catch (e: Exception) { file.failWrite(stream); throw e }
    }
    /** App-private directories contain only this prototype's synthetic records. */
    @Synchronized fun reset() {
        File(context.noBackupFilesDir, "independent-admission-proof").listFiles()?.filter { it.extension == "db" }?.forEach {
            runCatching { DurableAdmission.deleteSynthetic(context, it.nameWithoutExtension) }
        }
        File(context.noBackupFilesDir, "independent-admission-proof").deleteRecursively()
        // AndroidKeyStore is isolated by application UID: proof apps have separate stores.
        // Include an orphan created just before a database file could be committed.
        if (scope == "main") {
            val store = keys()
            store.aliases().toList().filter { it.startsWith("dev.squadtime.proof.admission.") }.forEach { store.deleteEntry(it) }
        }
        file.delete()
        keys().deleteEntry(alias)
    }
}
