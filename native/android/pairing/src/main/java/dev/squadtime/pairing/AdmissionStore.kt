package dev.squadtime.pairing

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AdmissionRejected : IllegalStateException("Durable admission operation rejected")

/** Secret role-specific state is local only. Never serialize this record outside encrypted storage. */
internal class AdmissionRecord(
    val role: String,
    val phase: String,
    val state: String,
    val outbox: String?,
    val trustedPin: String,
    val publicKey: String,
    val inbox: List<InboxMessage> = emptyList(),
    val inputDigest: String? = null,
    val acceptedInput: String? = null,
) {
    fun clear() { inbox.forEach { it.clear() } }
    fun next(phase: String, state: String, outbox: String?, inbox: List<InboxMessage> = this.inbox, inputDigest: String? = this.inputDigest, acceptedInput: String? = this.acceptedInput) =
        AdmissionRecord(role, phase, state, outbox, trustedPin, publicKey, inbox, inputDigest, acceptedInput)
}

/** One encrypted row commits phase, role-specific Rust state, exact public outbox and inbox together. */
internal class AdmissionStore private constructor(
    private val database: SQLiteDatabase,
    private val key: SecretKey,
    val id: String,
    private var revision: Long,
) : Closeable {
    companion object {
        private const val MAX_PAYLOAD = 1024 * 1024
        private const val MAX_STATE = 512 * 1024
        private const val MAX_OUTBOX = 128 * 1024
        private val creationLock = Any()
        private fun validId(id: String) { require(UUID.fromString(id).toString() == id) }
        fun signingAlias(id: String): String { validId(id); return "dev.squadtime.proof.admission.sign.$id" }
        fun encryptionAlias(id: String): String { validId(id); return "dev.squadtime.proof.admission.encrypt.$id" }
        fun file(context: Context, id: String): File {
            validId(id)
            return File(File(context.noBackupFilesDir, "independent-admission-proof"), "$id.db")
        }
        private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        private fun existingKey(id: String) = store().getKey(encryptionAlias(id), null) as? SecretKey ?: throw AdmissionRejected()
        private fun newKey(id: String): SecretKey {
            if (store().containsAlias(encryptionAlias(id))) throw AdmissionRejected()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(encryptionAlias(id), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).build())
            }.generateKey()
        }
        private fun connect(file: File): SQLiteDatabase {
            val db = SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY)
            try {
                check(db.enableWriteAheadLogging())
                db.rawQuery("PRAGMA journal_mode", null).use { check(it.moveToFirst() && it.getString(0) == "wal") }
                db.execSQL("PRAGMA synchronous=FULL")
                db.rawQuery("PRAGMA synchronous", null).use { check(it.moveToFirst() && it.getInt(0) == 2) }
                return db
            } catch (_: Exception) { db.close(); throw AdmissionRejected() }
        }
        fun create(context: Context, id: String, role: String, trustedPin: String? = null): AdmissionStore = synchronized(creationLock) {
            val path = file(context, id)
            if (role !in setOf("owner", "joiner") || path.exists() || store().containsAlias(signingAlias(id))) throw AdmissionRejected()
            if (role == "joiner" && trustedPin == null) throw AdmissionRejected()
            if (trustedPin != null) NativeEnrollment.publicBytes(NativeEnrollment.decode(trustedPin, 65).hex())
            path.parentFile?.mkdirs()
            val signer = DeviceSigningKey(signingAlias(id)).createOrLoad()
            val key = newKey(id)
            val db = connect(path)
            val instance = AdmissionStore(db, key, id, 0)
            try {
                val publicKey = NativeEnrollment.encode(NativeEnrollment.publicBytes(signer.publicKeyHex()))
                val resolvedPin = trustedPin ?: publicKey
                if (role == "owner" && resolvedPin != publicKey) throw AdmissionRejected()
                val initial = AdmissionRecord(role, "created", "", null, resolvedPin, publicKey)
                val sealed = instance.seal(initial, 0)
                db.beginTransaction()
                try {
                    db.execSQL("CREATE TABLE admission (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=0), nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)")
                    db.execSQL("INSERT INTO admission(singleton,revision,nonce,ciphertext) VALUES(1,0,?,?)", arrayOf(sealed.first, sealed.second))
                    db.setTransactionSuccessful()
                } finally { db.endTransaction() }
                instance
            } catch (_: Exception) { db.close(); throw AdmissionRejected() }
        }
        fun open(context: Context, id: String): AdmissionStore = synchronized(creationLock) {
            if (!file(context, id).isFile || !DeviceSigningKey(signingAlias(id)).exists()) throw AdmissionRejected()
            val key = try { existingKey(id) } catch (_: Exception) { throw AdmissionRejected() }
            val db = connect(file(context, id))
            try {
                val revision = db.rawQuery("SELECT revision FROM admission WHERE singleton=1", null).use {
                    if (!it.moveToFirst()) throw AdmissionRejected()
                    it.getLong(0)
                }
                val instance = AdmissionStore(db, key, id, revision)
                instance.current().clear()
                instance
            } catch (_: Exception) { db.close(); throw AdmissionRejected() }
        }
        fun deleteSynthetic(context: Context, id: String) = synchronized(creationLock) {
            SQLiteDatabase.deleteDatabase(file(context, id))
            store().deleteEntry(encryptionAlias(id))
            store().deleteEntry(signingAlias(id))
        }
    }
    private fun aad(revision: Long): ByteArray {
        if (revision < 0) throw AdmissionRejected()
        return "squadtime-independent-admission-store-v1\n$id\n$revision\n".toByteArray(Charsets.UTF_8)
    }
    private fun validate(record: AdmissionRecord) {
        if (record.inputDigest != null && !record.inputDigest.matches(Regex("[0-9a-f]{64}"))) throw AdmissionRejected()
        if (record.role !in setOf("owner", "joiner") || !record.phase.matches(Regex("[a-z][a-z0-9-]{0,31}")) || record.inbox.size > 128) throw AdmissionRejected()
        if (record.state.isEmpty()) { if (record.phase != "created") throw AdmissionRejected() }
        else { NativeEnrollment.decode(record.state, MAX_STATE).fill(0) }
        if (record.outbox != null) {
            if (record.outbox.toByteArray(Charsets.UTF_8).size > MAX_OUTBOX) throw AdmissionRejected()
            if (record.outbox.isNotEmpty()) NativeEnrollment.decode(record.outbox, MAX_OUTBOX).fill(0)
        }
        if (record.acceptedInput != null) {
            val bytes = NativeEnrollment.decode(record.acceptedInput, MAX_OUTBOX)
            if (NativeEnrollment.sha256(bytes) != record.inputDigest) throw AdmissionRejected()
        }
        NativeEnrollment.publicBytes(NativeEnrollment.decode(record.trustedPin, 65).hex())
        val signer = DeviceSigningKey(signingAlias(id))
        if (!signer.exists() || NativeEnrollment.encode(NativeEnrollment.publicBytes(signer.publicKeyHex())) != record.publicKey) throw AdmissionRejected()
    }
    private fun seal(record: AdmissionRecord, next: Long): Pair<ByteArray, ByteArray> {
        validate(record)
        val estimate = record.state.length.toLong() + (record.outbox?.length ?: 0) * 2L + (record.acceptedInput?.length ?: 0) * 2L + 2048L +
            record.inbox.sumOf { ((it.plaintext.size + 2L) / 3L) * 4L + 160L }
        if (estimate > MAX_PAYLOAD) throw AdmissionRejected()
        val json = JSONObject().put("role", record.role).put("phase", record.phase).put("state", record.state)
            .put("outbox", record.outbox ?: JSONObject.NULL).put("trustedPin", record.trustedPin).put("publicKey", record.publicKey)
            .put("inputDigest", record.inputDigest ?: JSONObject.NULL).put("acceptedInput", record.acceptedInput ?: JSONObject.NULL)
            .put("inbox", JSONArray().apply { record.inbox.forEach {
                put(JSONObject().put("id", it.id).put("plaintext", NativeEnrollment.encode(it.plaintext)).put("senderIndex", it.senderIndex))
            } })
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        try {
            if (bytes.size > MAX_PAYLOAD) throw AdmissionRejected()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key); cipher.updateAAD(aad(next))
            return cipher.iv to cipher.doFinal(bytes)
        } finally { bytes.fill(0) }
    }
    @Synchronized fun expectedRevision(): Long = revision
    @Synchronized fun current(): AdmissionRecord {
        try {
            database.rawQuery("SELECT revision,nonce,ciphertext FROM admission WHERE singleton=1", null).use { cursor ->
                if (!cursor.moveToFirst() || cursor.getLong(0) != revision || revision < 0) throw AdmissionRejected()
                val nonce = cursor.getBlob(1)
                val ciphertext = cursor.getBlob(2)
                if (nonce.size != 12 || ciphertext.size !in 16..MAX_PAYLOAD + 16) throw AdmissionRejected()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce)); cipher.updateAAD(aad(revision))
                val bytes = cipher.doFinal(ciphertext)
                val inbox = mutableListOf<InboxMessage>()
                try {
                    val json = JSONObject(bytes.toString(Charsets.UTF_8))
                    val entries = json.getJSONArray("inbox")
                    if (entries.length() > 128) throw AdmissionRejected()
                    for (index in 0 until entries.length()) {
                        val item = entries.getJSONObject(index)
                        val messageId = item.getString("id")
                        validId(messageId)
                        val sender = item.getLong("senderIndex")
                        if (sender !in 0..4_294_967_295L) throw AdmissionRejected()
                        inbox.add(InboxMessage(messageId, NativeEnrollment.decode(item.getString("plaintext"), MAX_PAYLOAD), sender))
                    }
                    val outbox = if (json.isNull("outbox")) null else json.getString("outbox")
                    return AdmissionRecord(json.getString("role"), json.getString("phase"), json.getString("state"), outbox,
                        json.getString("trustedPin"), json.getString("publicKey"), inbox,
                        if (json.isNull("inputDigest")) null else json.getString("inputDigest"),
                        if (json.isNull("acceptedInput")) null else json.getString("acceptedInput")).also { validate(it) }
                } catch (_: Exception) { inbox.forEach { it.clear() }; throw AdmissionRejected() }
                finally { bytes.fill(0) }
            }
        } catch (_: Exception) { throw AdmissionRejected() }
    }
    @Synchronized fun commit(expected: Long, next: AdmissionRecord, fault: VaultFault, testBeforeCas: (() -> Unit)? = null) {
        try {
            if (revision != expected || expected == Long.MAX_VALUE) throw AdmissionRejected()
            val sealed = seal(next, expected + 1)
            testBeforeCas?.invoke()
            if (revision != expected) throw AdmissionRejected()
            database.beginTransaction()
            try {
                val changed = database.compileStatement("UPDATE admission SET revision=?,nonce=?,ciphertext=? WHERE singleton=1 AND revision=?").use {
                    it.bindLong(1, expected + 1); it.bindBlob(2, sealed.first); it.bindBlob(3, sealed.second); it.bindLong(4, expected)
                    it.executeUpdateDelete()
                }
                if (changed != 1 || fault == VaultFault.BEFORE_COMMIT) throw AdmissionRejected()
                database.setTransactionSuccessful()
            } finally { database.endTransaction() }
            if (fault == VaultFault.AFTER_COMMIT_UNCERTAIN) throw AdmissionRejected()
            revision = expected + 1
        } catch (_: Exception) { throw AdmissionRejected() }
    }
    override fun close() { database.close() }
}
