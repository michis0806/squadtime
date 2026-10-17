package dev.squadtime.pairing

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
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

/** Generic rejection deliberately excludes state, plaintext and provider diagnostics. */
class VaultRejected : IllegalStateException("Vault operation rejected")

/** Fault injection only; not proof of physical power-loss behavior. */
enum class VaultFault { NONE, BEFORE_COMMIT, AFTER_COMMIT_UNCERTAIN }

class InboxMessage(val id: String, val plaintext: ByteArray, val senderIndex: Long) {
    fun clear() { plaintext.fill(0) }
}

/** Proof vault: a single encrypted payload atomically binds MLS state and pending inbox. */
class MlsVault private constructor(
    private val database: SQLiteDatabase,
    private val key: SecretKey,
    private val vaultId: String,
    private var revision: Long,
) : Closeable {
    companion object {
        private const val MAX_PAYLOAD = 1024 * 1024
        private const val MAX_SNAPSHOT = 700 * 1024
        private const val MAX_INBOX = 128
        private val createLock = Any()
        private fun validId(id: String) { require(UUID.fromString(id).toString() == id) }
        fun keyAlias(vaultId: String): String { validId(vaultId); return "dev.squadtime.proof.vault.$vaultId" }
        fun databaseFile(context: Context, vaultId: String): File {
            validId(vaultId)
            return File(File(context.noBackupFilesDir, "mls-vault-proof"), "$vaultId.db")
        }
        private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        private fun existingKey(id: String): SecretKey = store().getKey(keyAlias(id), null) as? SecretKey ?: throw VaultRejected()
        private fun createKey(id: String): SecretKey {
            if (store().containsAlias(keyAlias(id))) return existingKey(id)
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(keyAlias(id), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).build())
            }.generateKey()
        }
        private fun connect(path: File): SQLiteDatabase {
            val db = SQLiteDatabase.openDatabase(path.path, null, SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY)
            try {
                check(db.enableWriteAheadLogging())
                db.rawQuery("PRAGMA journal_mode", null).use { check(it.moveToFirst() && it.getString(0) == "wal") }
                db.execSQL("PRAGMA synchronous=FULL")
                db.rawQuery("PRAGMA synchronous", null).use { check(it.moveToFirst() && it.getInt(0) == 2) }
                return db
            } catch (_: Exception) { db.close(); throw VaultRejected() }
        }
        fun create(context: Context, vaultId: String, snapshot: ByteArray): MlsVault = synchronized(createLock) {
            val path = databaseFile(context, vaultId)
            if (path.exists() || snapshot.isEmpty() || snapshot.size > MAX_SNAPSHOT) throw VaultRejected()
            path.parentFile?.mkdirs()
            val key = createKey(vaultId)
            val db = connect(path)
            val vault = MlsVault(db, key, vaultId, 0)
            try {
                db.beginTransaction()
                try {
                    db.execSQL("CREATE TABLE vault (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=0), nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)")
                    val payload = Payload(snapshot.copyOf(), mutableListOf())
                    val sealed = try { vault.seal(payload, 0) } finally { payload.clear() }
                    db.execSQL("INSERT INTO vault(singleton,revision,nonce,ciphertext) VALUES(1,0,?,?)", arrayOf(sealed.first, sealed.second))
                    db.setTransactionSuccessful()
                } finally { db.endTransaction() }
                vault
            } catch (_: Exception) { db.close(); throw VaultRejected() }
        }
        fun open(context: Context, vaultId: String): MlsVault = synchronized(createLock) {
            val path = databaseFile(context, vaultId)
            if (!path.isFile) throw VaultRejected()
            val key = try { existingKey(vaultId) } catch (_: Exception) { throw VaultRejected() }
            val db = connect(path)
            try {
                val revision = db.rawQuery("SELECT revision FROM vault WHERE singleton=1", null).use {
                    if (!it.moveToFirst()) throw VaultRejected()
                    it.getLong(0)
                }
                val vault = MlsVault(db, key, vaultId, revision)
                vault.load().clear()
                vault
            } catch (_: Exception) { db.close(); throw VaultRejected() }
        }
        /** Test cleanup only; removal is not secure erasure on flash storage. */
        fun deleteSynthetic(context: Context, vaultId: String) = synchronized(createLock) {
            SQLiteDatabase.deleteDatabase(databaseFile(context, vaultId))
            store().deleteEntry(keyAlias(vaultId))
        }
    }

    private class Payload(val snapshot: ByteArray, val inbox: MutableList<InboxMessage>) {
        fun clear() { snapshot.fill(0); inbox.forEach { it.clear() } }
    }
    private fun aad(value: Long): ByteArray {
        if (value < 0) throw VaultRejected()
        return "squadtime-mls-vault-v1\n$vaultId\n$value\n".toByteArray(Charsets.UTF_8)
    }
    private fun encode(value: ByteArray): String = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String, maximum: Int): ByteArray {
        if (value.length > ((maximum + 2L) / 3L) * 4L) throw VaultRejected()
        return Base64.decode(value, Base64.NO_WRAP).also { if (it.size > maximum) { it.fill(0); throw VaultRejected() } }
    }
    private fun seal(payload: Payload, next: Long): Pair<ByteArray, ByteArray> {
        if (payload.snapshot.isEmpty() || payload.snapshot.size > MAX_SNAPSHOT) throw VaultRejected()
        val estimatedBytes = ((payload.snapshot.size + 2L) / 3L) * 4L + 128L +
            payload.inbox.sumOf { ((it.plaintext.size + 2L) / 3L) * 4L + 160L }
        if (payload.inbox.size > MAX_INBOX || estimatedBytes > MAX_PAYLOAD) throw VaultRejected()
        val json = JSONObject().put("snapshot", encode(payload.snapshot)).put("inbox", JSONArray().apply {
            payload.inbox.forEach { put(JSONObject().put("id", it.id).put("plaintext", encode(it.plaintext)).put("senderIndex", it.senderIndex)) }
        })
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        try {
            if (bytes.size > MAX_PAYLOAD || payload.inbox.size > MAX_INBOX) throw VaultRejected()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad(next))
            return cipher.iv to cipher.doFinal(bytes)
        } finally { bytes.fill(0) }
    }
    private fun load(): Payload {
        database.rawQuery("SELECT revision,nonce,ciphertext FROM vault WHERE singleton=1", null).use { cursor ->
            if (!cursor.moveToFirst() || cursor.getLong(0) != revision || revision < 0) throw VaultRejected()
            val nonce = cursor.getBlob(1)
            val ciphertext = cursor.getBlob(2)
            if (nonce.size != 12 || ciphertext.size !in 16..MAX_PAYLOAD + 16) throw VaultRejected()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad(revision))
            val bytes = cipher.doFinal(ciphertext)
            try {
                val json = JSONObject(bytes.toString(Charsets.UTF_8))
                val entries = json.getJSONArray("inbox")
                if (entries.length() > MAX_INBOX) throw VaultRejected()
                val inbox = mutableListOf<InboxMessage>()
                var snapshot: ByteArray? = null
                try {
                    snapshot = decode(json.getString("snapshot"), MAX_SNAPSHOT)
                    for (index in 0 until entries.length()) {
                        val item = entries.getJSONObject(index)
                        val id = item.getString("id")
                        validId(id)
                        val sender = item.getLong("senderIndex")
                        if (sender !in 0..4_294_967_295L) throw VaultRejected()
                        inbox.add(InboxMessage(id, decode(item.getString("plaintext"), 1024 * 1024), sender))
                    }
                    return Payload(snapshot, inbox)
                } catch (_: Exception) { snapshot?.fill(0); inbox.forEach { it.clear() }; throw VaultRejected() }
            } finally { bytes.fill(0) }
        }
    }
    private fun save(payload: Payload, fault: VaultFault, expectedRevision: Long) {
        if (revision != expectedRevision || expectedRevision == Long.MAX_VALUE) throw VaultRejected()
        val next = expectedRevision + 1
        val sealed = seal(payload, next)
        database.beginTransaction()
        try {
            val statement = database.compileStatement("UPDATE vault SET revision=?,nonce=?,ciphertext=? WHERE singleton=1 AND revision=?")
            val affected = statement.use {
                it.bindLong(1, next); it.bindBlob(2, sealed.first); it.bindBlob(3, sealed.second); it.bindLong(4, expectedRevision)
                it.executeUpdateDelete()
            }
            if (affected != 1 || fault == VaultFault.BEFORE_COMMIT) throw VaultRejected()
            database.setTransactionSuccessful()
        } finally { database.endTransaction() }
        if (fault == VaultFault.AFTER_COMMIT_UNCERTAIN) throw VaultRejected()
        revision = next
    }
    @Synchronized
    fun receive(
        packet: ByteArray,
        fault: VaultFault = VaultFault.NONE,
        testBeforeCas: (() -> Unit)? = null,
    ): InboxMessage {
        val expectedRevision = revision
        var payload: Payload? = null
        var processed: MlsReceive? = null
        try {
            payload = load()
            if (payload.inbox.size >= MAX_INBOX) throw VaultRejected()
            processed = NativeMls.receive(payload.snapshot, packet)
            val message = InboxMessage(UUID.randomUUID().toString(), processed.plaintext, processed.senderIndex)
            val next = Payload(processed.snapshot, payload.inbox.toMutableList().apply { add(message) })
            testBeforeCas?.invoke()
            save(next, fault, expectedRevision)
            return InboxMessage(message.id, message.plaintext.copyOf(), message.senderIndex)
        } catch (_: Exception) { throw VaultRejected() }
        finally { payload?.clear(); processed?.snapshot?.fill(0); processed?.plaintext?.fill(0) }
    }
    @Synchronized
    fun pending(): List<InboxMessage> = try {
        val payload = load()
        try { payload.inbox.map { InboxMessage(it.id, it.plaintext.copyOf(), it.senderIndex) } }
        finally { payload.clear() }
    } catch (_: Exception) { throw VaultRejected() }
    @Synchronized
    fun acknowledge(messageId: String, fault: VaultFault = VaultFault.NONE) {
        val expectedRevision = revision
        var payload: Payload? = null
        try {
            payload = load()
            val index = payload.inbox.indexOfFirst { it.id == messageId }
            if (index < 0) throw VaultRejected()
            payload.inbox.removeAt(index).clear()
            save(payload, fault, expectedRevision)
        } catch (_: Exception) { throw VaultRejected() }
        finally { payload?.clear() }
    }
    override fun close() { database.close() }
}
