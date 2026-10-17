package dev.squadtime.proof

import android.database.sqlite.SQLiteDatabase
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.squadtime.pairing.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator

@RunWith(AndroidJUnit4::class)
class MlsVaultProofTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun id() = UUID.randomUUID().toString()
    private fun reject(action: () -> Unit) { assertThrows(VaultRejected::class.java) { action() } }
    private fun mutate(vaultId: String, action: (SQLiteDatabase) -> Unit) {
        SQLiteDatabase.openDatabase(MlsVault.databaseFile(context, vaultId).path, null, SQLiteDatabase.OPEN_READWRITE).use(action)
    }
    private fun assertPending(vault: MlsVault, expected: List<ByteArray>) {
        val messages = vault.pending()
        try {
            assertEquals(expected.size, messages.size)
            messages.forEachIndexed { index, item -> assertTrue(item.plaintext.contentEquals(expected[index])) }
        } finally { messages.forEach { it.clear() } }
    }

    @Test fun actualRustMlsReceiveSurvivesReopenAndAck() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).use { assertPending(it, emptyList()) }
            MlsVault.open(context, vaultId).use { vault ->
                val tampered = fixture.packets[0].copyOf()
                tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
                try { reject { vault.receive(tampered) } } finally { tampered.fill(0) }
                assertPending(vault, emptyList())
                val first = vault.receive(fixture.packets[0])
                try { assertTrue(first.plaintext.contentEquals(fixture.expected[0])); assertTrue(first.senderIndex >= 0) }
                finally { first.clear() }
                reject { vault.receive(fixture.packets[0]) }
            }
            MlsVault.open(context, vaultId).use { vault ->
                assertPending(vault, listOf(fixture.expected[0]))
                reject { vault.receive(fixture.packets[0]) }
                val second = vault.receive(fixture.packets[1])
                try { assertTrue(second.plaintext.contentEquals(fixture.expected[1])) } finally { second.clear() }
                assertPending(vault, fixture.expected)
                val pending = vault.pending()
                try {
                    vault.acknowledge(pending[0].id)
                    reject { vault.acknowledge(pending[0].id) }
                } finally { pending.forEach { it.clear() } }
            }
            MlsVault.open(context, vaultId).use { vault ->
                assertPending(vault, listOf(fixture.expected[1]))
                val pending = vault.pending()
                try { vault.acknowledge(pending.single().id) } finally { pending.forEach { it.clear() } }
            }
            MlsVault.open(context, vaultId).use { vault ->
                assertPending(vault, emptyList())
                reject { vault.receive(fixture.packets[0]) }
                reject { vault.receive(fixture.packets[1]) }
            }
            assertTrue(MlsVault.databaseFile(context, vaultId).canonicalPath.startsWith(context.noBackupFilesDir.canonicalPath + "/"))
            mutate(vaultId) { db ->
                db.rawQuery("SELECT nonce,ciphertext FROM vault", null).use {
                    assertTrue(it.moveToFirst()); assertEquals(12, it.getBlob(0).size)
                    assertFalse(it.getBlob(1).contentEquals(fixture.snapshot))
                }
            }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun preCommitFailureRollsBackAndAuthenticRetrySucceeds() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).use { vault ->
                reject { vault.receive(fixture.packets[0], VaultFault.BEFORE_COMMIT) }
                assertPending(vault, emptyList())
            }
            MlsVault.open(context, vaultId).use { vault ->
                val received = vault.receive(fixture.packets[0])
                received.clear()
                assertPending(vault, listOf(fixture.expected[0]))
                val pending = vault.pending()
                try {
                    reject { vault.acknowledge(pending.single().id, VaultFault.BEFORE_COMMIT) }
                    assertPending(vault, listOf(fixture.expected[0]))
                } finally { pending.forEach { it.clear() } }
            }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun uncertainCommitReturnsNoPlaintextAndReopenRecoversInbox() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).use { vault ->
                var returned = false
                reject { vault.receive(fixture.packets[0], VaultFault.AFTER_COMMIT_UNCERTAIN); returned = true }
                assertFalse(returned)
                reject { vault.pending() }
            }
            MlsVault.open(context, vaultId).use { vault ->
                assertPending(vault, listOf(fixture.expected[0]))
                reject { vault.receive(fixture.packets[0]) }
                val pending = vault.pending()
                try { reject { vault.acknowledge(pending.single().id, VaultFault.AFTER_COMMIT_UNCERTAIN) } }
                finally { pending.forEach { it.clear() } }
            }
            MlsVault.open(context, vaultId).use { assertPending(it, emptyList()) }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun independentConnectionsRejectStaleWriter() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).use { first ->
                MlsVault.open(context, vaultId).use { stale ->
                    reject {
                        stale.receive(fixture.packets[0], testBeforeCas = {
                            first.receive(fixture.packets[0]).clear()
                        })
                    }
                    reject { stale.receive(fixture.packets[1]) }
                    reject { stale.pending() }
                }
            }
            MlsVault.open(context, vaultId).use { fresh ->
                assertPending(fresh, listOf(fixture.expected[0]))
                fresh.receive(fixture.packets[1]).clear()
                assertPending(fresh, fixture.expected)
            }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun reentrantReceiveCannotOverwriteInnerCommittedStateOrInbox() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).use { vault ->
                reject {
                    vault.receive(fixture.packets[0], testBeforeCas = {
                        vault.receive(fixture.packets[0]).clear()
                    })
                }
                assertPending(vault, listOf(fixture.expected[0]))
                reject { vault.receive(fixture.packets[0]) }
                vault.receive(fixture.packets[1]).clear()
                assertPending(vault, fixture.expected)
            }
            MlsVault.open(context, vaultId).use { vault ->
                assertPending(vault, fixture.expected)
                fixture.packets.forEach { packet -> reject { vault.receive(packet) } }
            }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun oversizedInitialStateRejectsWithoutDatabaseOrKeyCreation() {
        val vaultId = id()
        val oversized = ByteArray(700 * 1024 + 1)
        try {
            reject { MlsVault.create(context, vaultId, oversized) }
            assertFalse(MlsVault.databaseFile(context, vaultId).exists())
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            assertFalse(store.containsAlias(MlsVault.keyAlias(vaultId)))
        } finally { oversized.fill(0); MlsVault.deleteSynthetic(context, vaultId) }
    }

    @Test fun missingKeyNeverRegeneratesAndWrongKeyRejects() {
        val fixture = NativeMls.fixture()
        val vaultId = id()
        val alias = MlsVault.keyAlias(vaultId)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).close()
            assertNull(store.getKey(alias, null).encoded)
            store.deleteEntry(alias)
            reject { MlsVault.open(context, vaultId) }
            assertFalse(store.containsAlias(alias))
            reject { MlsVault.create(context, vaultId, fixture.snapshot) }
            assertFalse(store.containsAlias(alias))
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
            }.generateKey()
            reject { MlsVault.open(context, vaultId) }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear() }
    }

    @Test fun modifiedCiphertextRevisionAndNonceReject() {
        val fixture = NativeMls.fixture()
        val vaultIds = List(3) { id() }
        try {
            vaultIds.forEach { MlsVault.create(context, it, fixture.snapshot).close() }
            mutate(vaultIds[0]) { db ->
                val ciphertext = db.rawQuery("SELECT ciphertext FROM vault", null).use { it.moveToFirst(); it.getBlob(0) }
                ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()
                db.execSQL("UPDATE vault SET ciphertext=?", arrayOf(ciphertext))
            }
            reject { MlsVault.open(context, vaultIds[0]) }
            mutate(vaultIds[1]) { it.execSQL("UPDATE vault SET revision=revision+1") }
            reject { MlsVault.open(context, vaultIds[1]) }
            mutate(vaultIds[2]) { db ->
                val nonce = db.rawQuery("SELECT nonce FROM vault", null).use { it.moveToFirst(); it.getBlob(0) }
                nonce[0] = (nonce[0].toInt() xor 1).toByte()
                db.execSQL("UPDATE vault SET nonce=?", arrayOf(nonce))
            }
            reject { MlsVault.open(context, vaultIds[2]) }
        } finally { vaultIds.forEach { MlsVault.deleteSynthetic(context, it) }; fixture.clear() }
    }
}
