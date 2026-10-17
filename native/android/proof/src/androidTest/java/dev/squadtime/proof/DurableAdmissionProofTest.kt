package dev.squadtime.proof

import android.database.sqlite.SQLiteDatabase
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.squadtime.pairing.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class DurableAdmissionProofTest {
    private val now = 1_700_000_001L
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val probe = "{\"v\":1,\"eventId\":\"independent-admission-probe\",\"type\":\"availability.set\"}".toByteArray(Charsets.UTF_8)
    private fun id() = UUID.randomUUID().toString()
    private fun reject(action: () -> Unit) { assertThrows(AdmissionRejected::class.java) { action() } }
    private fun envelope(value: String) = JSONObject(Base64.decode(value, Base64.NO_WRAP).toString(Charsets.UTF_8))
    private fun encode(json: JSONObject) = Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    private fun assertInbox(client: DurableAdmission, count: Int) {
        val inbox = client.pending()
        try { assertEquals(count, inbox.size); inbox.forEach { assertTrue(it.plaintext.contentEquals(probe)) } }
        finally { inbox.forEach { it.clear() } }
    }
    private class Peers(val ownerId: String, val joinerId: String, val ownerKey: String, val joinerKey: String,
                        val invitation: String, val request: String)
    private fun peers(): Peers {
        val ownerId = id()
        val joinerId = id()
        try {
            val invite = DurableAdmission.createOwner(context, ownerId).use { it.ownerStart(now) }
            val request = DurableAdmission.createJoiner(context, joinerId, invite.nativePublicKey).use { it.joinerStart(invite.outbox, now) }
            return Peers(ownerId, joinerId, invite.nativePublicKey, request.nativePublicKey, invite.outbox, request.outbox)
        } catch (failure: Throwable) {
            DurableAdmission.deleteSynthetic(context, ownerId); DurableAdmission.deleteSynthetic(context, joinerId)
            throw failure
        }
    }
    private fun cleanup(peers: Peers) {
        DurableAdmission.deleteSynthetic(context, peers.ownerId); DurableAdmission.deleteSynthetic(context, peers.joinerId)
    }

    @Test fun independentRoleStoresResumeExactOutboxesAndAtomicJoinedInbox() {
        val peers = peers()
        try {
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                assertEquals(peers.invitation, owner.resume().outbox)
                assertEquals(peers.invitation, owner.ownerStart(now).outbox)
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                assertEquals(peers.request, joiner.resume().outbox)
                assertEquals(peers.request, joiner.joinerStart(peers.invitation, now).outbox)
            }
            val welcome = DurableAdmission.open(context, peers.ownerId).use { it.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox }
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                assertEquals(welcome, owner.resume().outbox)
                assertEquals(welcome, owner.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox)
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                assertEquals("joined", joiner.joinerFinish(welcome, now + 301).kind)
                assertInbox(joiner, 1)
                assertEquals("", joiner.resume().outbox)
                assertEquals("joined", joiner.joinerFinish(welcome, now + 302).kind)
                assertInbox(joiner, 1)
                reject { joiner.receive(joiner.consumedProbeForProof()) }
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                assertInbox(joiner, 1)
                val inbox = joiner.pending()
                try { joiner.acknowledge(inbox.single().id) } finally { inbox.forEach { it.clear() } }
            }
            DurableAdmission.open(context, peers.joinerId).use { assertInbox(it, 0); assertEquals("joined", it.resume().kind) }
            assertTrue(DurableAdmission.databaseFileForProof(context, peers.joinerId).canonicalPath.startsWith(context.noBackupFilesDir.canonicalPath + "/"))
        } finally { cleanup(peers) }
    }

    @Test fun preCommitFailureExposesNoNewOutboxAndAuthenticRetrySucceeds() {
        val ownerId = id()
        val joinerId = id()
        try {
            DurableAdmission.createOwner(context, ownerId).use { owner ->
                reject { owner.ownerStart(now, VaultFault.BEFORE_COMMIT) }
                reject { owner.resume() }
            }
            val invitation = DurableAdmission.open(context, ownerId).use { it.ownerStart(now) }
            val request = DurableAdmission.createJoiner(context, joinerId, invitation.nativePublicKey).use { joiner ->
                reject { joiner.joinerStart(invitation.outbox, now, VaultFault.BEFORE_COMMIT) }
                reject { joiner.resume() }
                joiner.joinerStart(invitation.outbox, now)
            }
            val welcome = DurableAdmission.open(context, ownerId).use { owner ->
                reject { owner.ownerAdmit(request.outbox, request.nativePublicKey, true, now, VaultFault.BEFORE_COMMIT) }
                assertEquals(invitation.outbox, owner.resume().outbox)
                owner.ownerAdmit(request.outbox, request.nativePublicKey, true, now)
            }
            DurableAdmission.open(context, joinerId).use { joiner ->
                reject { joiner.joinerFinish(welcome.outbox, now, VaultFault.BEFORE_COMMIT) }
                assertEquals(request.outbox, joiner.resume().outbox)
                assertInbox(joiner, 0)
            }
            DurableAdmission.open(context, joinerId).use { joiner -> joiner.joinerFinish(welcome.outbox, now); assertInbox(joiner, 1) }
        } finally { DurableAdmission.deleteSynthetic(context, ownerId); DurableAdmission.deleteSynthetic(context, joinerId) }
    }

    @Test fun uncertainCommitsRequireReopenAndRecoverExactOutboxAndInbox() {
        val peers = peers()
        try {
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                var released = false
                reject { owner.ownerAdmit(peers.request, peers.joinerKey, true, now, VaultFault.AFTER_COMMIT_UNCERTAIN); released = true }
                assertFalse(released)
                reject { owner.resume() }
            }
            val welcome = DurableAdmission.open(context, peers.ownerId).use { owner ->
                val resumed = owner.resume()
                assertEquals("welcome", resumed.kind)
                assertEquals(resumed.outbox, owner.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox)
                resumed
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                var released = false
                reject { joiner.joinerFinish(welcome.outbox, now, VaultFault.AFTER_COMMIT_UNCERTAIN); released = true }
                assertFalse(released)
                reject { joiner.pending() }
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                assertEquals("joined", joiner.resume().kind)
                assertInbox(joiner, 1)
                assertEquals("joined", joiner.joinerFinish(welcome.outbox, now).kind)
                assertInbox(joiner, 1)
            }
        } finally { cleanup(peers) }
    }

    @Test fun independentConnectionCasCannotOverwriteCommittedWelcome() {
        val peers = peers()
        try {
            var committed = ""
            DurableAdmission.open(context, peers.ownerId).use { outer ->
                DurableAdmission.open(context, peers.ownerId).use { inner ->
                    reject { outer.ownerAdmit(peers.request, peers.joinerKey, true, now, testBeforeCas = {
                        committed = inner.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox
                    }) }
                    reject { outer.resume() }
                }
            }
            DurableAdmission.open(context, peers.ownerId).use { assertEquals(committed, it.resume().outbox) }
            DurableAdmission.open(context, peers.joinerId).use { it.joinerFinish(committed, now); assertInbox(it, 1) }
        } finally { cleanup(peers) }
    }

    @Test fun reentrantCasRetainsInnerWelcomeAndConsumedProbe() {
        val peers = peers()
        try {
            var committed = ""
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                reject { owner.ownerAdmit(peers.request, peers.joinerKey, true, now, testBeforeCas = {
                    committed = owner.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox
                }) }
                assertEquals(committed, owner.resume().outbox)
            }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                reject { joiner.joinerFinish(committed, now, testBeforeCas = { joiner.joinerFinish(committed, now) }) }
                assertInbox(joiner, 1)
                reject { joiner.receive(joiner.consumedProbeForProof()) }
            }
        } finally { cleanup(peers) }
    }

    @Test fun rejectedPinsConsentTamperingAndExpiryDoNotAdvancePhases() {
        val peers = peers()
        val wrongId = id()
        val wrongJoinerId = id()
        val expiredJoinerId = id()
        try {
            val wrongPin = DurableAdmission.createOwner(context, wrongId).use { it.nativePublicKey() }
            DurableAdmission.createJoiner(context, wrongJoinerId, wrongPin).use { joiner ->
                reject { joiner.joinerStart(peers.invitation, now) }
                reject { joiner.resume() }
            }
            DurableAdmission.createJoiner(context, expiredJoinerId, peers.ownerKey).use { joiner ->
                reject { joiner.joinerStart(peers.invitation, now + 300) }
                reject { joiner.resume() }
            }
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                reject { owner.ownerAdmit(peers.request, peers.joinerKey, false, now) }
                reject { owner.ownerAdmit(peers.request, wrongPin, true, now) }
                reject { owner.ownerAdmit(peers.request, peers.joinerKey, true, now + 300) }
                val bad = encode(envelope(peers.request).put("devicePublicKey", wrongPin))
                reject { owner.ownerAdmit(bad, wrongPin, true, now) }
                assertEquals(peers.invitation, owner.resume().outbox)
            }
            val welcome = DurableAdmission.open(context, peers.ownerId).use { it.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                val bad = encode(envelope(welcome).put("welcome", Base64.encodeToString(ByteArray(8), Base64.NO_WRAP)))
                reject { joiner.joinerFinish(bad, now) }
                val badProbe = encode(envelope(welcome).put("probe", Base64.encodeToString(ByteArray(8), Base64.NO_WRAP)))
                reject { joiner.joinerFinish(badProbe, now) }
                assertEquals(peers.request, joiner.resume().outbox)
                assertInbox(joiner, 0)
                joiner.joinerFinish(welcome, now)
                reject { joiner.joinerFinish(bad, now) }
            }
        } finally {
            cleanup(peers)
            for (id in listOf(wrongId, wrongJoinerId, expiredJoinerId)) DurableAdmission.deleteSynthetic(context, id)
        }
    }

    @Test fun missingKeysAndModifiedCiphertextFailClosedWithoutRegeneration() {
        val ownerId = id()
        val signingId = id()
        val tamperId = id()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            for (id in listOf(ownerId, signingId, tamperId)) DurableAdmission.createOwner(context, id).use { it.ownerStart(now) }
            store.deleteEntry(DurableAdmission.encryptionAliasForProof(ownerId))
            reject { DurableAdmission.open(context, ownerId) }
            assertFalse(store.containsAlias(DurableAdmission.encryptionAliasForProof(ownerId)))
            store.deleteEntry(DurableAdmission.signingAliasForProof(signingId))
            reject { DurableAdmission.open(context, signingId) }
            assertFalse(store.containsAlias(DurableAdmission.signingAliasForProof(signingId)))
            SQLiteDatabase.openDatabase(DurableAdmission.databaseFileForProof(context, tamperId).path, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
                val ciphertext = db.rawQuery("SELECT ciphertext FROM admission", null).use { it.moveToFirst(); it.getBlob(0) }
                ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()
                db.execSQL("UPDATE admission SET ciphertext=?", arrayOf(ciphertext))
            }
            reject { DurableAdmission.open(context, tamperId) }
        } finally { for (id in listOf(ownerId, signingId, tamperId)) DurableAdmission.deleteSynthetic(context, id) }
    }

    @Test fun oversizedPublicInputAndFailedAckLeaveCommittedStateIntact() {
        val peers = peers()
        try {
            DurableAdmission.open(context, peers.ownerId).use { owner ->
                reject { owner.ownerAdmit(Base64.encodeToString(ByteArray(128 * 1024 + 1), Base64.NO_WRAP), peers.joinerKey, true, now) }
                assertEquals(peers.invitation, owner.resume().outbox)
            }
            val welcome = DurableAdmission.open(context, peers.ownerId).use { it.ownerAdmit(peers.request, peers.joinerKey, true, now).outbox }
            DurableAdmission.open(context, peers.joinerId).use { joiner ->
                joiner.joinerFinish(welcome, now)
                val inbox = joiner.pending()
                try {
                    reject { joiner.acknowledge(inbox.single().id, VaultFault.BEFORE_COMMIT) }
                    assertInbox(joiner, 1)
                    reject { joiner.acknowledge(inbox.single().id, VaultFault.AFTER_COMMIT_UNCERTAIN) }
                } finally { inbox.forEach { it.clear() } }
            }
            DurableAdmission.open(context, peers.joinerId).use { assertInbox(it, 0); assertEquals("joined", it.resume().kind) }
        } finally { cleanup(peers) }
    }
}
