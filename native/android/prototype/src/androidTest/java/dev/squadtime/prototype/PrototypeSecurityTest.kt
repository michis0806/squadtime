package dev.squadtime.prototype

import android.content.Context
import android.content.ContextWrapper
import androidx.test.platform.app.InstrumentationRegistry
import dev.squadtime.pairing.DurableAdmission
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.util.UUID

class PrototypeSecurityTest {
    private fun rejected(block: () -> Unit) {
        var rejected = false
        try { block() } catch (_: Exception) { rejected = true }
        assertTrue("Expected fail-closed rejection", rejected)
    }
    private fun isolatedContext(): Context {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(base.noBackupFilesDir,"instrumentation-${UUID.randomUUID()}").apply { mkdirs() }
        return object : ContextWrapper(base) { override fun getNoBackupFilesDir(): File = directory }
    }
    @Test fun relayOriginsRejectExternalRedirectTargetsAndAmbiguousAddresses() {
        listOf("https://192.168.1.2:8789","http://example.com:8789","http://127.0.0.1:8789","http://192.168.1.2:8789/", "http://192.168.1.2:8789?x=1", "http://user@192.168.1.2:8789", "http://192.168.001.2:8789", "http://192.168.1.2:80", "http://172.15.1.1:8789").forEach { rejected { PrototypeProtocol.origin(it) } }
        listOf("http://192.168.1.2:8789","http://10.0.2.2:8789","http://172.16.1.1:8789").forEach { assertEquals(it,PrototypeProtocol.origin(it)) }
    }
    @Test fun profileIsEncryptedAndKeyLossDoesNotCreateReplacement() {
        val context = isolatedContext()
        val scope = UUID.randomUUID().toString()
        val alias = "dev.squadtime.prototype.profile.v1.$scope"
        val store = ProfileStore(context,scope)
        try {
            store.save(JSONObject().put("nickname","synthetic-private-marker"),true)
            val bytes = File(context.noBackupFilesDir,"prototype-profile.bin").readBytes()
            assertFalse(bytes.toString(Charsets.ISO_8859_1).contains("synthetic-private-marker"))
            assertEquals("synthetic-private-marker",ProfileStore(context,scope).read()!!.getString("nickname"))
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            rejected { ProfileStore(context,scope).read() }
            rejected { ProfileStore(context,scope).save(JSONObject()) }
            assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias))
        } finally { store.reset(); context.noBackupFilesDir.deleteRecursively() }
    }
    @Test fun actualAdmissionReceiptBindsAllCommittedEnvelopesAndNativePin() {
        val context = isolatedContext()
        val ownerId = UUID.randomUUID().toString()
        val joinerId = UUID.randomUUID().toString()
        try {
            val now = System.currentTimeMillis() / 1000
            val invitation = DurableAdmission.createOwner(context,ownerId).use { it.ownerStart(now) }
            val request = DurableAdmission.createJoiner(context,joinerId,invitation.nativePublicKey).use { it.joinerStart(invitation.outbox,now) }
            val qr = JSONObject().put("v",1).put("type","request").put("relay","http://192.168.1.2:8789").put("session","a".repeat(64))
                .put("key",request.nativePublicKey).put("hash",PrototypeProtocol.hash(request.outbox)).put("expiresAt",now+300).put("label","Android Test")
            assertEquals("request",PrototypeProtocol.parseQr(PrototypeProtocol.qr(qr),now).getString("type"))
            rejected { PrototypeProtocol.parseQr(PrototypeProtocol.qr(JSONObject(qr.toString()).put("unknown",true)),now) }
            rejected { PrototypeProtocol.parseQr(PrototypeProtocol.qr(JSONObject(qr.toString()).put("expiresAt",now)),now) }
            rejected { PrototypeProtocol.parseQr(PrototypeProtocol.qr(JSONObject(qr.toString()).put("v","1")),now) }
            val malformedUtf8 = qr.toString().replace("Android Test", "BAD_MARKER").toByteArray()
            val marker = "BAD_MARKER".toByteArray()
            val markerOffset = malformedUtf8.indices.first { offset -> offset + marker.size <= malformedUtf8.size && malformedUtf8.copyOfRange(offset,offset + marker.size).contentEquals(marker) }
            malformedUtf8[markerOffset] = 0xff.toByte()
            val malformedCode = PrototypeProtocol.PREFIX + android.util.Base64.encodeToString(malformedUtf8,android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
            rejected { PrototypeProtocol.parseQr(malformedCode,now) }
            val welcome = DurableAdmission.open(context,ownerId).use { it.ownerAdmit(request.outbox,request.nativePublicKey,true,now) }
            DurableAdmission.open(context,joinerId).use { it.joinerFinish(welcome.outbox,now) }
            val metadata = JSONObject().put("id",joinerId).put("session","a".repeat(64)).put("peerKey",request.nativePublicKey)
                .put("invitationHash",PrototypeProtocol.hash(invitation.outbox)).put("requestHash",PrototypeProtocol.hash(request.outbox)).put("welcomeHash",PrototypeProtocol.hash(welcome.outbox))
            val receipt = PrototypeProtocol.createReceipt(metadata)
            PrototypeProtocol.verifyReceipt(metadata,receipt)
            val receiptJson = JSONObject(PrototypeProtocol.decode(receipt).toString(Charsets.UTF_8))
            rejected { PrototypeProtocol.verifyReceipt(metadata,PrototypeProtocol.encode(JSONObject(receiptJson.toString()).put("v","1").toString().toByteArray())) }
            rejected { PrototypeProtocol.verifyReceipt(metadata,PrototypeProtocol.encode(receiptJson.toString().replace("\"v\":1", "\"v\":1.0").toByteArray())) }
            rejected { PrototypeProtocol.verifyReceipt(JSONObject(metadata.toString()).put("welcomeHash","b".repeat(64)),receipt) }
            rejected { PrototypeProtocol.verifyReceipt(JSONObject(metadata.toString()).put("peerKey",invitation.nativePublicKey),receipt) }
            DurableAdmission.open(context,joinerId).use {
                assertEquals("joined",it.resume().kind)
                val inbox = it.pending()
                assertEquals(1,inbox.size)
                inbox.forEach { message -> message.clear() }
            }
            assertEquals(welcome.outbox,DurableAdmission.open(context,ownerId).use { it.resume().outbox })
        } finally {
            DurableAdmission.deleteSynthetic(context,ownerId)
            DurableAdmission.deleteSynthetic(context,joinerId)
            context.noBackupFilesDir.deleteRecursively()
        }
    }
}
