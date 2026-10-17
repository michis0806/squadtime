package dev.squadtime.proof

import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.squadtime.pairing.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class PairingProofTest {
    private val now = 1_700_000_001L
    private fun fixture(): JSONObject {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val imported = InstrumentationRegistry.getArguments().getString("fixtureFile")
        if (imported != null) {
            require(imported.matches(Regex("pairing-[a-z-]+\\.json")))
            return JSONObject(File(instrumentation.targetContext.filesDir, imported).readText())
        }
        return instrumentation.context.assets.open("pairing-v1.json").bufferedReader().use { JSONObject(it.readText()) }
    }
    private fun key() = DeviceSigningKey("dev.squadtime.proof.test.${UUID.randomUUID()}").createOrLoad()

    @Test fun independentFixtureTranscriptsAndSignatures() {
        val fixture = fixture()
        val request = PairingJson.request(fixture.getJSONObject("request"))
        val approval = PairingJson.approval(fixture.getJSONObject("approval"))
        assertEquals(fixture.getString("requestTranscriptHex"), request.transcript().hex())
        assertEquals(fixture.getString("approvalTranscriptHex"), approval.transcript().hex())
        assertTrue(request.valid(fixture.getLong("now")))
        assertTrue(approval.valid(request, fixture.getString("trustedApproverPublicKey"), fixture.getLong("now")))
        assertFalse(request.valid(request.issuedAt - 1))
        assertTrue(request.valid(request.issuedAt))
        assertFalse(request.valid(request.expiresAt))
        assertFalse(request.copy(expiresAt = request.issuedAt + 301).valid(now))
    }

    @Test fun rejectTamperedFieldsAndMalformedEncoding() {
        val fixture = fixture()
        val request = PairingJson.request(fixture.getJSONObject("request"))
        val approval = PairingJson.approval(fixture.getJSONObject("approval"))
        val trusted = fixture.getString("trustedApproverPublicKey")
        val requests = listOf(
            request.copy(version = 2), request.copy(requestId = UUID.randomUUID().toString()),
            request.copy(deviceId = UUID.randomUUID().toString()), request.copy(challenge = "00".repeat(32)),
            request.copy(publicKey = trusted), request.copy(issuedAt = request.issuedAt + 1),
            request.copy(expiresAt = request.expiresAt - 1), request.copy(signature = request.signature.dropLast(2) + if (request.signature.endsWith("00")) "01" else "00"),
            request.copy(signature = request.signature + "00"), request.copy(signature = "3006020100020100"),
            request.copy(publicKey = "04" + "00".repeat(64)), request.copy(publicKey = request.publicKey.uppercase()),
            request.copy(challenge = request.challenge.uppercase()), request.copy(requestId = request.requestId.uppercase()),
            request.copy(issuedAt = -1), request.copy(expiresAt = 9_007_199_254_740_992L),
            request.copy(expiresAt = request.issuedAt)
        )
        requests.forEachIndexed { index, tampered ->
            assertFalse("request mutation $index", tampered.valid(now))
            assertFalse("approval binding $index", approval.valid(tampered, trusted, now))
        }
        val approvals = listOf(
            approval.copy(version = 2), approval.copy(requestId = UUID.randomUUID().toString()),
            approval.copy(requestDigest = "00".repeat(32)), approval.copy(approverPublicKey = request.publicKey),
            approval.copy(signature = "3006020100020100"), approval.copy(signature = approval.signature + "00")
        )
        approvals.forEach { assertFalse(it.valid(request, trusted, now)) }
        assertFalse(approval.valid(request, request.publicKey, now))
        val invalidJson = PairingJson.encode(request).put("issuedAt", "1700000000")
        assertThrows(IllegalStateException::class.java) { PairingJson.request(invalidJson) }
        assertThrows(IllegalArgumentException::class.java) {
            PairingJson.request(PairingJson.encode(request).put("extra", true))
        }
    }

    @Test fun pendingConsumesOnlySuccessfulApproval() {
        val fixture = fixture()
        val request = PairingJson.request(fixture.getJSONObject("request"))
        val approval = PairingJson.approval(fixture.getJSONObject("approval"))
        val pending = PendingPairing(request, fixture.getString("trustedApproverPublicKey"))
        assertFalse(pending.accept(approval.copy(signature = "3006020100020100"), now))
        assertFalse(pending.accept(approval, request.expiresAt))
        assertTrue(pending.accept(approval, now))
        assertFalse(pending.accept(approval, now))
    }

    @Test fun androidKeyStoreLifecycleAndPublicInteropExport() {
        val device = key()
        val approver = key()
        try {
            assertTrue(device.privateKeyIsNonExportable())
            assertTrue(approver.privateKeyIsNonExportable())
            val request = PairingRequest.create(device, now)
            assertThrows(IllegalArgumentException::class.java) {
                PairingApproval.create(request, approver, now, userConfirmed = false)
            }
            val approval = PairingApproval.create(request, approver, now, userConfirmed = true)
            assertTrue(request.valid(now))
            assertTrue(PendingPairing(request, approver.publicKeyHex()).accept(approval, now))
            val untrusted = PairingApproval.create(request, device, now, userConfirmed = true)
            assertFalse(untrusted.valid(request, approver.publicKeyHex(), now))
            assertTrue(PairingJson.request(PairingJson.encode(request)).valid(now))
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            File(context.filesDir, "pairing-native-export.json").writeText(JSONObject().apply {
                put("request", PairingJson.encode(request)); put("approval", PairingJson.encode(approval))
                put("trustedApproverPublicKey", approver.publicKeyHex()); put("now", now)
                put("requestTranscriptHex", request.transcript().hex()); put("approvalTranscriptHex", approval.transcript().hex())
            }.toString())
            val level = device.securityLevel()
            assertTrue(level in setOf(KeyProperties.SECURITY_LEVEL_SOFTWARE, KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE))
            File(context.filesDir, "key-security-level.txt").writeText("Android KeyInfo.securityLevel=$level\nEmulator only; no physical hardware assurance.\n")
        } finally { device.delete(); approver.delete() }
        assertFalse(device.exists()); assertFalse(approver.exists())
    }

    @Test fun existingAliasLoadsAcrossInstancesAndDeletionRotatesKey() {
        val alias = "dev.squadtime.proof.test.${UUID.randomUUID()}"
        val first = DeviceSigningKey(alias).createOrLoad()
        try {
            val second = DeviceSigningKey(alias).createOrLoad()
            assertEquals(first.publicKeyHex(), second.publicKeyHex())
            val request = PairingRequest.create(first, now)
            val signedAgain = request.copy(signature = second.sign(request.transcript()))
            assertTrue(request.valid(now)); assertTrue(signedAgain.valid(now))
            assertTrue(second.privateKeyIsNonExportable())
            first.delete()
            assertFalse(second.exists())
            second.createOrLoad()
            assertNotEquals(request.publicKey, second.publicKeyHex())
            assertFalse(request.copy(signature = second.sign(request.transcript())).valid(now))
        } finally { first.delete() }
        assertFalse(first.exists())
    }
}
