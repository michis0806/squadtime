package dev.squadtime.proof

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.squadtime.pairing.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class MlsEnrollmentProofTest {
    private val now = 1_700_000_001L
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun key() = DeviceSigningKey("dev.squadtime.proof.enrollment.${UUID.randomUUID()}").createOrLoad()
    private fun reject(action: () -> Unit) { assertThrows(EnrollmentRejected::class.java) { action() } }
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun bytes(value: String) = Base64.decode(value, Base64.NO_WRAP)
    private fun signature(key: DeviceSigningKey, transcript: String): String =
        b64(key.sign(bytes(transcript)).chunked(2).map { it.toInt(16).toByte() }.toByteArray())

    @Test fun nativeSignedBindingAdmitsAndDecryptsThroughEncryptedVault() {
        val device = key()
        val approver = key()
        val vaultId = UUID.randomUUID().toString()
        try {
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                val proof = pending.authorize(approver, userConfirmed = true, now = now)
                File(context.filesDir, "enrollment-native-export.json").writeText(proof.publicJson().toString())
                pending.completeIntoVault(context, vaultId, proof, now).use { joined ->
                    assertEquals(2, joined.packets.size)
                    joined.packets.forEachIndexed { index, packet ->
                        val received = joined.vault.receive(packet)
                        try { assertTrue(received.plaintext.contentEquals(joined.expected[index])) }
                        finally { received.clear() }
                    }
                    val inbox = joined.vault.pending()
                    try { assertEquals(2, inbox.size) } finally { inbox.forEach { it.clear() } }
                    assertThrows(VaultRejected::class.java) { joined.vault.receive(joined.packets[0]) }
                }
                reject { pending.complete(proof, now) }
                reject { NativeEnrollment.completeCandidate(proof, now) }
            }
            MlsVault.open(context, vaultId).use { vault ->
                val inbox = vault.pending()
                try {
                    assertEquals(2, inbox.size)
                    inbox.forEach { vault.acknowledge(it.id) }
                } finally { inbox.forEach { it.clear() } }
            }
            MlsVault.open(context, vaultId).use { assertTrue(it.pending().isEmpty()) }
        } finally { MlsVault.deleteSynthetic(context, vaultId); device.delete(); approver.delete() }
    }

    @Test fun rustRejectsOtherKeyPackageGroupAndSignaturesWithoutConsumingValidPending() {
        val device = key()
        val approver = key()
        val attacker = key()
        try {
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { other ->
                    val proof = pending.authorize(approver, userConfirmed = true, now = now)
                    val candidates = listOf(
                        proof.copy(keyPackage = other.keyPackage),
                        proof.copy(groupId = other.groupId),
                        proof.copy(pendingId = other.pendingId),
                        proof.copy(requestSignature = signature(attacker, proof.request)),
                        proof.copy(approvalSignature = signature(attacker, proof.approval)),
                    )
                    candidates.forEach { candidate -> reject { NativeEnrollment.completeCandidate(candidate, now) } }
                    pending.complete(proof, now).clear()
                }
            }
        } finally { device.delete(); approver.delete(); attacker.delete() }
    }

    @Test fun nativeCoordinatorRejectsChangedContextPinsAndTranscripts() {
        val device = key()
        val approver = key()
        val attacker = key()
        try {
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                reject { pending.authorize(attacker, userConfirmed = true, now = now) }
                val proof = pending.authorize(approver, userConfirmed = true, now = now)
                val candidates = listOf(
                    proof.copy(groupId = b64(ByteArray(32))),
                    proof.copy(keyPackage = b64(bytes(proof.keyPackage).apply { this[lastIndex] = (last().toInt() xor 1).toByte() })),
                    proof.copy(request = b64(bytes(proof.request) + byteArrayOf(10))),
                    proof.copy(approval = b64(bytes(proof.approval) + byteArrayOf(10))),
                    proof.copy(devicePublicKey = b64(attacker.publicKeyHex().chunked(2).map { it.toInt(16).toByte() }.toByteArray())),
                    proof.copy(trustedApproverPublicKey = b64(attacker.publicKeyHex().chunked(2).map { it.toInt(16).toByte() }.toByteArray())),
                    proof.copy(requestSignature = signature(attacker, proof.request)),
                    proof.copy(approvalSignature = signature(attacker, proof.approval)),
                )
                candidates.forEach { reject { pending.complete(it, now) } }
                pending.complete(proof, now).clear()
            }
        } finally { device.delete(); approver.delete(); attacker.delete() }
    }

    @Test fun consentExpiryAndReplayFailClosed() {
        val device = key()
        val approver = key()
        try {
            reject { NativeEnrollment.prepare(device, device.publicKeyHex(), now) }
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                reject { pending.authorize(approver, userConfirmed = false, now = now) }
                reject { pending.authorize(approver, userConfirmed = true, now = now - 1) }
                reject { pending.authorize(approver, userConfirmed = true, now = now + 300) }
                val proof = pending.authorize(approver, userConfirmed = true, now = now)
                reject { pending.complete(proof, now + 300) }
                reject { NativeEnrollment.completeCandidate(proof, now + 300) }
            }
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                val proof = pending.authorize(approver, userConfirmed = true, now = now)
                pending.complete(proof, now + 299).clear()
                reject { pending.authorize(approver, userConfirmed = true, now = now + 299) }
                reject { NativeEnrollment.completeCandidate(proof, now + 299) }
            }
        } finally { device.delete(); approver.delete() }
    }

    @Test fun cancellationRejectsPreviouslySignedAdmission() {
        val device = key()
        val approver = key()
        try {
            val pending = NativeEnrollment.prepare(device, approver.publicKeyHex(), now)
            val proof = pending.authorize(approver, userConfirmed = true, now = now)
            pending.close()
            reject { pending.authorize(approver, userConfirmed = true, now = now) }
            reject { pending.complete(proof, now) }
            reject { NativeEnrollment.completeCandidate(proof, now) }
        } finally { device.delete(); approver.delete() }
    }

    @Test fun vaultCreationFailureDoesNotClaimAtomicAdmissionRollback() {
        val device = key()
        val approver = key()
        val fixture = NativeMls.fixture()
        val vaultId = UUID.randomUUID().toString()
        try {
            MlsVault.create(context, vaultId, fixture.snapshot).close()
            NativeEnrollment.prepare(device, approver.publicKeyHex(), now).use { pending ->
                val proof = pending.authorize(approver, userConfirmed = true, now = now)
                assertThrows(VaultRejected::class.java) { pending.completeIntoVault(context, vaultId, proof, now) }
                reject { pending.complete(proof, now) }
                reject { NativeEnrollment.completeCandidate(proof, now) }
            }
            MlsVault.open(context, vaultId).use { assertTrue(it.pending().isEmpty()) }
        } finally { MlsVault.deleteSynthetic(context, vaultId); fixture.clear(); device.delete(); approver.delete() }
    }
}
