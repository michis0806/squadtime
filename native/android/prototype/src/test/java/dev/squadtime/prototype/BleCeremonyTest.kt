package dev.squadtime.prototype

import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.*
import java.security.spec.*

class BleCeremonyTest {
    private val fixture = javaClass.classLoader!!.getResourceAsStream("ble-pairing-v1.json")!!.bufferedReader().use { it.readText() }
    private fun field(name: String) = Regex("\"$name\"\\s*:\\s*\"([^\"]*)\"").find(fixture)!!.groupValues[1]
    private fun bytes(name: String) = field(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun rejected(block: () -> Unit) { assertTrue(runCatching(block).isFailure) }
    private fun vector(owner: Boolean): BleCeremony {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val public = bytes(if (owner) "ownerPublicKeyHex" else "joinerPublicKeyHex")
        val factory = KeyFactory.getInstance("EC")
        val key = factory.generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1,public.copyOfRange(1,33)),BigInteger(1,public.copyOfRange(33,65))),params))
        // Public synthetic reference scalars are constructed locally, never serialized.
        val privateKey = factory.generatePrivate(ECPrivateKeySpec(if (owner) BigInteger.ONE else BigInteger.TWO,params))
        return BleCeremony(owner,KeyPair(key,privateKey),bytes(if (owner) "ownerNonceHex" else "joinerNonceHex"),if (owner) bytes("sidHex") else null)
    }
    private fun handshake(owner: BleCeremony, joiner: BleCeremony) {
        val commit = owner.start(); val reply = joiner.receive(commit).outgoing!!
        val reveal = owner.receive(reply).outgoing!!; owner.receive(joiner.receive(reveal).outgoing!!)
    }
    private fun approve(owner: BleCeremony, joiner: BleCeremony) {
        val ownerMac = owner.approve(); owner.confirmationQueued(); joiner.receive(ownerMac)
        assertFalse(joiner.authenticated)
        val joinerMac = joiner.approve(); assertFalse(joiner.authenticated)
        joiner.confirmationQueued(); owner.receive(joinerMac)
        assertTrue(owner.authenticated); assertTrue(joiner.authenticated)
    }
    @Test fun matchesIndependentPublicFixtureBothDirections() {
        vector(true).use { owner -> vector(false).use { joiner ->
            val first = owner.start(); assertEquals(field("ownerCommitmentHex"),hex(first.copyOfRange(17,49)))
            val second = joiner.receive(first).outgoing!!; assertEquals(field("joinerCommitmentHex"),hex(second.copyOfRange(17,49)))
            val reveal = owner.receive(second).outgoing!!; owner.receive(joiner.receive(reveal).outgoing!!)
            assertEquals(field("sas"),owner.sas); assertEquals(owner.sas,joiner.sas)
            val ownerMac = owner.approve(); owner.confirmationQueued()
            assertEquals(field("ownerConfirmMacHex"),hex(ownerMac.copyOfRange(17,49))); joiner.receive(ownerMac)
            val joinerMac = joiner.approve(); joiner.confirmationQueued()
            assertEquals(field("joinerConfirmMacHex"),hex(joinerMac.copyOfRange(17,49))); owner.receive(joinerMac)
            val ownerFrame = owner.seal(field("ownerPlaintext")); assertEquals(field("ownerFrameHex"),hex(ownerFrame))
            assertEquals(field("ownerPlaintext"),joiner.receive(ownerFrame).pairCode)
            assertArrayEquals(ownerFrame,owner.seal(field("ownerPlaintext")))
            val joinerFrame = joiner.seal(field("joinerPlaintext")); assertEquals(field("joinerFrameHex"),hex(joinerFrame))
            assertEquals(field("joinerPlaintext"),owner.receive(joinerFrame).pairCode)
        } }
    }
    @Test fun localApprovalQueuedMacAndPeerApprovalAreAllRequired() {
        BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            handshake(owner,joiner); assertEquals(owner.sas,joiner.sas)
            rejected { owner.seal("premature") }
            val peerMac = joiner.approve(); joiner.confirmationQueued(); owner.receive(peerMac)
            assertFalse(owner.authenticated); owner.approve(); assertFalse(owner.authenticated)
            owner.confirmationQueued(); assertTrue(owner.authenticated)
        } }
    }
    @Test fun changedCommitmentReplaysAndReflectedMacsFailClosed() {
        BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            val commit = owner.start(); val reply = joiner.receive(commit).outgoing!!
            val reveal = owner.receive(reply).outgoing!!; reveal[20] = (reveal[20].toInt() xor 1).toByte()
            rejected { joiner.receive(reveal) }; assertFalse(joiner.authenticated); assertNull(joiner.sas)
        } }
        BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            handshake(owner,joiner); val mac = owner.approve(); owner.confirmationQueued()
            rejected { owner.receive(mac) }; assertFalse(owner.authenticated)
        } }
        BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            val commit = owner.start(); joiner.receive(commit); rejected { joiner.receive(commit) }; assertNull(joiner.sas)
        } }
    }
    @Test fun ciphertextSessionRoleCounterReplayAndChangedResealAreRejected() {
        for (offset in listOf(1,17,25,27,30)) BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            handshake(owner,joiner); approve(owner,joiner)
            val packet = owner.seal("authenticated test"); packet[offset] = (packet[offset].toInt() xor 1).toByte()
            rejected { joiner.receive(packet) }; assertFalse(joiner.authenticated)
        } }
        BleCeremony(true).use { owner -> BleCeremony(false).use { joiner ->
            handshake(owner,joiner); approve(owner,joiner)
            val packet = owner.seal("exact bytes"); joiner.receive(packet)
            rejected { joiner.receive(packet) }; rejected { owner.seal("different bytes") }
        } }
    }
    @Test fun malformedPointAndOutOfOrderRevealCannotDisplayCode() {
        BleCeremony(false).use { joiner -> rejected { joiner.receive(ByteArray(114).apply { this[0] = 3 }) }; assertNull(joiner.sas) }
        vector(true).use { owner -> vector(false).use { joiner ->
            val initial = owner.start(); val invalidPoint = ByteArray(65).apply { this[0] = 4 }; val nonce = bytes("ownerNonceHex")
            val commit = BleCeremony.sha("squadtime-ble-commit-v1\n".toByteArray() + initial.copyOfRange(1,17) + byteArrayOf(0) + invalidPoint + nonce)
            joiner.receive(byteArrayOf(1) + initial.copyOfRange(1,17) + commit)
            rejected { joiner.receive(byteArrayOf(3) + initial.copyOfRange(1,17) + invalidPoint + nonce) }; assertNull(joiner.sas)
        } }
    }
}
