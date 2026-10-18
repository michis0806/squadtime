package dev.squadtime.prototype

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Experimental BLE v1 only. Native signing keys and durable MLS state never enter this object. */
class BleCeremony internal constructor(val owner: Boolean, suppliedPair: KeyPair? = null, suppliedNonce: ByteArray? = null, suppliedSid: ByteArray? = null) : AutoCloseable {
    data class Result(val outgoing: ByteArray? = null, val pairCode: String? = null)
    private var pair: KeyPair? = suppliedPair ?: KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val parameters = (pair!!.public as ECPublicKey).params
    private var localPoint = point(pair!!.public as ECPublicKey)
    private var localNonce = suppliedNonce?.copyOf() ?: ByteArray(32).apply { SecureRandom().nextBytes(this) }
    private var sid: ByteArray? = if (owner) suppliedSid?.copyOf() ?: ByteArray(16).apply { SecureRandom().nextBytes(this) } else null
    init { require(localNonce.size == 32 && (!owner || sid?.size == 16)) }
    private var ownerCommit: ByteArray? = null
    private var joinerCommit: ByteArray? = null
    private var peerPoint: ByteArray? = null
    private var peerNonce: ByteArray? = null
    private var transcriptHash: ByteArray? = null
    private var keys: ByteArray? = null
    private var phase = if (owner) "new" else "owner-commit"
    private var approved = false
    private var confirmationQueued = false
    private var peerConfirmed = false
    private var sealed: ByteArray? = null
    private var sealedPlain: ByteArray? = null
    private var received = false
    private var closed = false
    val authenticated: Boolean get() = !closed && approved && confirmationQueued && peerConfirmed && keys != null
    val sas: String? get() = keys?.let { sas(it,transcriptHash!!) }
    val awaitingHandshake: Boolean get() = !closed && keys == null
    val localApproved: Boolean get() = approved
    private val role: Byte get() = if (owner) 0 else 1
    private fun packet(type: Int, value: ByteArray): ByteArray = byteArrayOf(type.toByte()) + checkNotNull(sid) + value
    private fun commitment(role: Byte, publicPoint: ByteArray, nonce: ByteArray): ByteArray = sha(domain("commit") + sid!! + role + publicPoint + nonce)
    fun start(): ByteArray {
        check(!closed && owner && phase == "new")
        ownerCommit = commitment(0,localPoint,localNonce); phase = "joiner-commit"
        return packet(1,ownerCommit!!)
    }
    fun receive(message: ByteArray): Result = try {
        check(!closed)
        require(message.size in 1..2092)
        val type = message[0].toInt() and 255
        if (type == 16) Result(pairCode = open(message)) else {
            require(type in 1..6 && message.size == if (type in 3..4) 114 else 49)
            val incomingSid = message.copyOfRange(1,17)
            if (!owner && phase == "owner-commit") sid = incomingSid.copyOf()
            require(MessageDigest.isEqual(incomingSid,sid))
            val value = message.copyOfRange(17,message.size)
            when {
                !owner && type == 1 && phase == "owner-commit" -> {
                    ownerCommit = value; joinerCommit = commitment(1,localPoint,localNonce); phase = "owner-reveal"
                    Result(packet(2,joinerCommit!!))
                }
                owner && type == 2 && phase == "joiner-commit" -> {
                    joinerCommit = value; phase = "joiner-reveal"
                    Result(packet(3,localPoint + localNonce))
                }
                !owner && type == 3 && phase == "owner-reveal" -> {
                    verifyReveal(value,0,ownerCommit!!); derive(); phase = "confirmation"
                    Result(packet(4,localPoint + localNonce))
                }
                owner && type == 4 && phase == "joiner-reveal" -> {
                    verifyReveal(value,1,joinerCommit!!); derive(); phase = "confirmation"; Result()
                }
                type == (if (owner) 6 else 5) && phase == "confirmation" && !peerConfirmed -> {
                    require(MessageDigest.isEqual(value,confirmation(if (owner) 1 else 0)))
                    peerConfirmed = true; value.fill(0); Result()
                }
                else -> error("Unexpected ceremony message")
            }
        }
    } catch (error: Exception) { close(); throw error }
    private fun verifyReveal(value: ByteArray, peerRole: Byte, expectedCommitment: ByteArray) {
        val publicPoint = value.copyOfRange(0,65)
        val nonce = value.copyOfRange(65,97)
        require(!MessageDigest.isEqual(publicPoint,localPoint) && !MessageDigest.isEqual(nonce,localNonce))
        publicKey(publicPoint)
        require(MessageDigest.isEqual(commitment(peerRole,publicPoint,nonce),expectedCommitment))
        peerPoint = publicPoint; peerNonce = nonce; value.fill(0)
    }
    private fun publicKey(bytes: ByteArray): PublicKey {
        require(bytes.size == 65 && bytes[0] == 4.toByte())
        // The platform validates the imported uncompressed point and curve membership.
        val point = java.security.spec.ECPoint(BigInteger(1,bytes.copyOfRange(1,33)),BigInteger(1,bytes.copyOfRange(33,65)))
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point,parameters))
        require((key as ECPublicKey).params.order == parameters.order)
        return key
    }
    private fun derive() {
        val ownerPoint = if (owner) localPoint else peerPoint!!
        val joinerPoint = if (owner) peerPoint!! else localPoint
        val ownerNonce = if (owner) localNonce else peerNonce!!
        val joinerNonce = if (owner) peerNonce!! else localNonce
        transcriptHash = sha(domain("transcript") + sid!! + ownerCommit!! + joinerCommit!! + ownerPoint + ownerNonce + joinerPoint + joinerNonce)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(pair!!.private); agreement.doPhase(publicKey(peerPoint!!),true)
        val shared = agreement.generateSecret()
        try { require(shared.size == 32); keys = deriveKeys(shared,transcriptHash!!) } finally { shared.fill(0) }
    }
    private fun confirmation(senderRole: Byte): ByteArray {
        val key = keys!!.copyOfRange(if (senderRole == 0.toByte()) 32 else 64,if (senderRole == 0.toByte()) 64 else 96)
        return try { hmac(key,domain("confirm") + transcriptHash!! + senderRole) } finally { key.fill(0) }
    }
    fun approve(): ByteArray {
        check(!closed && phase == "confirmation" && keys != null && !approved)
        approved = true
        return packet(if (owner) 5 else 6,confirmation(role))
    }
    fun confirmationQueued() {
        check(!closed && approved && !confirmationQueued && keys != null)
        confirmationQueued = true
    }
    fun seal(pairCode: String): ByteArray {
        check(authenticated)
        val plaintext = pairCode.toByteArray(Charsets.UTF_8)
        try {
            require(plaintext.size in 1..2048)
            sealed?.let { require(MessageDigest.isEqual(plaintext,sealedPlain)); return it.copyOf() }
            check(owner || received)
            val header = ByteBuffer.allocate(28).put(16.toByte()).put(sid!!).put(role).putLong(0).putShort((plaintext.size + 16).toShort()).array()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val key = keys!!.copyOfRange(if (owner) 96 else 128,if (owner) 128 else 160)
            try { cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,ByteArray(12))) } finally { key.fill(0) }
            cipher.updateAAD(domain("data") + transcriptHash!! + header)
            sealed = header + cipher.doFinal(plaintext); sealedPlain = plaintext.copyOf()
            return sealed!!.copyOf()
        } finally { plaintext.fill(0) }
    }
    private fun open(message: ByteArray): String {
        check(authenticated && !received && (!owner || sealed != null))
        require(message.size in 45..2092)
        val header = message.copyOfRange(0,28)
        val buffer = ByteBuffer.wrap(header)
        require(buffer.get() == 16.toByte())
        val incomingSid = ByteArray(16).also { buffer.get(it) }
        require(MessageDigest.isEqual(incomingSid,sid) && buffer.get() == if (owner) 1.toByte() else 0.toByte())
        require(buffer.long == 0L)
        val length = buffer.short.toInt() and 65535
        require(length in 17..2064 && message.size == 28 + length)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = keys!!.copyOfRange(if (owner) 128 else 96,if (owner) 160 else 128)
        try { cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,ByteArray(12))) } finally { key.fill(0) }
        cipher.updateAAD(domain("data") + transcriptHash!! + header)
        val plaintext = cipher.doFinal(message.copyOfRange(28,message.size))
        return try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(plaintext)).toString()
            received = true; text
        } finally { plaintext.fill(0) }
    }
    override fun close() {
        closed = true; phase = "closed"; approved = false; confirmationQueued = false; peerConfirmed = false
        listOf(localPoint,localNonce,sid,ownerCommit,joinerCommit,peerPoint,peerNonce,transcriptHash,keys,sealed,sealedPlain).forEach { it?.fill(0) }
        runCatching { pair?.private?.destroy() }; pair = null; keys = null; sealed = null; sealedPlain = null
    }
    companion object {
        private fun domain(name: String) = "squadtime-ble-$name-v1\n".toByteArray(Charsets.US_ASCII)
        internal fun sha(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
        internal fun hmac(key: ByteArray, bytes: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key,"HmacSHA256")); doFinal(bytes) }
        internal fun deriveKeys(shared: ByteArray, hash: ByteArray): ByteArray {
            val prk = hmac(hash,shared)
            val result = ByteArray(160)
            var previous = ByteArray(0)
            try {
                for (index in 1..5) {
                    val next = hmac(prk,previous + domain("keys") + index.toByte())
                    previous.fill(0); previous = next; next.copyInto(result,(index - 1) * 32)
                }
                return result
            } finally { prk.fill(0); previous.fill(0) }
        }
        internal fun sas(keys: ByteArray, hash: ByteArray): String {
            val key = keys.copyOfRange(0,32)
            val bytes = try { hmac(key,domain("sas") + hash) } finally { key.fill(0) }
            return try { bytes.take(4).fold(0L) { value, byte -> (value shl 8) or (byte.toLong() and 255) }.rem(1_000_000).toString().padStart(6,'0') } finally { bytes.fill(0) }
        }
        internal fun point(key: ECPublicKey): ByteArray {
            fun fixed(value: BigInteger): ByteArray = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            return byteArrayOf(4) + fixed(key.w.affineX) + fixed(key.w.affineY)
        }
    }
}
