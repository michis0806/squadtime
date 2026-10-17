package dev.squadtime.pairing

import android.util.Base64
import org.json.JSONObject

internal object NativeMlsBridge {
    init {
        System.loadLibrary("squadtime_mls_spike")
        System.loadLibrary("squadtime_mls_jni")
    }
    external fun call(input: ByteArray): ByteArray
}

/** Synthetic two-peer MLS fixture, created in memory by the actual Rust core. */
class MlsFixture(val snapshot: ByteArray, val packets: List<ByteArray>, val expected: List<ByteArray>) {
    fun clear() { snapshot.fill(0); packets.forEach { it.fill(0) }; expected.forEach { it.fill(0) } }
}

internal class MlsReceive(val snapshot: ByteArray, val plaintext: ByteArray, val senderIndex: Long)

object NativeMls {
    private const val MAX_SNAPSHOT = 8 * 1024 * 1024
    private const val MAX_PACKET = 1024 * 1024
    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String, maximum: Int): ByteArray {
        require(value.length <= ((maximum + 2L) / 3L) * 4L)
        val result = Base64.decode(value, Base64.NO_WRAP)
        if (result.size > maximum) { result.fill(0); error("Native MLS operation rejected") }
        return result
    }
    private fun call(json: JSONObject): JSONObject {
        val input = json.toString().toByteArray(Charsets.UTF_8)
        try {
            require(input.size <= 16 * 1024 * 1024)
            val output = NativeMlsBridge.call(input)
            try { return JSONObject(output.toString(Charsets.UTF_8)) }
            finally { output.fill(0) }
        } finally { input.fill(0) }
    }
    fun fixture(): MlsFixture {
        val json = call(JSONObject().put("op", "fixture"))
        val packets = json.getJSONArray("packets")
        val expected = json.getJSONArray("expected")
        require(packets.length() == 2 && expected.length() == 2)
        return MlsFixture(decode(json.getString("snapshot"), MAX_SNAPSHOT),
            (0 until packets.length()).map { decode(packets.getString(it), MAX_PACKET) },
            (0 until expected.length()).map { decode(expected.getString(it), MAX_PACKET) })
    }
    internal fun receive(snapshot: ByteArray, packet: ByteArray): MlsReceive {
        require(snapshot.isNotEmpty() && snapshot.size <= MAX_SNAPSHOT)
        require(packet.isNotEmpty() && packet.size <= MAX_PACKET)
        val json = call(JSONObject().put("op", "receive").put("snapshot", encode(snapshot)).put("packet", encode(packet)))
        val sender = json.getLong("senderIndex")
        require(sender in 0..4_294_967_295L)
        return MlsReceive(decode(json.getString("snapshot"), MAX_SNAPSHOT),
            decode(json.getString("plaintext"), MAX_PACKET), sender)
    }
}
