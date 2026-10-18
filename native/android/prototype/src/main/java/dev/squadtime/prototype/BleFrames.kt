package dev.squadtime.prototype

import java.nio.ByteBuffer
import java.util.ArrayDeque

/** A single bounded stream. Malformed input poisons this attempt until explicitly cleared. */
class BleFrameReader {
    private val header = ByteArray(4)
    private var headerSize = 0
    private var body: ByteArray? = null
    private var bodySize = 0
    private var rejected = false
    private var fragments = 0
    val hasPartial: Boolean get() = headerSize > 0
    fun accept(chunk: ByteArray): List<ByteArray> {
        check(!rejected)
        val messages = mutableListOf<ByteArray>()
        try {
            require(chunk.size in 1..20)
            require(++fragments <= 4096)
            for (byte in chunk) {
                val target = body
                if (target == null) {
                    header[headerSize++] = byte
                    if (headerSize == 4) {
                        val length = header.fold(0L) { value, next -> (value shl 8) or (next.toLong() and 255) }
                        require(length in 1..2092)
                        body = ByteArray(length.toInt())
                    }
                } else {
                    target[bodySize++] = byte
                    if (bodySize == target.size) {
                        messages.add(target.copyOf())
                        target.fill(0); body = null; bodySize = 0; header.fill(0); headerSize = 0; fragments = 0
                    }
                }
            }
            return messages
        } catch (error: Exception) { messages.forEach { it.fill(0) }; clear(); rejected = true; throw error }
    }
    fun clear() { header.fill(0); headerSize = 0; body?.fill(0); body = null; bodySize = 0; rejected = false; fragments = 0 }
}

/** Only one acknowledged ATT chunk is released at a time; frames never interleave. */
class BleFrameWriter {
    private val frames = ArrayDeque<ByteArray>()
    private var totalBytes = 0
    private var offset = 0
    private var inFlight = 0
    fun enqueue(bytes: ByteArray) {
        require(bytes.size in 1..2092)
        require(totalBytes + bytes.size + 4 <= 65536)
        val frame = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
        frames.addLast(frame); totalBytes += frame.size
    }
    fun next(): ByteArray? {
        check(inFlight == 0)
        val frame = frames.peekFirst() ?: return null
        inFlight = minOf(20,frame.size - offset)
        return frame.copyOfRange(offset,offset + inFlight)
    }
    fun acknowledge() {
        check(inFlight > 0 && frames.isNotEmpty())
        val frame = frames.first
        frame.fill(0,offset,offset + inFlight)
        offset += inFlight; inFlight = 0
        if (offset == frame.size) { frames.removeFirst(); totalBytes -= frame.size; offset = 0 }
    }
    fun isIdle(): Boolean = frames.isEmpty() && inFlight == 0
    fun clear() { frames.forEach { it.fill(0) }; frames.clear(); totalBytes = 0; offset = 0; inFlight = 0 }
}
