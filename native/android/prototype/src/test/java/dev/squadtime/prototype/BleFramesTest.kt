package dev.squadtime.prototype
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.io.ByteArrayOutputStream

class BleFramesTest {
    private fun frame(bytes: ByteArray): ByteArray = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private fun rejected(block: () -> Unit) { assertTrue(runCatching(block).isFailure) }
    @Test fun everyAttSplitPreservesBinaryFramesAndWithholdsIncompleteData() {
        val first = ByteArray(114) { it.toByte() }; val second = byteArrayOf(-1,0,1)
        for (size in 1..20) {
            val reader = BleFrameReader()
            val received = (frame(first) + frame(second)).toList().chunked(size).flatMap { reader.accept(it.toByteArray()) }
            assertEquals(2,received.size); assertArrayEquals(first,received[0]); assertArrayEquals(second,received[1])
        }
        val reader = BleFrameReader()
        assertTrue(reader.accept(frame(second).copyOfRange(0,6)).isEmpty())
        assertArrayEquals(second,reader.accept(byteArrayOf(1)).single())
    }
    @Test fun invalidLengthsPoisonTheAttemptUntilCleared() {
        for (length in listOf(0,2093,-1,Int.MAX_VALUE)) {
            val reader = BleFrameReader()
            rejected { reader.accept(ByteBuffer.allocate(4).putInt(length).array()) }
            rejected { reader.accept(frame(byteArrayOf(1))) }
            reader.clear(); assertArrayEquals(byteArrayOf(1),reader.accept(frame(byteArrayOf(1))).single())
        }
        rejected { BleFrameReader().accept(ByteArray(21)) }
    }
    @Test fun outgoingFramesWaitForAcknowledgementAndNeverInterleave() {
        val writer = BleFrameWriter()
        val first = ByteArray(114) { it.toByte() }; val second = byteArrayOf(6)
        writer.enqueue(first); writer.enqueue(second)
        val actual = ByteArrayOutputStream()
        while (!writer.isIdle()) {
            val chunk = writer.next()!!; assertTrue(chunk.size in 1..20)
            rejected { writer.next() }; actual.write(chunk); writer.acknowledge()
        }
        assertArrayEquals(frame(first) + frame(second),actual.toByteArray())
        assertNull(writer.next()); rejected { writer.acknowledge() }
    }
    @Test fun queueAndMessageSizesRemainBoundedAndClearDiscardsPendingBytes() {
        val writer = BleFrameWriter()
        repeat(31) { writer.enqueue(ByteArray(2092)) }
        rejected { writer.enqueue(ByteArray(2092)) }; rejected { writer.enqueue(ByteArray(2093)) }
        writer.next(); writer.acknowledge(); rejected { writer.enqueue(ByteArray(2092)) }
        writer.clear(); assertTrue(writer.isIdle()); assertNull(writer.next())
        writer.enqueue(byteArrayOf(1)); assertArrayEquals(frame(byteArrayOf(1)),writer.next())
    }
}
