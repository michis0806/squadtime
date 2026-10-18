import Foundation
import XCTest
@testable import SquadtimePrototype

final class BLEFramingTests: XCTestCase {
    func testFramesSurviveEveryChunkBoundaryWithoutInterleaving() throws {
        let first = Data("{\"type\":\"first\",\"padding\":\"abcdefghijklmnopqrstuvw\"}".utf8)
        let second = Data("{\"type\":\"second\"}".utf8)
        var queue = BLEFrameQueue(); try queue.append(first); try queue.append(second)
        let stream = queue.buffered
        for size in 1...20 {
            var decoder = BLEFrameDecoder(); var received: [Data] = []
            for start in stride(from: 0, to: stream.count, by: size) {
                received += try decoder.consume(Data(stream.dropFirst(start).prefix(size)))
            }
            XCTAssertEqual(received, [first, second]); XCTAssertTrue(decoder.buffered.isEmpty)
        }
    }
    func testInvalidLengthEncodingAndOversizedChunkFailClosed() throws {
        for prefix: [UInt8] in [[0,0,0,0], [0,0,32,1], [255,255,255,255]] {
            var decoder = BLEFrameDecoder()
            XCTAssertThrowsError(try decoder.consume(Data(prefix)))
        }
        var decoder = BLEFrameDecoder()
        XCTAssertThrowsError(try decoder.consume(Data(repeating: 1, count: 21)))
        XCTAssertEqual(try decoder.consume(Data([0,0,0,1,255])), [Data([255])])
        decoder.clear(); XCTAssertTrue(decoder.buffered.isEmpty)
    }
    func testMaximumFrameAndAdjacentFrameFitBoundedDecoder() throws {
        let maximum = Data(("{\"p\":\"" + String(repeating: "a", count: 2084) + "\"}").utf8)
        XCTAssertEqual(maximum.count, 2092)
        let next = Data("{\"n\":1}".utf8)
        var queue = BLEFrameQueue(); try queue.append(maximum); try queue.append(next)
        var decoder = BLEFrameDecoder(); var received: [Data] = []
        while !queue.buffered.isEmpty {
            let chunk = queue.nextChunk; received += try decoder.consume(chunk); queue.acknowledge(chunk.count)
        }
        XCTAssertEqual(received, [maximum, next])
    }
    func testOutgoingCapacityAndResetDoNotReleaseUnqueuedBytes() throws {
        let payload = Data(("{\"p\":\"" + String(repeating: "a", count: 2084) + "\"}").utf8)
        var queue = BLEFrameQueue()
        for _ in 0..<31 { try queue.append(payload) }
        let before = queue.buffered
        XCTAssertThrowsError(try queue.append(payload)); XCTAssertEqual(queue.buffered, before)
        queue.clear(); XCTAssertTrue(queue.buffered.isEmpty)
        XCTAssertThrowsError(try queue.append(Data()))
    }
}
