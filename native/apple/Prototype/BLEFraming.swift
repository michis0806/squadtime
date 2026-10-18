import Foundation

/// A bounded byte stream, independent of ATT packet boundaries.
struct BLEFrameDecoder {
    private(set) var buffered = Data()
    mutating func consume(_ chunk: Data) throws -> [Data] {
        guard !chunk.isEmpty, chunk.count <= 20, buffered.count + chunk.count <= 2115 else { throw PrototypeFailure.invalid }
        buffered.append(chunk)
        var messages: [Data] = []
        while buffered.count >= 4 {
            let length = buffered.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard (1...2092).contains(length) else { throw PrototypeFailure.invalid }
            let end = 4 + Int(length)
            guard buffered.count >= end else { break }
            let payload = Data(buffered.dropFirst(4).prefix(Int(length)))
            buffered.removeFirst(end)
            messages.append(payload)
        }
        return messages
    }
    mutating func clear() { buffered.resetBytes(in: 0..<buffered.count); buffered.removeAll(keepingCapacity: false) }
}

struct BLEFrameQueue {
    private(set) var buffered = Data()
    mutating func append(_ payload: Data) throws {
        guard (1...2092).contains(payload.count), buffered.count + payload.count + 4 <= 65536 else { throw PrototypeFailure.invalid }
        let length = UInt32(payload.count)
        buffered.append(contentsOf: [UInt8(length >> 24), UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)])
        buffered.append(payload)
    }
    var nextChunk: Data { Data(buffered.prefix(20)) }
    mutating func acknowledge(_ count: Int) { buffered.removeFirst(count) }
    mutating func clear() { buffered.resetBytes(in: 0..<buffered.count); buffered.removeAll(keepingCapacity: false) }
}
