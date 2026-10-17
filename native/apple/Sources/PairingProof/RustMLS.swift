import Foundation
import SquadtimeMLSFFI

public enum VaultError: Error, Equatable {
    case keychain(Int32), missingKey, malformed, authentication, sqlite(Int32)
    case alreadyExists, missingDatabase, staleRevision, inboxFull, unknownMessage
    case mlsRejected, injectedRollback, commitUncertain, requiresReopen
}

/// Synthetic, in-memory fixture. Never serialize the snapshot to an unencrypted file.
public struct MLSFixture: Decodable, Sendable {
    public let snapshot: Data
    public let packets: [Data]
    public let expected: [Data]
}

struct MLSReceived: Decodable {
    let snapshot: Data
    let plaintext: Data
    let senderIndex: UInt32
}

public enum RustMLS {
    public static func fixture() throws -> MLSFixture {
        let result: MLSFixture = try call(["op": "fixture"])
        guard result.snapshot.count <= 8 * 1024 * 1024, result.packets.count == 2,
              result.expected.count == 2 else { throw VaultError.malformed }
        return result
    }

    static func receive(snapshot: Data, packet: Data) throws -> MLSReceived {
        guard snapshot.count <= 8 * 1024 * 1024, packet.count <= 1024 * 1024 else { throw VaultError.malformed }
        let result: MLSReceived = try call(["op": "receive", "snapshot": snapshot.base64EncodedString(),
                                            "packet": packet.base64EncodedString()])
        guard result.snapshot.count <= 8 * 1024 * 1024,
              result.plaintext.count <= 1024 * 1024 else { throw VaultError.malformed }
        return result
    }

    private static func call<T: Decodable>(_ request: [String: String]) throws -> T {
        let input = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
        guard input.count <= 16 * 1024 * 1024 else { throw VaultError.malformed }
        var output: UnsafeMutablePointer<UInt8>?
        var length = 0
        let status = input.withUnsafeBytes { bytes in
            squadtime_mls_call(bytes.bindMemory(to: UInt8.self).baseAddress, input.count, &output, &length)
        }
        defer { if let output { squadtime_mls_free(output, length) } }
        guard status == 0, let output, length > 0, length <= 16 * 1024 * 1024 else { throw VaultError.mlsRejected }
        do { return try JSONDecoder().decode(T.self, from: Data(bytes: output, count: length)) }
        catch { throw VaultError.malformed }
    }
}
