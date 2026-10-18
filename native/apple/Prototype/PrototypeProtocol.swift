import CryptoKit
import Foundation
import PairingProof

func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
func nativeBytes(_ key: DeviceKeyStore) throws -> Data {
    let text = try key.publicKeyHex()
    return Data(stride(from: 0, to: text.count, by: 2).compactMap { i in
        let start = text.index(text.startIndex, offsetBy: i)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)
    })
}
func origin(_ text: String) throws -> String {
    guard let c = URLComponents(string: text), c.scheme == "http", c.user == nil, c.password == nil,
          c.path.isEmpty, c.query == nil, c.fragment == nil, let host = c.host,
          c.port == nil || (1024...65535).contains(c.port!), let url = c.url, url.absoluteString == text else { throw PrototypeFailure.invalid }
    let parts = host.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { throw PrototypeFailure.invalid }
    let values = parts.compactMap { Int($0) }
    guard values.count == 4, zip(parts, values).allSatisfy({ String($0.1) == $0.0 && (0...255).contains($0.1) }),
          values[0] == 10 || (values[0] == 172 && (16...31).contains(values[1])) || (values[0] == 192 && values[1] == 168) else { throw PrototypeFailure.invalid }
    return text
}
struct PairCode: Codable, Sendable {
    let v: Int; let type: String; let relay: String; let session: String; let key: Data; let hash: String; let expiresAt: Int64; let label: String
    func text() throws -> String { "squadtime-prototype-v1:" + (try JSONEncoder().encode(self)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    static func parse(_ text: String) throws -> PairCode {
        let prefix = "squadtime-prototype-v1:"
        guard text.utf8.count <= 2048, text.hasPrefix(prefix) else { throw PrototypeFailure.invalid }
        let encoded = String(text.dropFirst(prefix.count))
        var base = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base += String(repeating: "=", count: (4 - base.count % 4) % 4)
        guard let data = Data(base64Encoded: base), data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == encoded,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == Set(["v","type","relay","session","key","hash","expiresAt","label"]) else { throw PrototypeFailure.invalid }
        let code = try JSONDecoder().decode(Self.self, from: data)
        guard code.v == 1, ["invite", "request"].contains(code.type), code.session.isHash, code.hash.isHash,
              code.key.count == 65, (try? P256.Signing.PublicKey(x963Representation: code.key)) != nil,
              code.expiresAt > Int64(Date().timeIntervalSince1970), code.expiresAt <= Int64(Date().timeIntervalSince1970) + 300,
              code.label.unicodeScalars.count <= 32, !code.label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              (object["key"] as? String) == code.key.base64EncodedString() else { throw PrototypeFailure.invalid }
        _ = try origin(code.relay); return code
    }
}
extension String { var isHash: Bool { count == 64 && utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } } }
struct Receipt: Codable, Sendable {
    let v: Int; let session: String; let invitationHash: String; let requestHash: String; let welcomeHash: String; let signature: Data
    var transcript: Data { Data("squadtime-prototype-receipt-v1\n\(session)\n\(invitationHash)\n\(requestHash)\n\(welcomeHash)\n".utf8) }
}
private final class NoRedirect: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}
actor PrototypeRelay {
    private let delegate = NoRedirect()
    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral; c.timeoutIntervalForRequest = 8; c.timeoutIntervalForResource = 12
        c.httpCookieStorage = nil; c.urlCache = nil
        return URLSession(configuration: c, delegate: delegate, delegateQueue: nil)
    }()
    func exchange(relay: String, id: String, kind: String, put: Data? = nil) async throws -> Data? {
        _ = try origin(relay)
        guard id.isHash, ["invitation", "request", "welcome", "receipt"].contains(kind), let url = URL(string: "\(relay)/v1/sessions/\(id)/\(kind)") else { throw PrototypeFailure.invalid }
        var request = URLRequest(url: url); request.httpMethod = put == nil ? "GET" : "PUT"
        if let put { request.httpBody = try JSONEncoder().encode(["outbox": put.base64EncodedString()]); request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        // Stream with a hard byte limit; never let an untrusted relay buffer an unbounded body.
        let (stream, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse else { throw PrototypeFailure.unavailable }
        if response.statusCode == 404 && put == nil { return nil }
        guard [200, 201].contains(response.statusCode) else { throw PrototypeFailure.unavailable }
        var body = Data(); for try await byte in stream { guard body.count < 200_000 else { throw PrototypeFailure.invalid }; body.append(byte) }
        if put != nil { return put }
        let object = try JSONDecoder().decode([String: String].self, from: body)
        guard object.count == 1, let encoded = object["outbox"], let data = Data(base64Encoded: encoded), data.base64EncodedString() == encoded, data.count <= 128 * 1024 else { throw PrototypeFailure.invalid }
        return data
    }
}
