import CryptoKit
import XCTest
@testable import SquadtimePrototype

final class PrototypeProtocolTests: XCTestCase {
    func testRelayOriginRejectsExternalAndAmbiguousDestinations() throws {
        for value in ["https://192.168.1.2:8789", "http://127.0.0.1:8789", "http://example.com:8789", "http://192.168.1.2:80", "http://user@192.168.1.2:8789", "http://192.168.1.2:8789/path", "http://192.168.1.2:8789?x=1", "http://192.168.1.2:8789#x", "http://192.168.01.2:8789", "http://172.32.1.2:8789"] {
            XCTAssertThrowsError(try origin(value))
        }
        for value in ["http://192.168.1.2:8789", "http://10.1.2.3", "http://172.16.0.1:1024", "http://172.31.255.255:65535"] { XCTAssertEqual(try origin(value), value) }
    }
    func testQRRejectsExpiredUnknownFieldsAndKeySubstitution() throws {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let code = PairCode(v: 1, type: "invite", relay: "http://192.168.1.2:8789", session: String(repeating: "a", count: 64), key: key, hash: String(repeating: "b", count: 64), expiresAt: Int64(Date().timeIntervalSince1970) + 120, label: "Synthetic fox")
        XCTAssertEqual(try PairCode.parse(code.text()).key, key)
        func text(_ object: [String: Any]) throws -> String {
            "squadtime-prototype-v1:" + (try JSONSerialization.data(withJSONObject: object)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let data = try JSONEncoder().encode(code)
        let valid = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var unknown = valid; unknown["admin"] = true
        XCTAssertThrowsError(try PairCode.parse(text(unknown)))
        var expired = valid; expired["expiresAt"] = 1
        XCTAssertThrowsError(try PairCode.parse(text(expired)))
        var malformed = valid; malformed["key"] = Data(repeating: 0, count: 65).base64EncodedString()
        XCTAssertThrowsError(try PairCode.parse(text(malformed)))
        var control = valid; control["label"] = "Synthetic\nfox"
        XCTAssertThrowsError(try PairCode.parse(text(control)))
    }
}
