import CryptoKit
import Foundation
import XCTest
@testable import PairingProof

/// Run prepare and verify as separate targeted xcodebuild invocations with host termination between.
/// This target is intentionally outside the ordinary test suite; verify never skips a missing phase.
@MainActor
final class RestartProofTests: XCTestCase {
    private struct Marker: Codable { let vaultID: UUID; let packet: Data }

    private func paths(id: UUID? = nil) throws -> (marker: URL, directory: URL) {
        let documents = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                   appropriateFor: nil, create: true)
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: true)
        return (documents.appendingPathComponent("vault-restart-public-marker.json"),
                support.appendingPathComponent("squadtime-process-restart/\(id?.uuidString ?? "unused")"))
    }

    func testPrepare() async throws {
        let markerURL = try paths().marker
        // Clean only a previous unfinished synthetic proof, never another vault.
        if FileManager.default.fileExists(atPath: markerURL.path) {
            let old = try JSONDecoder().decode(Marker.self, from: Data(contentsOf: markerURL))
            try? VaultKeyStore(vaultID: old.vaultID.uuidString.lowercased()).delete()
            try? FileManager.default.removeItem(at: paths(id: old.vaultID).directory)
            try FileManager.default.removeItem(at: markerURL)
        }
        let fixture = try RustMLS.fixture()
        let marker = Marker(vaultID: UUID(), packet: fixture.packets[0])
        let directory = try paths(id: marker.vaultID).directory
        let vault = try DurableVault.create(directory: directory, vaultID: marker.vaultID, initialSnapshot: fixture.snapshot)
        let accepted = try await vault.receive(packet: marker.packet)
        XCTAssertTrue(accepted.plaintext == fixture.expected[0])
        let pending = try await vault.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        // Public ID and MLS ciphertext packet only. Snapshot and plaintext stay inside the vault.
        try JSONEncoder().encode(marker).write(to: markerURL, options: [.atomic, .completeFileProtection])
        // Deliberately do not close here: the test-host process must end before verify.
    }

    func testVerifyAfterProcessRestart() async throws {
        let markerURL = try paths().marker
        // Missing prepare is a failure, not a skipped test or an automatic replacement fixture.
        let marker = try JSONDecoder().decode(Marker.self, from: Data(contentsOf: markerURL))
        let directory = try paths(id: marker.vaultID).directory
        defer {
            try? VaultKeyStore(vaultID: marker.vaultID.uuidString.lowercased()).delete()
            try? FileManager.default.removeItem(at: directory)
            try? FileManager.default.removeItem(at: markerURL)
        }
        let vault = try DurableVault.open(directory: directory, vaultID: marker.vaultID)
        let pending = try await vault.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.id, Data(SHA256.hash(data: marker.packet)).hex)
        do {
            _ = try await vault.receive(packet: marker.packet)
            XCTFail("A consumed MLS packet must be rejected after process restart")
        } catch { XCTAssertEqual(error as? VaultError, .mlsRejected) }
        let event = try XCTUnwrap(pending.first)
        try await vault.acknowledge(messageID: event.id)
        await vault.close()
        let final = try DurableVault.open(directory: directory, vaultID: marker.vaultID)
        let remaining = try await final.pendingMessages()
        XCTAssertTrue(remaining.isEmpty)
        await final.close()
    }
}
