import Foundation
import XCTest
@testable import PairingProof

/// Host automation copies only input.json/output.json. Local secret state never leaves the vault.
@MainActor
final class AdmissionExchangeProofTests: XCTestCase {
    private struct Manifest: Codable { let vaultUUID: UUID; let keyAlias: String; let role: AdmissionRole }
    private struct Input: Decodable {
        let now: Int64?
        let outbox: Data?
        let trustedAdminPublicKey: Data?
        let trustedDevicePublicKey: Data?
        let userConfirmed: Bool?
    }
    private func exchangeDirectory() throws -> URL {
        let documents = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = documents.appendingPathComponent("admission-exchange")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        return directory
    }
    private func storeDirectory(_ id: UUID) throws -> URL {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return support.appendingPathComponent("squadtime-independent-admission/\(id.uuidString)")
    }
    private func input() throws -> Input {
        try JSONDecoder().decode(Input.self, from: Data(contentsOf: exchangeDirectory().appendingPathComponent("input.json")))
    }
    private func manifest() throws -> Manifest {
        try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: exchangeDirectory().appendingPathComponent("local.json")))
    }
    private func save(_ manifest: Manifest) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(manifest).write(to: exchangeDirectory().appendingPathComponent("local.json"), options: [.atomic, .completeFileProtection])
    }
    private func output(_ outbox: AdmissionOutbox, phase: String) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(outbox).write(to: exchangeDirectory().appendingPathComponent("output.json"), options: .atomic)
        print("ADMISSION_PHASE \(phase) PID \(ProcessInfo.processInfo.processIdentifier)")
    }
    private func start(role: AdmissionRole, input: Input) throws -> (Manifest, DeviceKeyStore, DurableAdmission) {
        guard !FileManager.default.fileExists(atPath: try exchangeDirectory().appendingPathComponent("local.json").path) else { throw VaultError.alreadyExists }
        let manifest = Manifest(vaultUUID: UUID(), keyAlias: UUID().uuidString, role: role)
        let key = try DeviceKeyStore(alias: manifest.keyAlias)
        let store = try DurableAdmission.create(directory: storeDirectory(manifest.vaultUUID), id: manifest.vaultUUID,
                                                role: role, nativeKey: key, trustedAdminPublicKey: input.trustedAdminPublicKey)
        try save(manifest)
        return (manifest, key, store)
    }
    private func reopen() throws -> (Manifest, DeviceKeyStore, DurableAdmission) {
        let manifest = try manifest()
        let key = try DeviceKeyStore(alias: manifest.keyAlias)
        return (manifest, key, try DurableAdmission.open(directory: storeDirectory(manifest.vaultUUID), id: manifest.vaultUUID))
    }

    func testOwnerStart() async throws {
        let input = try input()
        let (_, key, store) = try start(role: .owner, input: input)
        let outbox = try await store.ownerStart(nativeKey: key, now: XCTUnwrap(input.now))
        try output(outbox, phase: "ownerStart")
        await store.close()
    }
    func testJoinerStart() async throws {
        let input = try input()
        _ = try XCTUnwrap(input.trustedAdminPublicKey)
        let (_, key, store) = try start(role: .joiner, input: input)
        let outbox = try await store.joinerStart(invitation: XCTUnwrap(input.outbox), nativeKey: key, now: XCTUnwrap(input.now))
        try output(outbox, phase: "joinerStart")
        await store.close()
    }
    func testOwnerAdmit() async throws {
        let input = try input()
        let (_, key, store) = try reopen()
        let outbox = try await store.ownerAdmit(request: XCTUnwrap(input.outbox), trustedDevicePublicKey: XCTUnwrap(input.trustedDevicePublicKey),
                                                nativeKey: key, now: XCTUnwrap(input.now), userConfirmed: input.userConfirmed == true)
        try output(outbox, phase: "ownerAdmit")
        await store.close()
    }
    func testJoinerFinish() async throws {
        let input = try input()
        let (_, _, store) = try reopen()
        let accepted = try await store.join(welcome: XCTUnwrap(input.outbox), now: XCTUnwrap(input.now))
        XCTAssertTrue(accepted.plaintext == AdmissionValidation.expectedProbe)
        try output(await store.outbox(), phase: "joinerFinish")
        await store.close()
    }
    func testResume() async throws {
        _ = try input()
        let (_, _, store) = try reopen()
        try output(await store.outbox(), phase: "resume")
        await store.close()
    }
    func testVerifyInbox() async throws {
        _ = try input()
        let (manifest, _, store) = try reopen()
        let pending = try await store.pendingMessages()
        XCTAssertEqual(pending.count, 1)
        let accepted = try XCTUnwrap(pending.first)
        XCTAssertTrue(accepted.plaintext == AdmissionValidation.expectedProbe)
        let packet = try await store.proofProbePacket()
        do { _ = try await store.receive(packet: packet); XCTFail("Persisted probe replay must fail") }
        catch { XCTAssertEqual(error as? VaultError, .mlsRejected) }
        let retained = try await store.pendingMessages()
        XCTAssertEqual(retained.count, 1)
        try await store.acknowledge(messageID: accepted.id)
        await store.close()
        let reopened = try DurableAdmission.open(directory: storeDirectory(manifest.vaultUUID), id: manifest.vaultUUID)
        let empty = try await reopened.pendingMessages()
        XCTAssertTrue(empty.isEmpty)
        try output(await reopened.outbox(), phase: "verifyInbox")
        await reopened.close()
    }
    func testCleanup() throws {
        _ = try input()
        let manifest = try manifest()
        let key = try DeviceKeyStore(alias: manifest.keyAlias)
        let native = (try? Data(strictHex: key.publicKeyHex())) ?? Data()
        try key.delete()
        try VaultKeyStore(vaultID: manifest.vaultUUID.uuidString.lowercased(), purpose: .admission).delete()
        try FileManager.default.removeItem(at: storeDirectory(manifest.vaultUUID))
        try FileManager.default.removeItem(at: exchangeDirectory().appendingPathComponent("local.json"))
        try output(AdmissionOutbox(kind: "cleaned", outbox: Data(), nativePublicKey: native), phase: "cleanup")
    }
}
