# Durable native MLS state proof

Status: development proof with passing native runtime tests and separate process-restart checks on Apple Simulator and Android emulator. The implementation connects the shared Rust MLS receive bridge to encrypted SQLite vaults on Apple and Android. It uses synthetic two-peer fixtures and tests the application-message receive path only. It is not a production app, production E2EE, or proof of power-loss durability.

## Receive and commit flow

The native adapter loads a trusted local MLS snapshot and its revision, calls the Rust `receive` operation, then commits the returned candidate snapshot and the authenticated inbox item together. No accepted plaintext is returned to the app before the commit succeeds. The inbox is recoverable after reopening the vault; acknowledgement removes an item through another revision-checked commit. Delivery is at least once until acknowledgement, so application must be idempotent.

Each vault stores one encrypted payload containing both the MLS snapshot and its pending inbox. Apple uses AES-GCM through CryptoKit and binds the vault ID and revision as authenticated additional data. Its random AES wrapping key is stored in Keychain as device-only, available when unlocked; it is not a Secure Enclave AES key. Android uses AES/GCM and an AES key in AndroidKeyStore; the earlier signing-key proof in the tested environment reported software security level, so hardware-backed protection is not established.

Writers update only the expected revision. Apple uses SQLite compare-and-swap; Android uses a conditional revision update in a SQLite transaction. A stale writer is rejected. If a commit outcome is uncertain, the current instance must not continue from cached state: reopen the vault, authenticate and load the stored checkpoint, then inspect the pending inbox before retrying or showing the event.

## What this demonstrates

The shared Rust FFI performs actual MLS receive/authentication for synthetic two-peer packets. The native wrapper stores its next snapshot and inbox together, protects the row with authenticated encryption, rejects stale revisions, and provides reopen and inbox-acknowledgement operations. It demonstrates one bounded receive flow through the same Rust MLS core from Apple and Android native code.

Validation state is recorded in [validation.md](validation.md). The bridge protocol and its input bounds are described in [native-mls-bridge.md](native-mls-bridge.md). The standalone MLS staging behavior is described in [mls-state-transactions.md](mls-state-transactions.md). `node scripts/build-native-mls.mjs android`, `apple-simulator` and `apple-device` build the selected Rust target; generated artifacts are ignored. Native CI prepares the Rust bridge and compiles the platform proof projects but does not run vault tests.

## Boundaries and open work

- The two-peer fixture is synthetic. The P-256 device-approval proof is not yet bound to an MLS credential or group membership.
- The bridge rejects MLS control traffic. Authorized group creation, sends, membership changes and their application side effects need a reviewed transaction path.
- Guardian policy, user identity, onboarding, recovery and key lifecycle are not implemented by this proof. Vault/key creation requires a single provisioning owner; atomic cross-process key provisioning is not established.
- SQLite row encryption does not stop deletion, database replacement, restoration of an older valid encrypted row, or a malicious rollback. Revision CAS coordinates writers that share the same current database; it is not a trusted monotonic counter across restore or devices.
- Unit/instrumentation fault injection is not physical power-loss testing. No device reboot/power interruption claim follows unless separately validated.
- The proof is not the complete native application, production secure storage, or app-wide end-to-end encryption. Production integration, backup semantics, cross-process coordination and independent security review remain open.

## Build prerequisites and memory boundary

Builds use the pinned Rust toolchain and Cargo lockfile. Android currently targets
`arm64-v8a`, API 31 or later, with NDK `29.0.14206865`; both JNI and Rust libraries
use 16 KiB ELF load alignment. Apple Simulator builds contain arm64 and x86_64;
the device archive is arm64. The pinned AWS-LC dependency required CMake and
`bindgen-cli 0.72.1` for the Apple cross-build in this environment. Install the
latter with `cargo install bindgen-cli --version 0.72.1 --locked`; the build helper
expects `cargo`, `rustup`, `cmake` and `bindgen` on PATH. No generated native
archives, private snapshots or platform keys belong in Git.

Snapshot contents and decrypted inbox items necessarily exist in application
memory while processed. Rust and JNI clear selected owned buffers; Swift and JVM
serialization create managed copies whose complete erasure is not guaranteed.
Keychain accessibility governs key retrieval and file protection governs disk
access; neither establishes immediate erasure of already loaded keys or data when
the device locks. Lifecycle eviction and physical-device validation remain open.

The complete RustSec advisory-tree index was checked on 2026-10-17 for newly
introduced `base64ct`, `serde_json`, `itoa` and `zmij`; it contained no advisory
entries for those packages. This is a package-name advisory review, not a full
transitive dependency audit. Source: [RustSec advisory database](https://github.com/RustSec/advisory-db).
