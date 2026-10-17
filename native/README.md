# Native security prototypes

Apple and Android have implemented the same limited device-approval proof, with simulator and emulator test evidence. Specification: [device-pairing-proof.md](../docs/device-pairing-proof.md). Shared public test vector: `fixtures/pairing-v1.json`.

This remains a prototype, not a finished app or a complete native E2EE integration. The native signing/Keychain/Keystore layer is separate from the Rust MLS prototype. Android reports `securityLevel=0` (software-backed) in the tested environment; this is not hardware-backed proof.

- `apple/`: Swift, Security/CryptoKit, iOS Simulator tests.
- `android/`: Kotlin, AndroidKeyStore, emulator instrumentation.
- Private keys are not stored in the source tree or test vectors.

The local Apple suite passed all eight tests with no failures or skips on an iPhone 18 Pro simulator using iOS 27 and Xcode 27.1; this includes Android export verification. Both native exports also passed independent Node/OpenSSL verification. Android-to-Apple verification passed. Apple-to-Android verification also passed in a targeted Android instrumentation test. These runtime results are local; [native CI](../.github/workflows/native.yml) performs build-only checks (Apple Xcode 26.3 on macOS 15, Android JDK 17 on Ubuntu 24.04).

## Real MLS and durable state proof

The native proof also builds the shared Rust MLS library and connects its C/JNI bridge to an encrypted SQLite vault on Apple and Android. For synthetic two-peer fixtures, the vault receives a real MLS application packet, authenticates it through the Rust core, and commits the updated MLS snapshot together with the plaintext inbox item in one encrypted row. AES-GCM keys are protected by Keychain on Apple and AndroidKeyStore on Android. Revision compare-and-swap rejects stale vault writers. If a commit reports uncertain completion, callers must reopen the vault and inspect pending inbox items before retrying or presenting data.

This is limited receive-path evidence, not a production application or an app-wide MLS integration. The actual P-256 device-approval proof is not bound to MLS identity; group control sends and authorized membership changes, recovery, rollback protection against a malicious/restored database, real-hardware assurance and power-loss durability remain open. Build-only CI does not execute the vault tests. Current bridge and vault runtime status is tracked in [validation.md](../docs/validation.md); vault design and boundaries are in [durable-native-state.md](../docs/durable-native-state.md).
