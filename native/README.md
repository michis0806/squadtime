# Native security prototypes

Apple and Android have implemented the same limited device-approval proof, with simulator and emulator test evidence. Specification: [device-pairing-proof.md](../docs/device-pairing-proof.md). Shared public test vector: `fixtures/pairing-v1.json`.

This remains a prototype, not a finished app or a complete native E2EE integration. The original pairing v1 proof remains available; a separate local binding proof connects native signing to actual Rust MLS admission. Android reports `securityLevel=0` (software-backed) in the tested environment; this is not hardware-backed proof.

- `apple/`: Swift, Security/CryptoKit, iOS Simulator tests.
- `android/`: Kotlin, AndroidKeyStore, emulator instrumentation.
- Private keys are not stored in the source tree or test vectors.

The local Apple suite passed all eight tests with no failures or skips on an iPhone 18 Pro simulator using iOS 27 and Xcode 27.1; this includes Android export verification. Both native exports also passed independent Node/OpenSSL verification. Android-to-Apple verification passed. Apple-to-Android verification also passed in a targeted Android instrumentation test. These runtime results are local; [native CI](../.github/workflows/native.yml) performs build-only checks (Apple Xcode 26.3 on macOS 15, Android JDK 17 on Ubuntu 24.04).

## Real MLS and durable state proof

The native proof also builds the shared Rust MLS library and connects its C/JNI bridge to an encrypted SQLite vault on Apple and Android. For synthetic two-peer fixtures, the vault receives a real MLS application packet, authenticates it through the Rust core, and commits the updated MLS snapshot together with the plaintext inbox item in one encrypted row. AES-GCM keys are protected by Keychain on Apple and AndroidKeyStore on Android. Revision compare-and-swap rejects stale vault writers. If a commit reports uncertain completion, callers must reopen the vault and inspect pending inbox items before retrying or presenting data.

This is limited proof, not a production application or app-wide MLS integration. The earlier [same-process binding proof](../docs/mls-device-binding.md) is preserved. The newer [independent admission proof](../docs/independent-admission.md) keeps administrator and joining-client secret state separate and exercises public-envelope exchange via local file transport between independent app processes using pre-provisioned test pins. Its encrypted row persists role-local MLS state, the exact resumable public outbox, and pending inbox data under revision compare-and-swap. Apple and Android runtime suites passed (30 and 27 tests respectively); both cross-platform directions also passed the separate-process exchange harness. Cloudflare onboarding/transport, account and Guardian authority, group control sends and general membership changes, recovery, malicious database rollback protection, real-hardware assurance and power-loss durability remain open. Build-only CI does not execute these runtime tests. See [validation.md](../docs/validation.md), [durable-native-state.md](../docs/durable-native-state.md), and [independent-admission.md](../docs/independent-admission.md).

## Local MLS admission binding

The earlier same-process integration suites passed 23 Apple Simulator tests and 19 Android emulator tests, without failures or skips. They include native P-256 approval of actual group/MLS identity/KeyPackage context, real Add/Welcome processing and subsequent encrypted-vault receive. Both public enrollment exports passed independent Node/OpenSSL verification; `fixtures/enrollment-v1.json` is the public Android vector. That legacy proof remains documented in [mls-device-binding.md](../docs/mls-device-binding.md). The successor independent admission proof has separate current counts and limits in [independent-admission.md](../docs/independent-admission.md) and [validation.md](../docs/validation.md).

## Independent admission proof

Rust has 24 passing tests for the current implementation. The Apple Simulator suite passed 30 tests and the Android emulator suite passed 27 tests. The separate-process harness uses independent administrator/joiner secret state, encrypted role-local rows, revision CAS, exact outbox resume, and public envelope transport with pre-provisioned test pins. A separate harness completed both Apple-to-Android and Android-to-Apple exchanges across 22 fresh-process phases, including exact outbox resume, delayed Welcome, persisted inbox, replay rejection, acknowledgement and cleanup. Both public exports passed independent Node/OpenSSL verification; `fixtures/admission-v1.json` contains the public Apple-administrator/Android-joiner vector.
