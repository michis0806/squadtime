# Validation status

As of 2026-10-17. All checks use synthetic data.

## Local

- TypeScript type-check passed; Cloudflare runtime types were generated with the pinned Wrangler version.
- All 19 Node tests passed: 13 relay tests against real local workerd/D1, four secret-guard/hook tests and two independent pairing-vector tests. Relay coverage includes authentication, group permissions, revocation, concurrent changes, idempotency, expiry, pagination and size limits.
- Host MLS suite: nine tests (three lifecycle and six transaction tests); formatting and Clippy passed on macOS arm64 with Rust 1.90.0. Five additional Rust bridge tests pass, for 14 core Rust tests total. Android arm64 Rust/JNI builds and Apple arm64/x86_64 Simulator builds passed. The actual Rust-linked arm64 iOS device target compiled; physical execution remains unverified. See [mls-state-transactions.md](mls-state-transactions.md).
- Android device-signing/approval proof: all five tests passed, including explicit-consent checks. The tested Android Keystore reports `securityLevel=0` (software); this is not hardware-backed proof. Apple device-signing/approval proof: all eight simulator tests passed with no failures or skips on iPhone 18 Pro, iOS 27, Xcode 27.1; this includes Android export verification. Both native exports passed independent Node/OpenSSL verification, and Android-to-Apple verification passed. Apple-to-Android verification also passed in a targeted Android instrumentation test. These are local runtime results; native CI is build-only. See [native/README.md](../native/README.md), [device-pairing-proof.md](device-pairing-proof.md) and [native CI](../.github/workflows/native.yml).
- The integrated Apple suite passed all 16 tests (eight pairing and eight actual Rust/vault tests), with no failures or skips. Android passed all 13 tests (five pairing and eight actual Rust/JNI/vault tests), including independent-writer and same-instance reentrancy regressions. Separate prepare/verify invocations on each platform proved persistence across app processes: recover the pending inbox, reject consumed MLS ciphertext, acknowledge and reopen an empty inbox. These are process-restart tests, not device reboot or sudden-power-loss tests. The native workflow performs build/compile checks only. The implementation scope and boundaries are in [durable-native-state.md](durable-native-state.md).
- Apple Simulator did not expose file-protection metadata for the database/WAL/SHM files. The protection-setting calls succeeded, but physical file-lock enforcement remains unverified; backup exclusion and Keychain accessibility assertions passed.
- Git-hook and secret-guard tests specifically check staged Git contents, not only the working tree.
- npm reported no known vulnerabilities in the selected dependencies at the time checked. This does not replace source review.

## Cloudflare DEV

The Worker was created in the private Cloudflare environment selected by the owner, with a new D1 database. The exact mapping remains in the ignored local deployment configuration.

The previously recorded live test on 2026-10-17 stored a freshly generated MLS message in D1 over HTTPS, fetched it as a second authorized test device and successfully decrypted it in the Rust process while checking the MLS sender. Missing authentication, foreign group membership, identical retry and device revocation were also checked. The temporary devices, groups and events were then removed.

A subsequent live smoke on 2026-10-17 used `ApplicationReceiver` and passed the health, authentication, membership, actual MLS round-trip, idempotency and revocation checks. Its ephemeral records were removed after the run.

This proves the host/relay round trip, alongside the separate limited native device-approval proof described above. It does **not** prove complete account identity, real Guardian rights, recovery or finished app-wide E2EE. The separate native MLS vault proof passed local Simulator/emulator runtime tests; the Cloudflare transport is not connected to the native proof yet. MLS test identities were mutually authorized in memory in advance. Binding the inner MLS group/sender context to the production account model remains to be implemented.

## Raw receive finding and transaction wrapper

Direct MLS raw receive still consumes a message generation after failed authentication; the same message cannot then be processed again through that call. For application messages, `ApplicationReceiver` addresses this behavior by staging candidate state and committing only after authentication and policy checks. This works under atomic-storage and single-writer assumptions; six additional regression tests bring the MLS suite to nine tests.

The specific raw-receive finding is addressed for this wrapper. A separate native proof now couples the real MLS receive path to an encrypted SQLite checkpoint and inbox item with revision compare-and-swap. Complete application-data integration, proven crash/power-loss recovery, malicious database rollback protection, group-control authorization, recovery and finished native apps remain open. Details and limitations: [crypto-spike.md](crypto-spike.md) and [mls-state-transactions.md](mls-state-transactions.md).
