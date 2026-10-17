# Apple native key storage and pairing proof

`native/apple` contains a reusable Swift library (`PairingProof`) and a minimal UIKit XCTest host. This is a development proof with synthetic data, not a finished app, product onboarding, or approval to use real family or child data.

## Keys

`DeviceKeyStore` creates P-256 keys through Apple's Security framework and stores them in Keychain under `squadtime.proof.<alias>`. Its API exposes only public keys, signing, and scoped deletion. Private keys are never exported or logged. Each operation loads a Keychain reference; a new store instance with the same alias reuses the existing key. Signing fails after deletion, and subsequent creation produces a new public key.

Physical builds require `kSecAttrTokenIDSecureEnclave` and `.privateKeyUsage` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. An existing key without the Secure Enclave attribute is rejected. Hardware creation failure does not trigger a software fallback. Only `targetEnvironment(simulator)` enables software keys, explicitly identified as `simulatorSoftware`, with the same Keychain accessibility class. Simulator execution proves neither hardware nonexportability nor lock, backup, or recovery behavior. The native API exports only public keys in this mode too. Callers must serialize lifecycle operations for the same alias.

References: [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [Keychain: WhenUnlockedThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly). This accessibility class restricts access to the unlocked device and prevents migration to another device; it is not a recovery solution.

## Pairing

The library implements the shared [pairing proof v1](device-pairing-proof.md): exact UTF-8 transcripts, uncompressed X9.63 P-256 public keys, DER ECDSA/SHA-256 signatures, and SHA-256 binding of approval to request. UUIDs and hexadecimal representations must be canonical. A new client generates a random 32-byte challenge and signs the request. The approving client verifies the self-signature and validity window and requires `userConfirmed: true`. The future app must implement deliberate user confirmation itself.

`PairingCoordinator` accepts only its own pending request and a separately pinned trusted approver public key. The key carried by an approval does not establish authority. Success consumes the pending request once; failed attempts preserve it. The actor serializes consumption within that instance. This provides no persistent replay protection across restarts, complete QR ceremony, device identity administration, trust-anchor bootstrap, or binding to MLS keys or membership. Time is injected for repeatable tests; trusted time and clock rollback remain unresolved.

## Run locally

Requirements: Xcode with an iOS Simulator and XcodeGen. The checked-in project specification uses local ad hoc signing and explicit test-host Keychain entitlements; no developer account or Store changes are required. Disabling signing still allows compile-only CI checks but prevents this host from accessing Keychain at runtime (`errSecMissingEntitlement`, -34018). The generated Xcode project and build artifacts are ignored.

```sh
xcodegen generate --spec native/apple/project.yml
xcodebuild test \
  -project native/apple/SquadtimeAppleProof.xcodeproj \
  -scheme PairingProof \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro' \
  -derivedDataPath native/apple/build \
  -parallel-testing-enabled NO
```

The public `native/fixtures/pairing-v1.json` is copied into the test bundle. Tests compare transcripts and verify both signatures independently of their producer. An additional test creates an already expired synthetic request and approval as `Documents/pairing-native-export.json` in the Simulator container of `dev.squadtime.proof.host`. This public-only file contains public keys, nonces, signatures, and timestamps, never private keys or user data. All test keys are removed with scoped deletion at test completion. The export is for independent interoperability verification only.

## Evidence and limits

On 2026-10-17, Xcode 27.1 ran all eight tests successfully on the iPhone 18 Pro simulator with iOS 27.0: zero failures and zero skips. This includes verification of the public Android-native request and approval imported as `Documents/pairing-android-import.json`, as well as the shared fixture and Apple-native public export. The optional Android import test skips when that file is absent; copy a public export from the Android proof into the test host's Documents directory to reproduce that direction. The fixture must never include private keys. To run only that direction, add `-only-testing:PairingProofTests/PairingProofTests/testAndroidNativeFixtureImport` to the command above.

The physical-device conditional branch also compiled successfully with a generic iOS destination and `CODE_SIGNING_ALLOWED=NO`; this is a compile check, not hardware execution.

Simulator tests cover Keychain reuse across new store instances, signature verification, tamper rejection, deletion and recreation, accessibility attributes, explicit approval, pinned authority, validity windows, exact request binding, and single-use consumption. A new store object does not prove persistence across a process restart. Physical iPhone and Secure Enclave validation, actual device locking, process restart, recovery, native product validation, and production E2EE remain open.
