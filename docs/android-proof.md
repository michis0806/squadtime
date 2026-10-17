# Android native key-storage and pairing proof

`native/android` is a standalone Kotlin project containing the `pairing` Android
library and the minimal `proof` host (`dev.squadtime.proof`). It has no account
onboarding, guardian policy or finished QR interface. The shared public wire
contract is documented in [device-pairing-proof.md](device-pairing-proof.md).

## Key boundary

`DeviceSigningKey` generates P-256 keys through `AndroidKeyStore` and signs with
`SHA256withECDSA`, using canonical DER signatures. Private keys remain provider
references and are never serialized or exported. Instrumentation checks that
`PrivateKey.encoded == null`, two instances load the same public key for the same
alias, both instances sign valid requests, and deletion followed by creation
produces a different key. Existing signatures remain verifiable with the old
public key after key deletion.

The host disables backup with `allowBackup=false` and `fullBackupContent=false`.
No recovery is implemented. Keys do not require biometric authentication in this
proof. Authentication policy, device locking, rotation and a production key
lifecycle require separate design. This library deliberately restricts aliases
to the synthetic `dev.squadtime.proof.` namespace. Callers must serialize lifecycle
operations per alias across different `DeviceSigningKey` instances; the instance
lock does not provide cross-instance serialization. Tests delete their random test
aliases in `finally` blocks. Public interoperability exports contain only test
IDs, nonces, public keys and signatures, never private keys.

The proof reads the provider's actual `KeyInfo.securityLevel`. An emulator value
such as `TRUSTED_ENVIRONMENT` does not establish physical TEE, StrongBox or
hardware security. Emulator validation does not replace physical-device testing.

## Protocol and checks

The library implements the shared UTF-8 transcripts including trailing newlines.
It validates P-256 curve points, lowercase hex, canonical DER and scalar ranges,
UUID format, version and safe integer timestamps. The JSON adapter rejects
string/number coercion, non-integer number types and extra fields.

`PairingApproval.create` requires an explicit `userConfirmed=true` argument and
rejects `false`. The caller must actually obtain informed consent through its UI;
a Boolean argument alone cannot establish consent. No consent UI exists here.

A recipient needs the exact locally pending request and a separately trusted,
pinned approver public key. An approval's self-declared public key establishes no
trust. The in-memory coordinator consumes pending requests once, only after a
successful check. Invalid signatures and expired approvals do not consume the
pending request. Restart-persistent replay protection, authentic initial pin
verification, account/guardian authorization and MLS binding remain unimplemented.

Instrumentation verifies the independent public Node fixture, transcript bytes,
signatures, mutations of all security-sensitive fields, expiry boundaries,
invalid curve points and DER, untrusted approvers, replay and the real
AndroidKeyStore lifecycle. Tests use an injected historical clock and synthetic
identities; fixture timestamps are already expired in real time.

## Reproduce

Requirements: SDK platform 36, SDK build tools 36.0.0, JDK >=17 and an emulator.
The project pins AGP 9.1.1, its built-in Kotlin 2.2.10, and Gradle 9.3.1 with the
official distribution SHA-256. No separate Kotlin plugin is applied. The
[official AGP compatibility table](https://developer.android.com/build/releases/agp-9-1-0-release-notes)
documents these versions. AndroidX Runner 1.6.2 and JUnit extension 1.2.1 are pinned.
Local SDK paths belong in ignored `local.properties` or `ANDROID_HOME`.

```sh
cd native/android
./gradlew :proof:assembleDebug :proof:assembleDebugAndroidTest --console=plain
ANDROID_SERIAL=emulator-5580 ./gradlew :proof:connectedDebugAndroidTest --console=plain
```

Choose the actual emulator serial explicitly. This host is not a distribution
app. Gradle's connected test task removes test packages afterward; for an
export, explicitly install both APKs and run instrumentation using adb. The
instrumentation creates public synthetic `files/pairing-native-export.json` and
`files/key-security-level.txt` in the host's private directory. Read them with
`adb -s SERIAL exec-out run-as dev.squadtime.proof cat files/FILE` into an ignored
local directory. Private keys remain inside the Keystore.

To verify an export from another native platform, import its public-only fixture
into the host's private `files/pairing-apple-import.json`, then run:

```sh
adb -s SERIAL shell am instrument -w \
  -e class 'dev.squadtime.proof.PairingProofTest#independentFixtureTranscriptsAndSignatures' \
  -e fixtureFile pairing-apple-import.json \
  dev.squadtime.proof.test/androidx.test.runner.AndroidJUnitRunner
```

The fixture schema is identical to the shared Node fixture. The optional filename
argument is test-only and restricted to a simple `pairing-*.json` filename.

## Validation status

Local APK and instrumentation APK builds passed on 2026-10-17. Five connected
instrumentation tests passed with zero failures, errors or skips on the existing
`Medium_Phone_API_36.1` AVD, explicitly selected as `emulator-5580`. Despite its
name, the AVD actually runs Android API 37; `getprop ro.build.version.sdk` was
checked. The final APKs were also explicitly installed and all five tests passed again
through direct `adb shell am instrument -w` after the explicit consent guard and
public-fixture import support were added. The minimal host activity resolved and its launch command succeeded; no visual
foreground UI claim is made because the pre-existing emulator profile remained
behind its system lock screen. No screenshot containing that profile is retained.

`KeyInfo.securityLevel` returned `0` (`SOFTWARE`) on this emulator. The public-only
native fixture was generated and retained for independent verification; its
private signing keys were deleted by test cleanup. Cross-platform export results
are recorded in the shared proof document after independent retrieval. No production E2EE, physical hardware or
recovery claim follows from this proof.

The public Android export passed independent Node/OpenSSL verification and the
Apple Simulator import test. A public Apple export also passed the targeted
Android instrumentation verifier (one additional test, no failures). These
checks prove both signature/transcript interoperability directions using expired
synthetic fixtures; they do not establish the real-world approver trust pin.
