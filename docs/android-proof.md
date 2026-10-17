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
  dev.squadtime.proof.test/dev.squadtime.proof.VaultRestartInstrumentation
```

The fixture schema is identical to the shared Node fixture. The optional filename
argument is test-only and restricted to a simple `pairing-*.json` filename.

## Encrypted MLS vault and native ABI

The additional vault proof calls the actual Rust MLS implementation through
`native/include/squadtime_mls.h`, a bounded C JNI wrapper and Kotlin byte-array
adapter. It does not reimplement MLS in Kotlin. The Rust fixture creates two
synthetic peers and two ciphertext packets in memory; fixture snapshots are
secret local state, never network input or checked-in fixtures. The bridge
accepts at most 16 MiB per JSON input/output. Rust snapshots are capped at 8 MiB
and packets at 1 MiB by the adapter. JNI input copies and Rust-owned outputs are
wiped before release; Kotlin bridge byte arrays are cleared in `finally` blocks.
JSON/base64 processing also creates immutable JVM strings and internal runtime
copies that cannot be reliably erased. This is a development proof, not a claim
of comprehensive secret-memory zeroization.

`MlsVault` uses a separate non-exportable AndroidKeyStore AES-256-GCM key. Its
SQLite database lives under `Context.noBackupFilesDir`. A single AES-GCM payload
contains both the MLS snapshot and pending inbox, authenticated with AAD binding
format version, vault UUID and revision. Each update uses a fresh provider-created
nonce. The SQL row exposes revision, nonce and ciphertext; ciphertext sizes and
filesystem metadata remain visible. SQLite runs in WAL mode with synchronous
FULL. Plaintext snapshots and messages are never passed as SQL values or written
to files. The proof host still disables backup.

Android limits a vault snapshot to 700 KiB, the serialized encrypted payload to
1 MiB before encryption and the pending inbox to 128 entries. The smaller vault
bounds keep BLOB reads below Android CursorWindow limits; they are stricter than
the shared Rust bridge limits. Oversized creates reject before creating a database
or key. A receive that would exceed a bound rejects before commit and releases no
plaintext; the previously committed state remains authoritative.

A receive loads the trusted local snapshot, stages Rust MLS processing, and then
commits the advanced snapshot and pending plaintext inbox together in one SQL
transaction with a revision compare-and-swap. Only after commit does it return
plaintext to its caller. Reopening can recover pending messages without running
MLS a second time. Acknowledgement removes an inbox item in another atomic CAS
transaction. Independent connections reject stale revisions, including a competing
commit interleaved after MLS processing and immediately before SQL CAS. Each
operation captures its expected revision before loading state; a same-instance
reentrant callback that commits another receive makes the outer operation reject
instead of overwriting the inner state or inbox. A dedicated regression verifies
both packets remain consumed and both inbox entries survive reopening.

An existing database with a missing key fails closed; opening never creates a
replacement. Wrong keys, ciphertext/nonce changes and revision changes reject.
Whole-database rollback by a malicious party remains unsolved: AAD plus revision
CAS does not establish an external monotonic anchor. Coordination of initial
creation is process-local; this proof does not establish cross-process concurrent
creation guarantees. Callers must manage connection closure and lifetime.

`VaultFault.BEFORE_COMMIT`, `AFTER_COMMIT_UNCERTAIN` and `testBeforeCas` are explicit
proof-only fault/interleaving hooks. Before-commit faults roll back. After-commit
uncertainty returns no plaintext and requires reopening, which recovers the durable
inbox and rejects packet replay. These hooks test application behavior; they do
not simulate a real disk failure, kernel crash or power loss.

The JNI build uses the installed NDK 29.0.14206865 compiler directly, API 31 arm64,
and explicit 16 KiB ELF page alignment. It requires the separately built Rust
artifact at `.local/native/android/arm64-v8a/libsquadtime_mls_spike.so`; absence is a
build failure, not a skipped native test. `pairing:buildMlsJni` packages the tiny
JNI `.so` and the actual Rust `.so` into the proof host. No native binaries or
secret snapshots are checked into the repository.

## Cross-process restart proof

The test-only instrumentation runner delegates to AndroidJUnitRunner by default.
With `restartProof=true`, it instead requires one of two explicit phases. `prepare`
creates an encrypted vault and commits one MLS receive. It writes a marker
containing only a vault UUID, public ciphertext packet and a plaintext digest.
After the app process is force-stopped, `verify` reopens the same vault/key, checks
the pending plaintext by digest, rejects packet replay, acknowledges the message
and removes its synthetic vault, key and marker. Missing or invalid phases and
missing prepared state return `restartProof=rejected`; they never silently pass.

```sh
adb -s SERIAL shell am instrument -w -e restartProof true -e phase prepare \
  dev.squadtime.proof.test/dev.squadtime.proof.VaultRestartInstrumentation
adb -s SERIAL shell am force-stop dev.squadtime.proof
adb -s SERIAL shell am instrument -w -e restartProof true -e phase verify \
  dev.squadtime.proof.test/dev.squadtime.proof.VaultRestartInstrumentation
```

Both runs must report `restartProof=passed` and instrumentation result code `-1`.
This is an actual process restart proof when executed, not a power-loss durability
or full rollback/recovery guarantee. The two phases must use the same installed
host data; Gradle connected-test cleanup can remove it between runs.

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


### Rust-backed vault validation (2026-10-17)

The final host and test APKs built successfully with the actual Rust shared
library and the JNI wrapper. Direct instrumentation on `emulator-5580` (API 37,
`arm64-v8a`) passed **13 tests**, with zero failures: all five existing pairing
tests and eight additional real-Rust vault tests. Coverage includes authenticated
receive and retry after tampering, replay rejection after reopening, durable
pending inbox and acknowledgement, pre-commit rollback, post-commit uncertainty
without plaintext release, independent-connection stale CAS, same-instance
reentrant CAS, missing/wrong keys, ciphertext/revision/nonce tampering and
oversized creation without creating a database or key. Each opened vault
connection checked actual `journal_mode=wal` and `synchronous=2` (FULL).

The explicit restart-mode negative check rejected a missing phase with result
code `0`. Preparation passed with process ID **4919** and result code `-1`.
After `am force-stop dev.squadtime.proof`, verification passed in a distinct
process, ID **4953**, with result code `-1`. Verification recovered the pending
message by digest, rejected the already-consumed MLS ciphertext, acknowledged it,
reopened to an empty inbox, and deleted its synthetic vault, key and public marker.
This demonstrates process-restart persistence, not power-loss or malicious-disk
rollback protection.

ELF inspection confirmed the JNI library's LOAD segments have alignment `0x4000`
(16 KiB). No snapshots or private keys were exported. The scoped test and host
packages were uninstalled and the task-owned emulator was shut down after
validation; all generated host build outputs remain ignored.
