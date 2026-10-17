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

The complete Rust-linked library, including the physical-device Secure Enclave branch, also compiled successfully with a generic iOS destination and `CODE_SIGNING_ALLOWED=NO`; this is a compile check, not hardware execution.

Simulator tests cover Keychain reuse across new store instances, signature verification, tamper rejection, deletion and recreation, accessibility attributes, explicit approval, pinned authority, validity windows, exact request binding, and single-use consumption. A new store object does not prove persistence across a process restart. Physical iPhone and Secure Enclave validation, actual device locking, signing-key process-restart validation, recovery, native product validation, and production E2EE remain open. The separate encrypted-vault restart evidence below has a narrower scope.

## Encrypted durable MLS vault

`DurableVault` is a local development proof that calls the actual Rust MLS static library through `native/include/squadtime_mls.h`; it does not replace MLS with a mock. Build the ignored local archive before generating and testing the Xcode project:

```sh
node scripts/build-native-mls.mjs apple-simulator
xcodegen generate --spec native/apple/project.yml
```

The project explicitly fails if its platform's archive is missing. Simulator and physical-device archives are separate (`.local/native/apple/iphonesimulator/` and `iphoneos/`). No private snapshot, native binary, or local database belongs in Git. The C wrapper holds request and result JSON only in memory, copies the result, and releases the exact returned allocation with the bridge's free function. Errors expose status categories rather than secret payloads.

The vault stores one SQLite row containing a revision and an AES-256-GCM encrypted whole payload `{snapshot, inbox}`. Associated data binds the format version, caller's vault ID, and revision. The random AES key is a separate Keychain generic-password item under `squadtime.proof.vault`, with `WhenUnlockedThisDeviceOnly` accessibility and synchronization disabled. This AES key is used in process memory; it is not an AES Secure Enclave key. An existing database with a missing key fails closed. Opening never generates replacement keys or resets MLS state. Creation never overwrites an existing database, including one left incomplete by a failed initialization.

Each vault actor owns an independent SQLite connection. It verifies WAL mode, `synchronous=FULL`, `fullfsync=ON`, and `checkpoint_fullfsync=ON`. A receive first stages the Rust MLS result in memory, then uses `BEGIN IMMEDIATE` and a revision compare-and-swap to commit the new encrypted snapshot and accepted inbox event in one row update. Display data is returned only after successful commit. Stale writers fail and require reopening. Before-commit fault injection rolls back without consuming the packet. After-commit uncertainty returns no plaintext and poisons the instance; reopening reconciles the durable inbox and consumed MLS state. Acknowledgement removes an inbox item in another encrypted atomic revision update. Delivery remains at least once until acknowledgement, not exactly-once UI rendering.

The inbox is bounded to 32 pending messages and 2 MiB of plaintext in aggregate; a caller may select a smaller count limit. A full inbox rejects a packet without consuming its MLS state. MLS snapshot size is bounded to 8 MiB and packet/plaintext size to 1 MiB. The dedicated vault directory, database, WAL, and shared-memory sidecar are excluded from backup and assigned complete file protection. SQLite receives only ciphertext and public row metadata. Tests inspect files in memory for accidental raw snapshot/base64 snapshot/plaintext persistence; they never write a decrypted snapshot or dump database bytes to logs.

References: [SQLite WAL and synchronous behavior](https://www.sqlite.org/wal.html), [SQLite durability pragmas](https://www.sqlite.org/pragma.html), [Apple complete file protection](https://developer.apple.com/documentation/foundation/fileprotectiontype/complete), [Apple backup exclusion](https://developer.apple.com/documentation/foundation/urlresourcevalues/isexcludedfrombackup).

This is not a claim of power-loss validation, secure memory zeroization, tamper-proof hardware counters, recovery, or rollback resistance against replacement of the entire database with an older valid copy. Revision CAS prevents concurrent lost updates; it is not an external monotonic trust anchor. The tested iOS 27 Simulator accepted complete-protection attribute setters but returned no Data Protection metadata for the database or sidecars. Simulator tests therefore cannot verify that attribute or real device-lock enforcement; the physical test branch requires the reported protection class to be complete. Backup exclusion flags, encrypted bytes, and Keychain accessibility metadata are checked on Simulator. Closing a vault releases its SQLite connection but does not promise immediate wiping or lock-triggered eviction of the retained Swift key or payload; their lifetime follows the actor and runtime. The caller supplies trusted local snapshots and vault IDs; remote bootstrap, account authorization, MLS membership lifecycle, and production key management remain outside this proof.

## Separate process-restart proof

The `VaultRestartProof` scheme is intentionally separate from the ordinary suite. Run its prepare and verify phases as separate test invocations, terminating the host between them:

```sh
xcodebuild test -project native/apple/SquadtimeAppleProof.xcodeproj \
  -scheme VaultRestartProof -destination 'platform=iOS Simulator,name=iPhone 18 Pro' \
  -derivedDataPath native/apple/build -parallel-testing-enabled NO \
  -only-testing:VaultRestartProofTests/RestartProofTests/testPrepare
# Terminate the dev.squadtime.proof.host test host before the next invocation.
xcodebuild test -project native/apple/SquadtimeAppleProof.xcodeproj \
  -scheme VaultRestartProof -destination 'platform=iOS Simulator,name=iPhone 18 Pro' \
  -derivedDataPath native/apple/build -parallel-testing-enabled NO \
  -only-testing:VaultRestartProofTests/RestartProofTests/testVerifyAfterProcessRestart
```

Prepare accepts one actual MLS packet into the encrypted vault. Its only external marker contains the public synthetic vault ID and the ciphertext packet. Verify requires that marker, opens the existing Keychain key and encrypted database, finds the pending event, rejects the already consumed packet, acknowledges the event, reopens the empty inbox, and removes its scoped test key, vault, and marker. Missing preparation is a failure rather than an automatic reset or a skipped proof. This demonstrates an app process restart; it does not simulate sudden power loss or device reboot.

### Durable vault execution evidence

On 2026-10-17, Xcode 27.1 on the iPhone 18 Pro / iOS 27.0 Simulator ran the ordinary suite against the actual Rust archive: **16 passed, zero failures, zero skips**. This includes the eight prior pairing tests and eight durable-vault tests: real prior/current-epoch MLS messages, close/reopen with pending inbox, consumed-packet rejection, tampered packet followed by authentic retry, bounded inbox, stale independent connections and acknowledgements, missing/wrong keys, ciphertext/revision/identity tamper, rollback before commit, uncertainty after commit, encrypted files, backup flags, and Keychain accessibility metadata.

The separate prepare invocation then passed one test. Before verification, the proof host was confirmed absent; XCTest had already exited it, so an explicit termination request reported that it was not running. A separate verification invocation passed one test, confirming durable inbox/state across an actual process boundary and cleaning its scoped key, database, and public marker. Both phases had zero failures and zero skips. The complete Rust-linked generic iOS device build also succeeded without signing or installation. No physical device, lock enforcement, abrupt process kill, power loss, recovery, or production app was validated.

## Local native signature-to-MLS binding

`MLSEnrollmentCoordinator` exercises the [local MLS device-binding contract](mls-device-binding.md) through the real Rust C bridge. It leaves Pairing v1 and the durable vault format unchanged. This is a bounded **local binding proof**: Rust creates and retains both synthetic participants, including the initial administrator and prospective joiner, in the same process. It is not independent-device onboarding or a network admission ceremony.

The native device key signs only the exact context returned by its own `enrollmentprepare` call. That context binds a random pending ID, the actual MLS group ID, the exact KeyPackage digest, both encoded MLS identity digests, distinct native device and approver public keys, and a 300-second validity window. The coordinator checks transcript domains, canonical Base64/hex fields, exact local group/package context, keys, timestamps, and request/approval digest binding. It will not sign an arbitrary substituted transcript. Native approval requires deliberate `userConfirmed: true`, the separately pinned approver key, and a valid device signature on the request. DER signatures are bounded to 72 bytes.

`enrollmentcomplete` verifies both native signatures again inside Rust before actual MLS Add/Welcome and validates the resulting group/creator/roster against its trusted local preparation. Only success consumes the admission handle. Native context substitutions and failed signature attempts preserve the original pending context. Cancellation is explicit. Pending native and Rust admission state is memory-only, bounded and expiring; it is not durable authorization or restart-persistent replay protection.

Success returns the joined secret MLS snapshot and synthetic application fixtures only in memory. The caller can immediately pass the snapshot to `DurableVault.create` and receive the authorized post-join messages through the existing encrypted checkpoint/inbox path. Rust admission success and first vault creation are separate steps: a crash or storage failure between them has no automatic recovery and is not an atomic durable enrollment transaction. There is no Guardian/account policy, remote trust bootstrap, membership lifecycle, independent-device Welcome transport, or product onboarding in this helper.

The native export test writes `Documents/mls-enrollment-native-export.json` in the test host container. It contains only the public request/approval transcripts, pending/group IDs, public KeyPackage and native public keys, signatures, and an expired synthetic timestamp. Every byte field uses standard padded Base64. It excludes joined snapshots, private MLS state, application packets, expected plaintext, and native private keys. Independent verification uses:

```sh
node scripts/verify-enrollment-fixture.mjs /path/to/mls-enrollment-native-export.json
```

### Local binding execution evidence

On 2026-10-17, Xcode 27.1 / iPhone 18 Pro / iOS 27.0 ran the current main suite against the rebuilt actual Rust archive: **23 passed, zero failures, zero skips**. The seven new tests cover native signature-to-MLS binding followed by encrypted-vault decryption, exact KeyPackage/group/transcript substitution rejection, pinned native keys, explicit approval, malformed signatures, expiry/cancellation, replay, and an expired Rust handle releasing the native coordinator slot. A direct C-bridge test bypasses native context guards and confirms Rust rejects substituted group/package, a rogue approver signature, malformed request signature, and replay while authentic retry succeeds.

The public enrollment export was copied to ignored `.local/enrollment-apple-export.json` and independently passed the Node/OpenSSL transcript, digest, context, and signature verifier. The complete final Rust-linked helper also compiled successfully for generic iOS with signing disabled; no physical device was used. Existing Pairing v1 and durable vault tests remain compatible. This increment did not rerun the separate vault process-restart phases; their earlier evidence is recorded above. It adds no claim of persistent admission state, independent-device onboarding, physical hardware execution, account authorization, or recovery.

All generated native signing keys and vault AES keys use scoped test cleanup; successful admissions were consumed and the expiry-lifecycle test cancelled its remaining handles. The owned Simulator was shut down after verification. Public-only interoperability artifacts are retained separately from secret state.

## Independent clients with durable admission

`DurableAdmission` is a separate prototype adapter for independently serialized owner and joiner secrets. The new stateless Rust admission operations require each caller's own secret state blob; they do not use the older local binding proof's shared process registry. The owner creates and signs an invitation. The joiner verifies a separately provisioned native administrator pin and creates its own KeyPackage and signed request. The owner verifies a separately confirmed joiner key, requires explicit user approval, signs the exact inspected request context, and creates the MLS Add/Welcome. The joiner verifies and joins that Welcome using only its own retained secret state. Signed invitation/request context includes the group and relevant MLS identities. Admission must be approved before expiry; authenticated Welcome delivery may arrive after that deadline.

The adapter stores an AES-GCM encrypted payload in `admission.sqlite`, with a separate `squadtime.proof.admission` Keychain AES key. Associated data binds `squadtime-admission-v1`, storage ID, and revision. The payload contains role, phase, opaque Rust secret state, exact public outbox, native public key and public Keychain alias, pinned administrator, input digest, and pending inbox. It reuses the verified SQLite WAL/FULL/fullfsync engine without changing `vault.sqlite` or the existing vault schema. Creating an initialized empty record precedes the first phase transaction. Every subsequent transition atomically CAS-commits successor Rust state and exact signed public outbox in one encrypted row before returning the outbox. Joining and receiving the fixed authenticated synthetic probe are staged together and atomically committed with the joined inbox before any plaintext is returned.

A before-commit fault rolls back without publishing the staged outbox or consuming local state. An uncertain commit or stale revision poisons that instance; reopening validates the encrypted record and Rust's exact stored outbox and resumes those bytes rather than regenerating MLS or signatures. The final joined state and inbox remain in this same admission payload, avoiding the earlier local proof's separate admission-to-vault handoff. Probe replay is checked against the persisted consumed MLS state. Inbox acknowledgement is another atomic revision update.

Existing databases are checked before generating a native signing key. Opening requires both the original AES wrapping key and the existing matching native signing key; missing or replaced keys fail closed. Only the public alias is stored, never a private key reference or private representation. Initial provisioning assumes a single creator per storage ID and key alias; concurrent subsequent writers are protected by revision CAS. Incomplete initial provisioning fails closed rather than automatically resetting state.

Secret state is bounded to 512 KiB, a public outbox to 128 KiB, packets to 1 MiB, and the inbox to 32 items / 2 MiB aggregate plaintext. The database and sidecars retain complete-protection policy setters and backup exclusion. The earlier Simulator limitation on Data Protection metadata remains: neither physical lock enforcement nor power-loss durability is established. Whole-database rollback, trusted clocks, recovery, end-user identity bootstrap, Guardian/account authorization, and a production QR/network transport remain open.

### Cross-process public exchange interface

`AdmissionExchangeProof` is a separate scheme with target/class `AdmissionExchangeProofTests`; it is not part of the ordinary suite. Host automation writes public `Documents/admission-exchange/input.json` and reads `output.json`. The local lookup marker `local.json` contains only `vaultUUID`, `keyAlias`, and `role`; all secret state remains in the encrypted application-support database. Start refuses an existing marker. Other phases require an existing marker and never silently create replacement state.

Each phase exports exactly `{kind, outbox, nativePublicKey}`, with byte fields in standard padded Base64. The outbox is the exact committed Rust public envelope. The administrator and candidate public keys must be provisioned as separate trusted test inputs; they are not implicitly trusted merely because an invitation or request carries them. Successful phases log only `ADMISSION_PHASE <phase> PID <process id>` for process-isolation evidence.

| XCTest method | Required public input |
| --- | --- |
| `testOwnerStart` | `{now}` |
| `testJoinerStart` | `{now, outbox: invitationBase64, trustedAdminPublicKey}` |
| `testOwnerAdmit` | `{now, outbox: requestBase64, trustedDevicePublicKey, userConfirmed: true}` |
| `testJoinerFinish` | `{now, outbox: welcomeBase64}` |
| `testResume` | `{}` |
| `testVerifyInbox` | `{}` |
| `testCleanup` | `{}` |

Resume reads the committed exact outbox. VerifyInbox reopens the joined state, checks the persisted synthetic probe, rejects replay, acknowledges it, and reopens an empty inbox without logging plaintext. Cleanup removes only this marker's scoped signing key, admission AES key, database directory, and local marker. Public exchange files contain signed public metadata, MLS KeyPackages, encrypted Welcome material and an encrypted probe; they contain no private snapshots or keys. Copying these files is a test transport, not a production onboarding ceremony.

### Independent admission ordinary-suite evidence

The current Apple ordinary suite ran on Xcode 27.1 / iPhone 18 Pro / iOS 27.0 against the final actual Rust archive: **30 passed, zero failures, zero skips**. The seven new durable-admission tests cover phase-by-phase reopening and exact outboxes, delayed authenticated Welcome delivery, atomic joined inbox persistence, replay rejection and acknowledgement, rollback and uncertain commits without staged output/plaintext release, stale independent connections, pins/signature tampering/expiry/phase replay, missing or replaced AES and signing keys, no implicit signing-key regeneration for an existing database, ciphertext/revision tampering, and backup policy flags. All previous 23 tests remained passing.

The dedicated exchange scheme also built successfully into ignored `.local/admission-derived` and its proof host was installed for separately orchestrated cross-platform process tests. This build alone does not establish that those exchange phases completed; their runtime results are recorded separately.

### Independent cross-platform process evidence

On 2026-10-17, the host-orchestrated public-file exchange completed both directions: **Apple owner to Android joiner, and Android owner to Apple joiner**. All **22 targeted phase executions passed**, including scoped cleanup. Apple's 11 phase executions each ran in a distinct process, verified by the generic phase/PID markers; these were separate from the ordinary 30-test run above.

In each direction, the invitation, request, and Welcome resumed as the exact previously committed public bytes after process restart. The independently retained joiner accepted the authenticated Welcome after the admission deadline (`now + 600` in the synthetic clock), persisted and decrypted the authorized probe, then a fresh verification process recovered that pending inbox and rejected the consumed probe ciphertext. Acknowledgement succeeded and reopening showed an empty inbox. Both sides' scoped signing/AES keys, encrypted admission directories, and local lookup markers were removed by their cleanup phases.

The public envelopes in both directions independently passed Node/OpenSSL signature and transcript/context verification. The host Node suite passed 23 tests, including the checked-in public Apple-owner exchange vector. Only public exchange envelopes and separately provisioned public pins crossed platform boundaries; no private MLS state or native private key was transferred. The owned Apple Simulator was shut down after the exchange.

This establishes the bounded synthetic independent-client and restart-safe local admission/outbox/inbox path on Simulator and emulator. It does not establish physical hardware or lock enforcement, device reboot or power-loss durability, malicious whole-database rollback resistance, production network/QR transport, account or Guardian authorization, recovery, or general multi-member membership management.
