# MLS protocol spike

Status: 2026-10-17. Runnable evaluation, **not production encryption**.

## Decision and evidence

The proof uses MLS (RFC 9420), not a new group-key protocol. It evaluates
`mls-rs = 0.56.0`, `mls-rs-core = 0.27.0`, and
`mls-rs-crypto-awslc = 0.25.1`; `Cargo.lock` fixes transitive dependencies.
The provider is AWS-LC with suite 1
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
The core tests use no external backend or account credentials. An interactive
synthetic ciphertext harness is available for a separate relay integration check.

This is a provisional implementation choice for the proof. Before selecting the
production library, compare the native bindings, persistent-state behavior,
security findings and update process of both candidates.

| Candidate | Primary-source finding | Consequence |
| --- | --- | --- |
| mls-rs | Maintainer explicitly states no full third-party security audit; AWS-LC is a supported provider, Rust Crypto is experimental. | Suitable to explore the API; no audit claim or production approval. |
| OpenMLS | Maintainer reports a 2026 SRLabs audit. Its security advisories include subsequent issues. Mobile targets are built in CI but not tested there. | Strong alternative; an audit of a particular version does not approve a whole app or every provider. Evaluate patched release and native integration before choosing. |

Sources checked on 2026-10-17:

- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html).
- [mls-rs project, providers and security notice](https://github.com/awslabs/mls-rs).
- [Versioned mls-rs 0.56.0 API](https://docs.rs/mls-rs/0.56.0/mls_rs/).
- [Versioned AWS-LC provider](https://docs.rs/mls-rs-crypto-awslc/0.25.1/mls_rs_crypto_awslc/).
- [OpenMLS project and platform status](https://github.com/openmls/openmls).
- [OpenMLS maintainer audit report announcement](https://blog.phnx.im/openmls-independent-security-audit/).
- [OpenMLS security advisories](https://github.com/openmls/openmls/security/advisories).

## Reproduce

Install Rust 1.90.0 using rustup and a native C compiler/SDK required by AWS-LC.
The package's toolchain file pins Rust and requests rustfmt/clippy. From the
repository root:

```sh
cd crypto/mls-spike
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

Initial dependency downloads need network access. The tests run locally and
create fresh random, disposable identities in memory on every run. They do not
print keys or plaintext, create user accounts, or contact the delivery service.
No test identities are suitable for production.

## What the tests prove

`tests/lifecycle.rs` uses the real library for each cryptographic operation. All
simulated network messages pass through MLS wire serialization and decoding.

1. Create Alice's group; add Bob and Carol from their KeyPackages, commit and
   join through Welcome. Alice's encrypted scheduling event arrives byte for
   byte at both recipients, with the authenticated MLS sender index. Bob can
   reply. The serialized application message does not contain the full event
   plaintext (a smoke check, not a cryptographic confidentiality proof).
2. Alice removes Bob and advances the epoch. Carol processes the commit and
   decrypts Alice's next message. Bob cannot decrypt that future message even
   if the delivery service withholds his removal commit; delivering the removal
   commit does not restore access.
3. Altered ciphertext is rejected; a fresh legitimate generation still works;
   replay of a successfully received message is rejected.
4. A new attacker key using Bob's exact credential identifier is rejected by
   Alice's custom `IdentityProvider`; Bob's pinned legitimate key can join.
   This demonstrates the hook for trusted device binding.

There are three lifecycle integration tests: the first covers items 1–2; the
second item 3; the third item 4. Last recorded validation for these tests:
**3 passed, 0 failed**, Rust 1.90.0,
`aarch64-apple-darwin` (macOS host). Formatting and clippy also pass.
This does not test real phones, multi-process networking or persistent storage.

The application-message receive wrapper adds six transaction regression tests,
bringing the Rust test suite to nine tests. Its implementation and evidence are
described in [mls-state-transactions.md](mls-state-transactions.md).

### Availability finding: failed authentication consumes a generation

With these pinned versions and default in-memory configuration, corrupting the
last byte of a message through the raw library API makes processing fail.
Retrying the original valid message from that same generation then fails with
`KeyMissing(0)`. A newly encrypted message from the next generation is accepted.
The unchanged raw test records this behavior; it must not be treated as safe to
retry directly.

For **application messages only**, the `ApplicationReceiver` wrapper addresses
that failure mode by processing on a candidate group and persisting only after
authentication and pure application-policy acceptance. Under the tested
assumptions of atomic storage writes and one writer per group, rejected input
does not consume the saved generation and an accepted input does. Six additional
tests exercise rejection, retry, replay, reload and storage errors. This resolves
the raw receive blocker only for callers that use this wrapper under those
assumptions. It does not provide a durable native inbox, process-crash atomicity
with application data, multi-process locking, rollback prevention, or a path for
MLS control commits and membership changes; those remain open. See
[mls-state-transactions.md](mls-state-transactions.md) for the limits and test
details. The separate [native vault proof](durable-native-state.md) now combines
actual Rust MLS receive with an encrypted SQLite checkpoint and recoverable inbox.
Its validation and remaining boundaries are separate from this standalone wrapper.

Do not patch cryptographic ratchet internals or retain old secrets as a
workaround. A malicious relay can already drop messages; this observation
concerns delivery robustness, not its ability to decrypt. No broad vulnerability
claim has been established by this proof.

## Proposed application boundary

One MLS leaf represents one authorized **device**, not one account. A child,
parent or adult may have several devices. Group changes must operate on every
affected device leaf. Normal group memberships and a separate parent/child
sharing group define distinct audiences; a parent relationship must never
silently grant access to all historical or future group content.

Application payloads should include a version, event ID, actor/device identity,
logical revision and domain-specific event data. The authenticated MLS sender
must match the actor and its permissions. Clients calculate availability
intersections, games, preferences and sessions after decryption. Sensitive
profile data, game inventories, schedules, parental rules and quick messages
belong inside the appropriate encrypted audience. TLS remains necessary.

The server stores opaque envelopes and routing metadata: account/device/group
IDs, current membership, ciphertext, MLS control messages, epoch/sequence and
retention information. This does **not** hide group membership, traffic times,
sizes or IP addresses. MLS authenticated additional data is plaintext: never
put names, schedules, emails, approval contents or push previews there.
Push content stays generic. The proof uses empty additional data.

The application still needs:

- Authenticated commit sequencing and compare-and-swap, durable local atomic
  state changes, crash recovery, multi-device catch-up, replay/idempotency and
  bounded out-of-order handling. Server acceptance of a commit is not proof
  that its new membership is authorized.
- Policy checks on every member/role change, including parent approvals. A
  malicious existing member must not be able to bypass the children's invite
  rules simply because MLS can cryptographically add a device. Unimplemented
  application policy must fail closed.
- Verification of the inner MLS group, epoch and authenticated sender against
  the outer routing envelope. Do not trust arbitrary server-supplied actor IDs.
- Ciphertext retention and explicit expiry in encrypted events. Server expiry
  cannot make an offline recipient forget a previously decrypted event.

## Authorized identity binding: concept and implemented limit

The spike preloads exact `(credential, signing public key)` pairs directly into
each client's local `ApprovedDevices` registry. Unknown pairs are rejected in
MLS validation; external senders are disabled. Same-key leaf updates are
allowed, silent successor key replacement is not. No names or server assertions
serve as proof of identity. This is an authorization fixture, not a complete
account identity system; the test never fetches that registry from the relay.

A production enrollment design must bind account ID, device ID and signing key
through an existing trusted device or an explicitly verified parent device,
using a short-lived one-time QR ceremony and reviewed signed authorization
format. Verify fingerprints/approval out of band, include scope and expiry,
and prevent approval replay and server key substitution. Device and account
keys have separate roles. Secure key storage and signature support on native
platforms require a real integration design; this proof does not establish
Secure Enclave/Android Keystore support for the chosen suite.

The mutable approval/revocation registry, signed approval transport,
permission/parent role enforcement, key transparency or consistency checks,
key rotation and trusted account roots are **not implemented**. Static test
pins only establish the narrow substitution rejection tested above.

## Recovery, deletion and remaining security work

No shared recovery secret lives on the server. Lost-device recovery needs an
approved surviving device or a carefully reviewed user-held recovery mechanism.
Adding a fresh device does not automatically give it old event history; any
history transfer must be explicit, encrypted and audience authorized. If all
trusted devices/recovery material are lost, access to old ciphertext may be
irrecoverable. Email login alone must never reconstruct encryption keys.

Removing a device prevents access to messages encrypted after the accepted
removal epoch. It cannot erase prior plaintext, screenshots, backups or old
keys retained by a malicious device; other authorized members could leak data.
Stale epochs must not be used for new events after a removal. Forward secrecy
and post-compromise security depend on correct key deletion and updates; this
proof does not validate those properties across backups or crashes.

Before production: complete and review the trust model, bind approvals into
membership enforcement, test secure persistent storage and crash recovery,
review dependencies/advisories and the pinned toolchain, fuzz untrusted inputs,
limit message and group sizes, and obtain an independent application/security
review. Swift/Kotlin bindings, iOS/Android builds/device tests, inter-library
interop, state migration, encrypted recovery and malicious-member policy tests
remain open. The interactive harness was also verified through the deployed DEV relay on
2026-10-17; see docs/validation.md for scope. Native apps remain unconnected, and this must
not be presented as app-wide E2EE already working.

## Interactive relay harness

```sh
cd crypto/mls-spike
cargo build --locked --example relay_roundtrip
./target/debug/examples/relay_roundtrip
```

The process generates approved synthetic Alice/Bob devices and a group in memory.
Its first stdout line is one serialized encrypted MLS application message as hex;
it flushes and waits for one hex line on stdin. A caller can convert that packet
to base64, submit it to a relay, fetch it, convert back to hex and return it. Bob
checks the decrypted synthetic event and authenticated sender. Success prints
`verified` and exits 0; failure exits nonzero with a generic reason on stderr.
No keys or plaintext are printed or persisted. The harness itself has no network
code or account access. Local echo success is not proof of a deployed relay;
the separate live integration result is recorded in docs/validation.md.
