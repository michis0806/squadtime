# Native MLS snapshot bridge

Status: 2026-10-17. Development proof using real `mls-rs 0.56.0` and AWS-LC
provider `0.25.1`, suite 1. It connects native encrypted-state/inbox experiments
to real MLS packets. It is not production enrollment, a production security
review, recovery, or proof of complete app E2EE.

## Boundary and secret handling

`crypto/mls-spike/src/native_bridge.rs` exposes a C ABI. Fixture/receive calls are
stateless; enrollment uses a bounded volatile process-local registry, described
below. The ABI is documented in
[`native/include/squadtime_mls.h`](../native/include/squadtime_mls.h):

```c
int32_t squadtime_mls_call(const uint8_t *input, size_t input_len,
                         uint8_t **output, size_t *output_len);
void squadtime_mls_free(uint8_t *output, size_t output_len);
```

Input/output are bounded UTF-8 JSON bytes, not NUL-terminated strings. Standard
padded Base64 encodes byte fields; whitespace inside Base64 is rejected. The
maximum JSON call/reply is 16 MiB, decoded snapshot 8 MiB, decoded MLS packet
1 MiB. Snapshots permit at most three retained prior epochs. Errors return fixed
status codes, never a provider error, packet, key or decrypted content:

- `0`: success; returned pointer/length are owned by the caller until freed.
- `1`: generic rejected command, state, packet, authentication or policy.
- `2`: invalid ABI arguments or input length.

When output arguments are valid, failure resets them to NULL/0. The caller must
provide valid, aligned, writable output slots that do not alias the readable
input or each other. After copying a successful reply, call `squadtime_mls_free`
exactly once with the exact pointer and length. The Rust allocation is zeroized
before release. Arbitrary, altered, already-freed or concurrently used pointers
are invalid; Rust cannot validate C memory ownership.

**Every snapshot is a secret**, including its Base64 form. It contains recipient
signing material, pinned identities, group state and retained prior-epoch secrets.
Snapshots are not ciphertext until protected by the native authenticated encrypted
store. They must never be sent to the relay, logs, analytics, crash attachments,
command arguments or files in unencrypted form. The bridge has no network/file
I/O and no logging. Native callers must manage and clear their own input/copy
buffers and avoid diagnostic capture. Failed parsing, allocator behavior,
managed-language strings and upstream libraries can still create temporary
copies; whole-process memory erasure is not established. Unexpected Rust panics
are contained at the ABI where unwinding is possible, but the host panic/crash
hook policy remains a separate responsibility. No process-global hook is changed.

## Commands

`{"op":"fixture"}` returns:

```text
{"snapshot": Base64, "packets": [Base64, Base64], "expected": [Base64, Base64]}
```

This generates fresh synthetic Alice/Bob identities in memory, initializes a real
MLS group and joins Bob with Welcome. `packets[0]` is a delayed application packet
from a previous epoch; `packets[1]` belongs to the current epoch. The snapshot is
Bob's state before consuming either application packet, including the retained
prior epoch. `expected` contains the corresponding synthetic plaintext bytes for
native test assertions. Alice's private state is discarded, not exported.
Fixture generation is a development operation, not an enrollment API.

`{"op":"receive","snapshot":Base64,"packet":Base64}` returns:

```text
{"snapshot": Base64, "plaintext": Base64, "senderIndex": unsigned integer}
```

Unknown commands/fields, malformed encodings and unsupported snapshot versions
are rejected. Snapshot version 1 is an internal evaluation format tied to the
pinned MLS state encoding; no cross-version migration contract is promised.

Each receive creates an isolated RAM store and restores via the supported
`GroupStateStorage` and `Client::load_group` APIs. The saved recipient signing key
must derive its pinned public key, the MLS group must match the saved group ID,
suite and recipient identity, and its two-member roster must contain the pinned
sender. The existing staged `ApplicationReceiver` authenticates/decrypts the
packet and checks the actual MLS sender index. Control messages are rejected;
authenticated sender data comes from MLS, not an outer relay assertion.
The returned snapshot includes updated current and prior-epoch state, so later
calls preserve consumed generations. No MLS internals or ratchet primitives were
patched. The native snapshot must originate from the **trusted local store**;
these checks do not authorize arbitrary snapshots supplied by a server.

## Required native transaction

A successful call produces only a candidate. Rust writes to an isolated in-memory
store and returns; it does not persist, acknowledge or display anything.

The native adapter must read a trusted encrypted snapshot and its local revision,
call `receive`, then atomically compare-and-swap that revision and commit both the
new protected snapshot and a recoverable protected inbox item. Only after commit
may it acknowledge/display/apply the event. A failed CAS discards the candidate
and rereads the latest state; an authentication/policy rejection must leave
persistent state unchanged. Inbox application must be idempotent.

A crash before commit retains the previous snapshot and permits authentic retry.
A crash after commit must recover the inbox item while retaining the advanced
snapshot; simply retrying the MLS packet is correctly rejected as a replay.
Concurrent sends, control changes and receives need the same local revision/lock
scheme. This bridge does not establish that native database transaction or
whole-device durability; the platform implementations/tests report their own
scope. Restoring an old backup can still resurrect an old snapshot. Local CAS
alone does not prevent malicious rollback or solve cross-device consistency.

## Host validation and dependencies

The host suite preserves all nine earlier protocol/transaction tests and adds
five bridge tests: real previous/current epoch reopen, both packet orders,
tamper then authentic retry, replay after returned-snapshot reopen, unrelated
fresh-group packet rejection, malformed/unknown commands and snapshot versions,
and C ABI ownership/failure-output checks. Test values remain in memory and are
not printed. These are host tests, not claims of phone execution or secure
hardware binding. Native simulator/emulator/device results must be recorded
separately by the integrating task.

From `crypto/mls-spike`:

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --lib
```

The crate emits `rlib`, `staticlib` and `cdylib`. Native build scripts select the
platform target/linker; the public C header is shared with Apple and JNI wrappers.
No keys or snapshots are generated by compilation.

Added dependencies are pinned: `serde_json 1.0.154` and `base64ct 1.8.3`;
`serde 1.0.229` and `zeroize 1.9.1` were already locked and now have direct runtime
roles. JSON adds locked `itoa 1.0.18` and `zmij 1.0.23`; MLS/provider versions did
not change. Base64ct uses arithmetic rather than data-dependent lookup tables for
best-effort data-independent encoding. This is **only** a property of that Rust
component: it does not make JSON, allocations, snapshot lengths, native
Foundation/JVM conversions, FFI or the application constant-time.
See [Base64ct documentation](https://docs.rs/base64ct/1.8.3/base64ct/) and
[serde_json documentation](https://docs.rs/serde_json/1.0.154/serde_json/).
The [RustSec advisory index](https://rustsec.org/advisories/) was reviewed for the
added package names; this is not a complete dependency audit or a production
security approval. A full pinned-dependency advisory check belongs in integration
and maintenance.

Still open: independent-device enrollment into MLS beyond the local binding proof, real shared-group
membership/control authorization, guardian policy, history transfer, recovery,
state migrations, rollback detection, and independent application security review.
The fixture's MLS signing keys are software keys protected as snapshot data;
this does not claim Ed25519 keys reside inside Secure Enclave or Android hardware.

## Local native P-256 approval bound to MLS admission

The bridge now also exposes `enrollmentprepare`, `enrollmentcomplete` and
`enrollmentcancel`. This is a **local, single-process binding proof**: Rust owns
both a synthetic existing MLS administrator and a synthetic joining MLS client.
It does not establish that independently operating devices can enroll over a
network, verify a person/guardian, or recover pending enrollment after restart.
See the separate [binding protocol description](mls-device-binding.md).

Prepare takes `devicePublicKey` and `approverPublicKey` as standard padded Base64
uncompressed 65-byte P-256 SEC1 public points, and an injected integer Unix `now`
up to `2^53-1` (leaving room for the 300-second expiry). The approver key must be
a previously trusted **local native pin**, not a key offered by the relay. Rust
validates both curve points and requires distinct keys. It creates a fresh MLS
identity and KeyPackage for the joiner and an actual single-member administrator
group. It retains their private state in a process-local, mutex-protected map.
Prepare returns only public proof material and a random one-use pending handle:

```text
{"pendingId":Base64,"groupId":Base64,"keyPackage":Base64,
 "request":Base64UTF8,"approval":Base64UTF8}
```

The exact returned request transcript binds the pending challenge, actual group
ID, SHA-256 digest of the complete MLS KeyPackage wire bytes, digests of both
encoded MLS signing identities, native device/approver public keys and issuance
and expiry times. Identity digests cover the complete upstream
`SigningIdentity::mls_encode_to_vec` representation, including credential and
MLS signing public key. The separate approval transcript signs the request digest,
pending handle and trusted approver pin. Both are fixed LF-terminated UTF-8 text;
JSON serialization is not signed. Native code must verify that the returned
transcripts match its retained local context before explicitly signing them.

Complete takes `pendingId`, exact `groupId` and `keyPackage`, native
`requestSignature` and `approvalSignature` (Base64 DER), and `now`. Rust checks
held context, time and both actual P-256/SHA-256 signatures using the existing
AWS-LC provider. It checks canonical DER lengths 8–72, minimal positive integer
encoding and scalar ranges `1 <= r,s < n`; high-S is allowed for native API
compatibility. There is no caller-supplied `approved` boolean. Only after these
checks does it execute the real MLS Add/commit/Welcome flow. The joining client's
group ID and identity must match the held context, its roster must contain the
two expected members, and the authenticated Welcome sender index must identify
the locally pinned administrator MLS identity. This prevents replacing the
approved group with an unrelated administrator's MLS context in this proof.

Successful completion returns the existing fixture-shaped reply:
`{snapshot, packets:[2], expected:[2]}`. The ready receiver snapshot contains the
signed native-to-MLS binding, group/identity hashes and trusted approver pin.
Subsequent `receive` calls retain that proof and verify its signatures and its
binding to the saved group and both MLS identities. Expiry gates admission;
it does not make already-authorized membership expire automatically.
The two synthetic packets exercise current and retained prior-epoch reception.
The native caller can now initialize its encrypted snapshot/inbox vault from
this admitted receiver state. Completion itself does not create that vault.

The entire completion is serialized under the pending-map mutex and staged with
an isolated administrator-group clone and a deep-copied joiner KeyPackage store.
Rejected signatures/context do not consume or mutate the original pending state.
Only successful result construction removes the handle. Two concurrent attempts
can produce only one success. Cancellation explicitly drops the held private
state and returns `{"cancelled":true}`; unknown/consumed handles reject. The map
is capped at 16 contexts; prepare/complete remove expired contexts, based on the
trusted caller's supplied clock. Expiry is not a promise of a background erasure
timer. Native callers should cancel abandoned contexts promptly.

Pending state, admission and commit delivery are **not durable**. Process loss
invalidates all handles. A crash after successful removal but before native vault
creation loses the result and requires a fresh proof; no durable replay ledger,
admission outbox, Welcome retransmission, rollback defense or cross-process
one-shot guarantee is provided. The accepted commit exists only in this local
proof's in-memory group. Do not generalize that ordering into a network delivery
protocol or release a real network Welcome without an accepted commit/outbox.

`tests/enrollment.rs` adds five host tests covering valid P-256 signatures followed
by working MLS traffic; exact KeyPackage/group/request/approver substitution
rejection with authentic retry; retained proof and altered saved signature/group/
identity rejection; malformed DER; concurrent one-shot completion; expiry;
cancellation; invalid curve points; and the pending cap. All fourteen earlier
protocol/bridge/transaction tests remain. No cryptographic dependencies changed.
Native simulator/emulator results and independent public transcript verification
are recorded separately by the integrating task. Injected historical transcript
times are test clocks; MLS KeyPackage generation/validation still uses the library's
ordinary current-time behavior within the local proof.
