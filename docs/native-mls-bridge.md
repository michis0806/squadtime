# Native MLS snapshot bridge

Status: 2026-10-17. Development proof using real `mls-rs 0.56.0` and AWS-LC
provider `0.25.1`, suite 1. It connects native encrypted-state/inbox experiments
to real MLS packets. It is not production enrollment, a production security
review, recovery, or proof of complete app E2EE.

## Boundary and secret handling

`crypto/mls-spike/src/native_bridge.rs` exposes a stateless C ABI described in
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

Still open: native approved-device identity enrollment into MLS, real shared-group
membership/control authorization, guardian policy, history transfer, recovery,
state migrations, rollback detection, and independent application security review.
The fixture's MLS signing keys are software keys protected as snapshot data;
this does not claim Ed25519 keys reside inside Secure Enclave or Android hardware.
