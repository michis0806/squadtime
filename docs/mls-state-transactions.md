# MLS receive-state transactions

2026-10-17. Evaluation with pinned `mls-rs 0.56.0` / AWS-LC provider `0.25.1`.
This addresses a specific application-receive robustness problem; it is not a
production security review or complete rollback defense. The later native proof
adds an encrypted checkpoint/inbox wrapper around this receive path; see
[durable-native-state.md](durable-native-state.md) for its distinct scope and limits.

## Why the raw call consumes a failed packet's generation

Inspection of the downloaded, checksum-locked upstream sources found:

- `group/ciphertext_processor.rs::open` gets a decryption key through
  `decryption_key` **before** authenticating the application ciphertext.
- `group/secret_tree.rs::get_message_key` advances the ratchet or removes a
  cached generation. Authentication failure does not restore that mutation.
- `Group` publicly implements `Clone`. Processing changes the group's in-memory
  state; persistence is explicit through `write_to_storage`.
- `GroupStateRepository` accumulates prior-epoch inserts/updates; the storage
  write happens in `write_to_storage`. Lazy loading a prior epoch reads storage
  into the group's own pending cache. This matters because storage handles may
  be shared when a group is cloned.

The original `altered_ciphertext_and_replay_are_rejected` test is unchanged and
still proves the raw behavior: modified ciphertext fails; original generation 0
then returns `KeyMissing(0)`; a fresh generation succeeds. No upstream crypto
code, ratchet primitive, or dependency version was modified to address it.

Public references checked:
[Group APIs and Clone](https://docs.rs/mls-rs/0.56.0/mls_rs/group/struct.Group.html),
[Client reload API](https://docs.rs/mls-rs/0.56.0/mls_rs/struct.Client.html), and
[storage trait source](https://docs.rs/mls-rs-core/0.27.0/src/mls_rs_core/group/group_state.rs.html).
The upstream storage trait requires atomic writes to avoid partially corrupting
state. The repository implementation also performs join KeyPackage cleanup
separately after the group write; initialization must account for that boundary.

## Adapter and ordering

`crypto/mls-spike/src/lib.rs` exports `ApplicationReceiver`:

1. `initialize` writes an already-established group once, including join cleanup,
   then reopens it through `Client::load_group`. Normal restart uses `open`.
2. `receive` bounds and decodes the packet, clones the current group and processes
   the candidate with the ordinary library API.
3. Only an authenticated application message reaches a **pure** application
   acceptance predicate. Protocol errors, non-application messages and policy
   rejection discard the candidate without a storage write.
4. An accepted candidate calls `write_to_storage`. Only successful persistence
   replaces the active in-memory group and returns its authenticated event.
5. Any persistence error permanently blocks that receiver instance. Errors can
   occur before writing, after committing, or during a partial write; retrying
   from stale memory would be unsafe. Recovery requires reconciling the actual
   trusted store before opening a new instance.

Rejection therefore does not publish a mutated ratchet. Acceptance publishes the
advanced ratchet; a subsequent replay cannot decrypt. This uses one short-lived
candidate, not an archive of previous message keys or snapshots. The interactive
`relay_roundtrip` example now uses this adapter and checks its event/sender in the
acceptance predicate before committing. Its stdin/stdout contract is unchanged.

The helper deliberately rejects MLS control traffic. Membership authorization,
control-commit validation and their application side effects require a separate
reviewed transaction path. Do not use the helper as proof that invite or guardian
policy is enforced.

## Regression evidence

`tests/transactions.rs` exercises real MLS packets and serialized snapshots, with
an observing wrapper around upstream in-memory group storage:

- Corrupted and malformed packets do not write or change the checkpoint; the
  authentic **same-generation** packet subsequently decrypts and replay fails.
- Authenticated application-policy rejection leaves state usable for a later
  explicitly accepted retry.
- A valid MLS control commit is rejected and the original epoch remains usable.
- Receiver loss before commit permits authentic retry from the checkpoint;
  receiver loss after commit preserves replay rejection on reload.
- An injected error before a write and an injected error after a successful atomic
  write both block further use. Reopening the authoritative test checkpoint
  respectively permits retry or rejects it as already consumed. No event is
  returned to the caller when persistence reports failure.
- A delayed prior-epoch packet exercises lazy-loaded epoch state: tampering does
  not change saved epoch bytes; accepting the authentic packet changes them;
  reloading preserves replay rejection for that epoch.

Snapshots are compared in memory without printing them. Test storage, synthetic
keys and event contents never go to files or logs. These are restart simulations
using retained opaque serialized **RAM** storage, not process-kill, filesystem,
fsync, power-loss, database-corruption, or mobile-device durability tests. A separate
native vault proof now exercises atomic encrypted SQLite state/inbox commits with
real MLS packets; it does not upgrade these host tests into power-loss evidence.

Run from `crypto/mls-spike`:

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --example relay_roundtrip
```

The direct dev dependency on `zeroize = 1.9.1` names the type required to implement
upstream storage in tests; the same version was already in the lockfile. No
library/provider upgrade was made.

## Security and integration boundaries

**Single writer:** `&mut self` serializes calls on one receiver, but cannot stop a
second instance or process using the same stored group. A real store must lock
or compare-and-swap a trusted revision across all writers, including send and
control operations. Calling `open` does not establish exclusive ownership.

**Shared providers:** cloning isolates group/ratchet/pending epoch state, not every
possible user-supplied provider. Providers, rules and validation must not have
irreversible processing-time side effects. The proof uses the inspected upstream
AWS-LC provider, pure static identity pins and upstream storage behavior. Changing
them requires reviewing and testing that assumption again.

**Memory:** staging duplicates current group secrets transiently. Rejecting or
replacing a candidate drops the unused object, with upstream secret types'
zeroization where implemented. This is not a guarantee that every allocation,
stack/register copy, swap page or crash dump is erased. Copies increase memory
and work per packet; bounds/rate limits and native profiling remain necessary.
Stored checkpoints themselves contain secret material and must use authenticated
encryption and native key protection in a real client. The default RAM store is
neither encrypted durable storage nor a recovery service.

**Crash gap and inbox:** this helper alone commits MLS state before returning plaintext.
If a process dies after that commit but before its application database/inbox is
updated, the relay retry is correctly rejected and the app could miss the event.
The native proof adds a vault that atomically commits encrypted MLS state and a
recoverable accepted inbox item, then supports reopening and idempotent acknowledgement.
That proof is not yet the production application store. A production store must apply/display
the accepted event idempotently and coordinate other application data.
The current pure predicate is not that transaction and must not write the UI,
application state or external services. A storage error after commit can create
the same application-delivery gap; blocking the instance avoids unsafe ratchet
reuse but does not repair missing inbox data.

**Rollback:** reloading a trusted latest checkpoint preserves consumed-generation
state in these tests. Restoring an older database/backup can resurrect a consumed
ratchet and permit an old event again. These tests do not prevent malicious
rollback, stale backup restore, server history forks, or sender nonce/key reuse
after sender rollback. Trusted monotonic state/consistency and backup semantics
remain open; never fix the crash gap by blindly restoring an old group.

The result supports continuing library evaluation without changing MLS libraries
solely for this raw-call behavior. Native Rust FFI and encrypted SQLite vaults now
exercise the receive path; production persistence, complete app-state atomicity,
enrollment, membership/control authorization, recovery, rollback defense and
independent security review remain separate work. Native validation status is
tracked in [validation.md](validation.md).
