# Native device approval bound to MLS

This document preserves the **legacy local, initial two-member enrollment binding proof**, not an onboarding service. The successor [independent admission proof](independent-admission.md) keeps administrator and joiner states separate and exercises public-envelope exchange between independent app processes with pre-provisioned test pins. Both directions passed the separate-process exchange harness. The native process owns both synthetic MLS participants through the Rust
bridge. It uses actual native P-256 keys, actual MLS KeyPackages, Add commits and
Welcome processing. It does not connect independently running devices, establish
account or Guardian authority, or implement a QR trust ceremony.

The earlier [pairing v1 proof](device-pairing-proof.md) remains separate and
compatible. Its approval cannot authorize this new operation: different signed
transcript domains prevent reuse between the two proofs.

## Trust and scope

The caller supplies its local device public key and a separately trusted approver
P-256 public key. These are local inputs, never keys accepted from an untrusted
relay response. The proof generates fresh joiner and administrator MLS signing
identities and one administrator group, then retains their exact identities and
private state locally. The request binds both MLS identity hashes, both native
keys, the group and the exact KeyPackage bytes. The native layer checks the
returned public transcript against its own inputs before signing. Approving
requires explicit user confirmation and the key matching the pinned approver.

The Rust core verifies both P-256 signatures itself before building an Add. An
outer `approved: true` value cannot bypass that check. The new member is accepted
only using the retained KeyPackage and identity pins; Welcome processing must
produce the intended group and the expected two-member roster. The administrator
MLS identity is pinned as well as the group ID: a visible group ID alone is not
an authentication mechanism.

This deliberately does not claim an independently authenticated binding of an
existing remote administrator's MLS identity to an account. Both MLS identities
originate inside this local proof. A distributed enrollment protocol still needs
a trusted invitation/context exchange and authorization rules for existing group
members. A native key signature also does not establish who owns an account or
whether the signer is a child's guardian.

[MLS credentials](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) require
application authentication. [KeyPackages](https://www.rfc-editor.org/rfc/rfc9420.html#section-10)
provide the keys for admission, but do not themselves express Squadtime's
permission policy. This proof adds a signed, scoped authorization layer around
the library's standard membership operations; it does not change MLS primitives.

## Public transcripts

All byte fields use canonical standard padded Base64. Hashes use lowercase
SHA-256 hexadecimal. Timestamps are nonnegative integer Unix seconds, at most
JavaScript's safe integer maximum. UTF-8 transcripts use LF and include the final
LF; these are signed as bytes, not as JSON serialization. Native P-256 signatures
use SHA-256 and canonical ASN.1 DER, with uncompressed 65-byte SEC1 public keys.

Request, in this exact order:

```text
squadtime-mls-device-request-v1
{pendingId}
{groupId}
{sha256(keyPackageBytes)}
{sha256(encodedJoinerMLSIdentity)}
{sha256(encodedAdministratorMLSIdentity)}
{devicePublicKey}
{approverPublicKey}
{issuedAt}
{expiresAt}
```

Approval:

```text
squadtime-mls-device-approval-v1
{pendingId}
{sha256(requestTranscriptBytes)}
{approverPublicKey}
```

`pendingId` is a fresh random 32-byte local request handle. It is not a relay login
credential or private key. The group ID and encoded MLS identities originate
from the actual Rust MLS objects. Identity encoding is the pinned library's MLS
encoding of `SigningIdentity`, including credential and MLS signing public key.
The request validity window is 300 seconds; validation requires
`issuedAt <= now < expiresAt`. The caller's clock is trusted in this proof;
clock rollback resistance is not established. This window gates admission only;
an admitted group does not expire when the original approval window closes.
Enrollment snapshots retain the signed binding and revalidate its signatures and
group/MLS identity matches on subsequent receive.

## Local bridge lifecycle

The existing C ABI gains three commands; field names below are exact:

```text
enrollmentprepare {devicePublicKey, approverPublicKey, now}
  -> {pendingId, groupId, keyPackage, request, approval}
enrollmentcomplete {pendingId, groupId, keyPackage, requestSignature,
                    approvalSignature, now}
  -> {snapshot, packets: [packet, packet], expected: [plaintext, plaintext]}
enrollmentcancel {pendingId}
  -> {cancelled: true}
```

JSON also carries `op` with the indicated command name. `request` and `approval`
are Base64-encoded transcript bytes. The prepare result is public material;
private MLS keys stay in bounded process memory. The complete result has the same
**secret, local-only** snapshot shape as the existing synthetic fixture. The two
packets and expected values are synthetic application-message test material,
not a general-purpose application sending API. Snapshot bytes must immediately
enter the existing [encrypted native vault](durable-native-state.md), never
plaintext files, logs, command arguments, fixtures or network envelopes.

At most 16 pending operations are held in a process. Expired entries are cleaned
on subsequent prepare/complete operations; cancellation explicitly drops an abandoned operation.
Accepted completion consumes the handle once. Invalid signatures or altered
context cannot consume a still-valid pending operation, so an authentic retry
remains possible. Concurrent completion is serialized by the Rust registry.

**This registry is volatile.** Process exit loses pending state and its private
keys. A successful in-memory Add/Welcome consumes the handle before native vault
creation: failure during subsequent persistence cannot atomically roll back
admission. Native callers must abandon that attempt and start a new one, and
must not release an external Welcome through this proof. There is no durable
membership transaction, restart-safe outbox, distributed concurrent-commit
resolution, or persisted authorization ledger. Retained registry objects and
managed-language copies are not a whole-process memory-erasure guarantee.

The [MLS ordering requirement](https://www.rfc-editor.org/rfc/rfc9420.html#section-14)
means production membership persistence and accepted-commit/outbox handling must
be completed before Welcome is delivered between devices. The existing durable
receive/inbox transaction covers subsequent application receive; it does not
supply this membership transaction.

## Verification

The Rust tests exercise genuine MLS admission and signature/context rejection.
Apple and Android runtime tests exercise their actual Keychain/Keystore signing
keys and Rust C/JNI bridge, then receive an admitted group's application message
through the encrypted vault. Negative cases include substituted KeyPackage or
group, wrong signing authority, tampering, expiry and consumed-handle replay.
Exact completed test counts and execution environments are tracked in
[validation.md](validation.md).

A public native export is independently checked using Node/OpenSSL:

```sh
node scripts/verify-enrollment-fixture.mjs native/fixtures/enrollment-v1.json
```

The checked-in vector was exported by the Android runtime proof with an expired
synthetic approval clock; its actual MLS KeyPackage was generated locally during
that test. The fixture contains only public keys, public KeyPackage, request/approval
transcripts, signatures and the test clock. The verifier checks canonical
encodings, framing, signatures, context hashes, validity window and explicit
approver pin. It does **not** parse/validate MLS membership or prove the true
origin of the identity hashes; the Rust and native runtime tests supply that
separate evidence. No private key or MLS snapshot is stored in the fixture.

Still open: Cloudflare-backed onboarding/transport and production trust bootstrap,
more than two members, general membership and revocation,
key rotation, Guardian permissions, account binding, recovery, malicious state
rollback, physical-device assurance and independent security review.
