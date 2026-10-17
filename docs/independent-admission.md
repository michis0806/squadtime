# Independent native admission and durable outbox

This development proof separates the existing group administrator and joining
client into independent secret states. Apple and Android can exchange the public
protocol envelopes without sharing a Rust registry, private key, MLS snapshot or
KeyPackage private storage. The scope is one administrator admitting one new
client into a fresh two-member group. It is not a complete account system,
Guardian policy, general group membership implementation or production E2EE.

The earlier [local binding experiment](mls-device-binding.md) remains available.
The new `admission*` commands use different signed transcript domains and a
stateless candidate API. Exact runtime and restart evidence is recorded in
[validation.md](validation.md); the executable test harness is described below.

## Trust and signed wire protocol

The joiner must receive the administrator's native P-256 public key through a
separately trusted channel. The administrator must explicitly approve a separately
verified new-device P-256 key. A signature whose public key arrives in the same
untrusted envelope is not a trust anchor. The test harness provisions those pins
from the other locally controlled test app, outside the exchanged envelopes.
This is test trust provisioning, not a finished QR, fingerprint or account
verification ceremony. The backend cannot establish these bindings for clients.

An administrator creates its own MLS identity and a single-member group, then
signs an invitation binding its native key, MLS identity, group and expiry.
The joiner verifies that invitation against its prior native-key pin, creates
its own MLS identity and KeyPackage, and signs a request bound to the exact
invitation bytes. The administrator validates the request and approved device
pin before signing the admission authorization. Rust verifies every signature
again before performing the actual MLS Add and processing Welcome.

MLS authenticates Welcome using the administrator MLS identity that was bound
by the signed invitation. The recipient checks its exact persisted request,
the native approval, group, both MLS identities and the resulting two-member
roster. A matching public group ID alone does not authorize a Welcome.

All byte fields use canonical standard padded Base64. SHA-256 hashes use
lowercase hexadecimal. Transcripts are UTF-8 with LF separators and a final LF;
JSON serialization is never the signed transcript. Native signatures are
P-256/SHA-256 with canonical ASN.1 DER and valid nonzero scalars below the curve
order; high-S signatures remain accepted for platform compatibility.

Invitation transcript:

```text
squadtime-mls-invitation-v1
{invitationId}
{groupId}
{sha256(adminIdentityBytes)}
{adminPublicKey}
{issuedAt}
{expiresAt}
```

Request transcript:

```text
squadtime-mls-admission-request-v1
{requestId}
{sha256(exactSignedInvitationBytes)}
{groupId}
{sha256(keyPackageBytes)}
{sha256(joinerIdentityBytes)}
{sha256(adminIdentityBytes)}
{devicePublicKey}
{adminPublicKey}
{issuedAt}
{expiresAt}
```

Approval transcript:

```text
squadtime-mls-admission-approval-v1
{requestId}
{sha256(requestTranscriptBytes)}
{sha256(exactSignedInvitationBytes)}
{groupId}
{sha256(adminIdentityBytes)}
{devicePublicKey}
{adminPublicKey}
{expiresAt}
```

Identity bytes are the pinned MLS library's `SigningIdentity` encoding, including
credential and signing public key. Both random IDs contain 32 bytes. The native
public keys must differ. The invitation lasts 300 seconds; a request inherits its
expiry and cannot predate the invitation. Initial request publication and the
administrator's new admission must occur before expiry. An already-authorized,
committed Welcome can arrive later: joining rechecks the exact pending context
and signatures without authorizing another Add. Resume only returns existing
outbox bytes; it does not renew expiry or issue a new approval. Clocks are caller
inputs and are not protected against malicious clock rollback.

Public outboxes are Base64 of the **exact** following JSON envelope bytes:

| Envelope | Fields |
| --- | --- |
| Invitation | `version:1`, `invitationId`, `groupId`, `adminIdentity`, `adminPublicKey`, `issuedAt`, `expiresAt`, `signature` |
| Request | `version:1`, `requestId`, `invitation`, `keyPackage`, `joinerIdentity`, `devicePublicKey`, `issuedAt`, `expiresAt`, `signature` |
| Welcome | `version:1`, `request`, `approvalSignature`, `welcome`, `probe` |

Nested `invitation` and `request` fields preserve the exact signed envelope
bytes, not a reconstructed JSON object. The `welcome` field is real MLS Welcome;
`probe` is a real MLS application ciphertext with fixed synthetic test content.
The probe is only an interoperability check, not a general sending API.

## State and transaction boundary

The bridge has no file or network access. Each operation receives a role-specific
secret state and returns a candidate successor. An administrator state never
contains the joiner's MLS private keys, and a joiner state never contains the
administrator's private keys. The native P-256 private keys remain in their
platform key stores. MLS secrets remain software keys inside encrypted local
state, not Secure Enclave or hardware-isolated MLS keys.

```mermaid
sequenceDiagram
  participant A as Administrator native vault
  participant B as Joining native vault
  A->>A: Commit own state and signed invitation outbox
  A->>B: Public signed invitation
  B->>B: Verify trusted pin; commit own state and request outbox
  B->>A: Public signed request
  A->>A: Explicit approval; commit Add state and Welcome outbox
  A->>B: Stored Welcome and encrypted probe
  B->>B: Verify and join; commit joined state and received inbox
```

Apple and Android admission stores put phase, role-specific Rust state, exact
public outbox, trust pins and pending received messages into one authenticated
encrypted SQLite row. A captured revision is the condition for committing the
entire next row. Losing concurrent writers cannot release their candidate
Welcome. A fault before commit leaves the previous state available for retry;
an uncertain result after commit invalidates that instance. Reopening reads the
authoritative committed row and returns the same outbox without regenerating
signatures, KeyPackages, commits or encryption keys.

Joining and receiving the fixed probe use the same admission store. There is no
handoff from a consumed admission to a separate vault database. Accepted
plaintext is exposed only after its updated MLS receive state and inbox item
are committed. Inbox delivery remains at least once until acknowledged; callers
must apply business effects idempotently. Acknowledging an inbox item does not
undo the MLS replay protection stored with it.

Only persisted outboxes may be returned to transport. Their retransmission is
safe; receiving an already-consumed request/Welcome must not trigger another
membership operation. This proof retains its one outgoing envelope and has no
general transport acknowledgment/retention queue. Native API callers must not
bypass the store and publish raw Rust candidates. The initial group has one
existing member, so no multi-administrator or competing remote-commit consensus
is established. [RFC 9420 section 14](https://www.rfc-editor.org/rfc/rfc9420.html#section-14)
describes the ordering requirement between accepted commits and Welcome delivery.

## Bridge commands

Each JSON call includes `op` with the command below. `state` is **secret** Base64
of a local state blob. It must never enter the relay, logs, public exports,
command arguments, plaintext fixture files or crash attachments. Outbox and
transcript byte fields are Base64. `now` is a nonnegative integer Unix timestamp
within JavaScript's safe integer range.

| Command | Inputs apart from `op` | Result |
| --- | --- | --- |
| `admissioncreateadmin` | `adminPublicKey`, `now` | `state`, `transcript` |
| `admissionpublishinvitation` | `state`, `signature`, `now` | `state`, `outbox`, `kind:"invitation"` |
| `admissioncreatejoiner` | `invitation`, `trustedAdminPublicKey`, `devicePublicKey`, `now` | `state`, `transcript` |
| `admissionpublishrequest` | `state`, `signature`, `now` | `state`, `outbox`, `kind:"request"` |
| `admissioninspectrequest` | `state`, `request`, `trustedDevicePublicKey`, `now` | `transcript` |
| `admissionadmit` | `state`, `request`, `trustedDevicePublicKey`, `approvalSignature`, `now` | `state`, `outbox`, `kind:"welcome"` |
| `admissionjoin` | `state`, `welcome`, `now` | `state`, empty `outbox`, `kind:"joined"` |
| `admissionresume` | `state` | Previously stored `outbox`, `kind` |
| `admissionreceive` | `state`, `packet` | `state`, `plaintext`, `senderIndex` |

A ready MLS snapshot remains inside the opaque role state. Draft states cannot
be resumed as published outboxes. Reusing a terminal state for a second Add or
join is rejected. Decoded state is bounded to 512 KiB and public outbox to
128 KiB; native encrypted-row bounds may impose a tighter combined limit.
Native wrappers validate the returned public transcript against local intent
before invoking their signing key, then validate the published envelope again.
Unknown fields, unsupported versions and invalid encodings fail closed.

## Repeatable native exchange

Build the shared Rust artifacts and native proof hosts first. Install the newly
built host/test APKs on a task-owned Android emulator, and the Apple test host on
a task-owned booted Simulator. Generate/build the `AdmissionExchangeProof`
scheme into the selected derived-data directory. The existing main native test
suites exercise failure injection and policy rejection; the exchange scheme and
Android runner are deliberately separate from ordinary tests.

```sh
node scripts/run-admission-exchange.mjs \
  --simulator SIMULATOR_UUID --android emulator-5580 \
  --derived .local/admission-derived --direction both
```

The harness exchanges only validated public envelope wrappers and separately
provisioned test trust pins. It terminates the exact proof host between phases,
records fresh process IDs, checks byte-identical outbox resume, delivers an
already-committed Welcome after its admission deadline, verifies the persisted
received message after another restart, rejects consumed ciphertext, and cleans
scoped state on success. A failed run preserves its scoped diagnostics for
inspection instead of silently resetting state. It does not boot, shut down or
choose arbitrary user devices. Build logs and public test evidence stay ignored
under `.local/admission-exchange/`.

The public fixture can be independently checked with Node/OpenSSL:

```sh
node scripts/verify-admission-fixture.mjs native/fixtures/admission-v1.json
```

That verifier checks the public signatures, transcript/context bindings, nesting,
expiry and explicit test pins. It does not decode MLS or authenticate Welcome
and the probe itself; the Rust and native exchange tests cover that separate
boundary. No private state belongs in this fixture.

## Remaining boundaries

Process restart and injected commit failures do not prove sudden-power-loss,
device reboot or hardware protection. The proof uses synthetic identities and
pre-provisioned test pins, with public envelopes copied by a local test harness;
it is not Cloudflare onboarding or a deployed native transport. Full user
verification, account/Guardian rights, more than two members, general message
sending, membership revocation and rotation, multi-device consistency, recovery,
state migrations, reliable trusted time, malicious database rollback protection
and independent security review remain open. Initial vault/key creation assumes
one provisioning owner; concurrent cross-process key provisioning is not
established. Replacing a database with an older valid encrypted copy can restore
an old state; revision CAS alone is not a
trusted monotonic counter. Whole-process erasure of native/managed temporary
buffers is not established.
