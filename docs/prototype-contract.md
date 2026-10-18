# Local device prototype contract

Draft implementation contract, 2026-10-18. Synthetic test profiles only. One pair
per installed app; no general chat, introductions, Guardian approval or production
onboarding. The first UI exercises the real durable admission and fixed encrypted
probe. The relay is a disposable process on the test Mac, not the Cloudflare API.

## Relay

Default port 8789. Configure an HTTP origin with a literal RFC1918 IPv4 address
(10/8, 172.16/12 or 192.168/16), optional port 1024..65535, no credentials/path/query/
fragment. Reject all other origins. Emulator-only loopback may be allowed in test
harnesses, never silently from a scanned invitation. Show the selected test-server
origin and require explicit approval before network access to a scanned origin;
if a server is already configured, require an exact origin match. Reject redirects.

`GET /health` -> `{"service":"squadtime-local-prototype","version":1}`.
`PUT /v1/sessions/{session}/{kind}` body `{"outbox":"<standard padded Base64>"}`.
`GET /v1/sessions/{session}/{kind}` -> same JSON. Session is 64 lowercase hex chars
from 32 secure random bytes; kind is `invitation`, `request`, `welcome`, `receipt`.
Missing/expired item: 404. First write: 201. Byte-identical retry: 200. Different
replacement: 409. Oversized body: 413. Store in memory for 30 minutes from creation,
never extend retention on reads/retries. Bound sessions and request sizes. No logs
of paths, bodies, QR data, contact names, state or keys. This relay is untrusted and
unauthenticated; session identifiers only isolate random test exchanges and are
not production authorization. DoS remains possible. Only public signed artifacts
and encrypted MLS material enter the relay. Read timeouts and bounded replies apply.

Clients must commit native durable outboxes before publishing. On a timeout,
reopen and resend the exact committed outbox, never regenerate MLS admission.
Poll only while the relevant screen is active, at about two-second intervals;
stop on background/terminal state. A server restart loses its in-memory records;
show a recoverable error rather than silently resetting device keys or vaults.

## Optional Bluetooth transfer

The foreground-only Bluetooth experiment transports the same exact public PairCode
payloads after bilateral code comparison over an authenticated channel. It keeps
the existing explicit peer/relay review, native admission and relay behavior. See
[bluetooth-prototype.md](bluetooth-prototype.md) for the separate wire contract,
limits and validation requirements. Merely discovering a BLE device grants no trust.

## QR payload

` squadtime-prototype-v1:` without the leading space, followed by canonical
unpadded Base64url of UTF-8 JSON with exactly these fields:

```
{"v":1,"type":"invite|request","relay":"http://192.168.1.2:8789","session":"<64 lowercase hex>","key":"<standard padded Base64 uncompressed 65-byte P-256 key>","hash":"<64 lowercase SHA-256 hex>","expiresAt":1700000300,"label":"Test nickname"}
```

`hash` is SHA-256 of the exact decoded native public outbox bytes for this QR's
phase, not its Base64 text. `expiresAt` is the signed native invitation expiry;
the request inherits it. Reject expired/future-invalid context, unknown fields,
bad encodings, payloads over 2048 bytes and labels over 32 Unicode code points or
containing control characters. Label is a display hint, not proof of real identity.
The origin/session must match the active exchange for a request QR.

Display a key fingerprint as SHA-256(native key bytes), full 64 lowercase hex grouped
for readability; a shortened list display must allow full comparison. Never treat
a relay-returned key as an independently trusted pin. QR scanning and explicit user
confirmation establish the prototype's pin. Manual paste is labelled as a separate
code-transfer test, not a demonstration of proximity. Neither mode proves presence,
age or Guardian approval. Camera denial has a useful retry/settings explanation.

## Sequence and state

1. Local nickname/avatar profile. User chooses **Show my code** or **Scan a code**.
2. Owner creates its own durable owner admission and starts at current Unix time.
   Upload its committed invitation; show invite QR and fingerprint.
3. Joiner scans invite, confirms the intended nearby device and test-server origin.
   Fetch invitation, verify its exact hash and native key against the QR, then create
   the durable joiner using that pin and publish its signed request. Show request QR.
4. Owner scans request, verifies session/origin and exact request hash, and explicitly
   confirms the other device. Call ownerAdmit with the scanned native key pin and
   userConfirmed=true; publish the committed Welcome. Owner displays awaiting receipt.
5. Joiner fetches Welcome and calls joinerFinish. Rust/native code authenticates the
   exact pending request/Welcome and commits joined state plus received fixed probe.
   Display the persisted probe as **Encrypted test received**; do not claim general
   user messaging. Preserve the inbox across restart until an explicit acknowledgement.
6. Joiner publishes a signed public receipt after successful committed join. Owner
   verifies it against its already scanned joiner pin before showing both sides done.

Receipt outbox is Base64 of UTF-8 JSON with exactly:
`{v:1,session,invitationHash,requestHash,welcomeHash,signature}`. Hashes use decoded
exact envelope bytes. Signature is standard Base64 canonical P-256 DER, generated by
the SAME native key that signed the request. Transcript UTF-8 with final LF:

```
squadtime-prototype-receipt-v1
{session}
{invitationHash}
{requestHash}
{welcomeHash}
```

Persist the exact receipt before publishing; after process restart resume it. Never
emit a receipt for an uncommitted join. Native admission remains authoritative;
resume after a crash between admission commit and UI metadata update must reconcile
from the durable phase, not rerun a consumed transition. Profile, peer metadata and
routing/pointers belong in encrypted local app storage; do not store MLS state in
UI preferences. Missing/replaced keys fail closed. Reset requires confirmation and
deletes only this prototype's own scoped keys/vault/metadata, not other proof apps.

The confirmed contact is a test-device binding, not an implemented production social
relationship. Introduction eligibility and multi-contact profiles will be a later
prototype step; do not show an enabled feature that merely simulates authorization.
