# Foreground Bluetooth pairing prototype

Experimental application-layer ceremony, version 1, 2026-10-18. Synthetic test
profiles only. This is not an independently reviewed authentication protocol, OS
Bluetooth Secure Connections, production onboarding, or proof of physical
presence, identity, age, or Guardian authority. Bluetooth and the LAN relay remain
untrusted. The existing native MLS admission, signed receipt and durable outboxes
remain authoritative. QR scanning remains an explicit fallback.

The owner advertises the fixed prototype service and the joiner connects. Device
names, discovery order, RSSI and BLE addresses establish no trust. Advertisements
must not contain profile labels, native keys or admission payloads. Lock one peer
and one ceremony; never silently switch a connected peer. No background pairing.

## GATT transport

The owner advertises service `9B0A1000-6E7D-4C56-9E2A-4D6E53515431`.
Characteristic `9B0A1001-6E7D-4C56-9E2A-4D6E53515431` accepts writes with
response from the joiner; `9B0A1002-6E7D-4C56-9E2A-4D6E53515431` notifies
messages to the joiner using the standard CCCD subscription. Wait for subscription
confirmation before starting the ceremony. Each complete binary message has a
four-byte big-endian length prefix and is split into chunks of at most 20 bytes.
Process writes/notifications with callback-driven backpressure; never interleave
frames. Limit complete payloads to 2092 bytes and queued transport data to 64 KiB.
Scan for at most 60 seconds and retain at most eight discovery candidates.

## Encoding and cryptography

All integers are unsigned big endian. Concatenation below joins exact bytes, with
no delimiters beyond those specified. ASCII domain strings include their final LF
(`0a`), never a NUL. Roles are owner `00` and joiner `01`. P-256 public points use
the 65-byte uncompressed X9.63 encoding, including `04`. Use platform P-256 ECDH,
SHA-256, HMAC-SHA256 and AES-GCM implementations; do not implement curve or cipher
arithmetic. Validate imported points with the platform and reject malformed points,
infinity and unsupported curves. ECDH `Z` is the raw 32-byte, zero-padded big-endian
shared X coordinate. HKDF is exactly RFC 5869 with SHA-256.

For each user-started ceremony generate a fresh owner session ID `sid` (16 random
bytes), independent ephemeral P-256 key pairs, and independent 32-byte random
nonces `No` and `Nj`. Never use the native signing keys for ECDH. Never reuse an
ephemeral key, session ID or nonce after an attempt ends. Secrets and ceremony
state stay in memory and are never logged or persisted.

```
Co = SHA256(ASCII("squadtime-ble-commit-v1\n") || sid || 00 || Po || No)
Cj = SHA256(ASCII("squadtime-ble-commit-v1\n") || sid || 01 || Pj || Nj)
T  = ASCII("squadtime-ble-transcript-v1\n") || sid || Co || Cj || Po || No || Pj || Nj
th = SHA256(T)
K  = HKDF-SHA256(IKM=Z, salt=th, info=ASCII("squadtime-ble-keys-v1\n"), length=160)
```

Split `K` in order into five 32-byte keys: `Ksas`, `KconfirmO`, `KconfirmJ`,
`KaeadO`, `KaeadJ`. The short authentication string is the first four bytes of
`HMAC-SHA256(Ksas, ASCII("squadtime-ble-sas-v1\n") || th)`, interpreted as a
big-endian integer modulo 1,000,000 and displayed as exactly six decimal digits,
including leading zeroes. Do not transmit the displayed code. Both people must
compare the complete code on the intended devices and explicitly select **Codes
match** on both devices. A mismatch ends this attempt; no automatic retry.

## Role-ordered messages

The GATT transport reassembles bounded complete messages before protocol parsing.
Each message has exactly the listed size; reject missing or trailing bytes.

| Type | Direction | Exact complete message | Bytes |
| --- | --- | --- | --- |
| `01` | owner to joiner | `01 || sid || Co` | 49 |
| `02` | joiner to owner | `02 || sid || Cj` | 49 |
| `03` | owner to joiner | `03 || sid || Po || No` | 114 |
| `04` | joiner to owner | `04 || sid || Pj || Nj` | 114 |
| `05` | owner to joiner | `05 || sid || confirmO` | 49 |
| `06` | joiner to owner | `06 || sid || confirmJ` | 49 |

Both commitments must be irrevocably fixed before either reveal. The joiner must
send its commitment before accepting the owner's reveal. The owner must accept
the joiner's commitment before sending its reveal. Verify the respective
commitment before computing/displaying the code. Reject equal public points or
equal nonces. Never replace a previously accepted commitment or reveal.

```
confirmO = HMAC-SHA256(KconfirmO, ASCII("squadtime-ble-confirm-v1\n") || th || 00)
confirmJ = HMAC-SHA256(KconfirmJ, ASCII("squadtime-ble-confirm-v1\n") || th || 01)
```

Messages 05 and 06 can arrive in either order, but each is sent only after its
sender's local user selects **Codes match**. Verify the peer MAC in constant time.
The channel is usable only after local approval, sending the local confirmation,
and verifying the peer confirmation. Receiving a peer confirmation alone grants
no trust. Disallow application data before this state. Direction-specific keys
and role bytes prevent treating a reflected local confirmation as a peer approval.

## Authenticated PairCode transfer

After mutual confirmation, transfer the exact existing UTF-8 PairCode string from
`docs/prototype-contract.md`. Do not parse and reserialize before transmission.
Each direction sends exactly one encrypted payload: owner invitation first, then
joiner request after the existing explicit native confirmation and durable commit.
Each uses sequence number zero. No other application messages are defined.

```
H     = 10 || sid || senderRole:u8 || seq:u64 || cipherLen:u16
nonce = 00000000 || seq:u64
AAD   = ASCII("squadtime-ble-data-v1\n") || th || H
frame = H || AES-256-GCM(directionKey, nonce, exactPairCodeUTF8, AAD)
```

`10` is one hexadecimal type byte. AES-GCM output is ciphertext followed by the
full 16-byte tag, with no nonce in the output. The owner uses `KaeadO`; the joiner
uses `KaeadJ`. Plaintext is 1..2048 bytes, `cipherLen` is plaintext length plus 16
(17..2064), and the header is 28 bytes. Maximum complete frame size is 2092 bytes.
Verify exact frame length, expected direction, session, phase and sequence before
decrypting; release no plaintext before tag authentication. Strictly decode UTF-8
and run all existing PairCode validation after decryption. Cache an already sealed
frame if the transport needs an identical resend; never seal different plaintext
under the same key/nonce. Reject a repeated delivered application sequence.

Receiving the authenticated invitation only supplies the independent native key
pin. The joiner still reviews the intended peer and test-server origin and explicitly
confirms the existing native flow. Only then may its durably committed request
PairCode be encrypted and sent. The owner reviews and explicitly confirms that
request before `ownerAdmit(... userConfirmed=true)`. A successful SAS check must
never automatically call either native confirmation. The full native fingerprint
remains available for inspection; BLE verification replaces the need to compare
its full text during this ceremony. Relay origin/session/expiry/hash and exact
native key checks are unchanged. Welcome, encrypted probe and signed receipt still
use the existing relay and native admission flow.

## Failure, cancellation and bounded transport

Abort on backgrounding, disconnect, local cancellation, bad point/commitment/MAC/
tag, wrong role/session/phase/counter/length, premature application data, unexpected
messages, or peer change. Reject duplicates at the protocol layer; transport-level
reassembly must not deliver duplicate messages. Clear volatile keys, unverified
peer candidates and partial buffers; stop advertising/scanning and close GATT.
Never persist a pending unverified native pin. No persistent OS bonding is required.

Use a 180-second overall ceremony limit, a 15-second idle limit during the four
commit/reveal messages, 90 seconds for code comparison, and 60 seconds waiting for
each application payload. The overall deadline and native invitation expiry always
win; activity and retries never extend them. Reject/bound complete messages before
allocation (2092 bytes), allow one incomplete message per direction, bound fragment
counts and completion time, and serialize state transitions. GATT fragmentation is
transport framing only and must not influence the cryptographic transcript.

Retry is an explicit user action with entirely fresh ceremony material. Preserve
already committed native admission/outboxes; do not regenerate MLS state or reset
device keys. A resumed joiner with an already committed request must match the
owner's invitation to its saved session/hash/pin, then send that exact request,
without rerunning a consumed native transition. QR fallback remains available for
the same committed artifacts. Imported, fully authenticated PairCodes are still
subject to the existing explicit review and expiry rules.

## Security limits and verification

Commit-before-reveal prevents an interposer from choosing fresh key/nonce values
after learning the honest participants' complete contributions. It is essential
for a short code; see the commitment rationale in
[RFC 6189, section 4.4.1.1](https://www.rfc-editor.org/rfc/rfc6189.html#section-4.4.1.1).
This specification is a separate bounded experiment, not an implementation or
security proof of ZRTP. Six decimal digits have limited authentication strength
and require attentive human comparison; explicit retries are new attempts.
Forwarding the whole ceremony remains possible, so BLE does not prove proximity.
Compromised devices and users approving unequal codes remain outside its protection.

`native/fixtures/ble-pairing-v1.json` contains public deterministic reference values
only. Its small synthetic scalar inputs are constructed in tests; it contains no
private keys or derived secret keys. The reference test independently computes the
public commitments, transcript hash, code, confirmation MACs and AES-GCM frames,
and checks changed commitments, reflected role MACs and altered ciphertext/AAD.
Platform tests must additionally verify state gating, cancellation/backgrounding,
timeouts, message order/size/replay bounds, rejection of malformed public points,
and existing origin/session/native pin validation. Passing reference vectors or
builds alone does not prove a real Apple-to-Android BLE exchange or production
authentication.
