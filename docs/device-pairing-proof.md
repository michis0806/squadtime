# Native device approval: limited protocol proof v1

This experiment checks approval for a **native P-256 device key**. It is not finished account registration, proof of guardianship, verified device attestation or enrollment into an MLS group. A camera feature or complete QR user flow is outside this technical proof. The separate [local MLS binding proof](mls-device-binding.md) adds native signatures around actual MLS admission; its transcript domains and scope differ from pairing v1.

## Trust boundary

The new device holds its private signing key in the operating system. An already trusted device approves the exact pending request. The recipient already knows the approver’s public key **through an independent trusted channel**. A key supplied by the relay or by the approval itself must not replace this trust anchor.

In the tests, this independent trust anchor is an explicit pin. The real process for establishing that pin through an in-person checked QR exchange or another reviewed method remains open. A signed request proves possession of a key, not a person’s identity or parental authority.

## Format and standard primitives

- ECDSA over NIST P-256, SHA-256, ASN.1-DER signature, lowercase hex in transport.
- Public keys: uncompressed SEC1/X9.63 representation, 65 bytes (`04 || x || y`), lowercase hex.
- UUIDs: exactly 36 ASCII characters, lowercase with hyphens. Challenge: 32 cryptographically random bytes, lowercase hex.
- Time: nonnegative integer Unix seconds up to 2^53-1; no floating-point or exponential representation in signed text.
- JSON is transport only. Sign the fixed UTF-8 transcripts below, with LF line endings and a final LF. This makes signatures independent of JSON field order and whitespace.

Request fields: `version` (1), `requestId`, `deviceId`, `challenge`, `publicKey`, `issuedAt`, `expiresAt`, `signature`.

```text
squadtime-pairing-request-v1
{requestId}
{deviceId}
{challenge}
{publicKey}
{issuedAt}
{expiresAt}
```

Approval fields: `version` (1), `requestId`, `requestDigest`, `approverPublicKey`, `signature`. `requestDigest` is the SHA-256 digest of the complete request transcript, in lowercase hex.

```text
squadtime-pairing-approval-v1
{requestId}
{requestDigest}
{approverPublicKey}
```

Both transcripts end with a line feed. The word `signature` and the signature itself are not transcript fields. The separate fixed prefixes bind signatures to their purpose and protocol version. Validate all field formats and curve points before use.

## Verification and one-time use

1. The new device creates a request and challenge locally and retains the pending request.
2. The approver checks the format, valid request signature and time window: `issuedAt <= now < expiresAt` and `0 < expiresAt - issuedAt <= 300`.
3. After explicit approval, the approver signs the request digest together with their own public identity.
4. The recipient compares the approval with its locally pending request and separately pinned approver key, then checks both signatures and the time again.
5. Only successful completion consumes the pending request. Errors must not consume it. A second completion of the same request is rejected.

The proof coordinators initially keep pending/consumed state in memory. **No replay or rollback protection across restarts is promised.** That requires atomic local storage together with the authorized device registry. Expired requests, or requests no longer known after restart, must not become trusted again based on a server response.

## Test vectors and source code

`native/fixtures/pairing-v1.json` contains only public keys, signatures, non-secret test challenges and expired synthetic timestamps. `scripts/generate-pairing-fixture.mjs` creates it using ephemeral private test keys without exporting them. The native tests use the same vector. `scripts/verify-pairing-fixture.mjs` independently verifies native public exports with Node/OpenSSL.

The native API exports only public keys. Apple Simulator tests explicitly use software Keychain keys; a simulator cannot prove Secure Enclave behavior on real hardware. Android tests use AndroidKeyStore and report the security level returned by the provider; an emulator does not prove physical TEE/StrongBox security.

## Remaining integration boundaries

- Complete, personally verified QR ceremony and defense against a fully replaced invitation.
- Bind the approved P-256 device key to account permissions and the separate MLS signing key.
- Authorized membership changes, revocation, multiple parents and transfer of a child account.
- Encrypted, atomic storage of MLS state with platform-specific protection keys.
- Key recovery and policies for devices without suitable secure hardware.

Sources: [Apple Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [Android Keystore](https://developer.android.com/privacy-and-security/keystore). Product integration needs independent review; standard primitives alone do not make an enrollment protocol secure.
