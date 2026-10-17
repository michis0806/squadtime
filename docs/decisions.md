# Architecture decisions

Statuses refer to the current project state. “Accepted” means a direction has been chosen; it does not claim that operation is production-ready.

## Accepted

### A-001: Cloudflare backend with EU data storage

**Decision:** API on Cloudflare Workers with TypeScript, D1 in the EU. R2 in the EU may be added later as needed.

**Reason:** A serverless shared API and EU data storage for the planned service.

**Boundary:** Cloudflare is a US company. EU storage location alone does not answer questions about data processing terms or possible cross-border access.

### A-002: End-to-end encryption and local planning

**Decision:** Private profiles and game inventories, plus availability and events per group, are encrypted on clients. Availability overlaps and suggested times are calculated locally.

**Consequence:** No server-side master key. Necessary IDs, routes and operational metadata remain visible. The family area is separate from group areas.

### A-003: Keep login and device keys separate

**Decision:** Passkey/login is not a substitute for device key material. Device encryption, Guardian approval and recovery require their own explicitly authorized model.

**Status:** Principle accepted; specific protocols and flows remain open.

### A-004: Development relay before identity onboarding

**Decision:** Start with a DEV relay for synthetic test clients and random, limited-lifetime bearer credentials whose hashes are stored.

**Boundary:** No public account creation and no finished end-user identity onboarding.

### A-005: No secrets in Git

**Decision:** No credentials, private keys, tokens or production account identifiers in Git. Public repository content must not contain private account email addresses or Cloudflare account IDs.

## Open

- **Key lifecycle:** generation, device binding, rotation, backup, recovery and deletion.
- **Device approval and membership:** the [local binding proof](mls-device-binding.md) ties native P-256 signatures to exact MLS identities, KeyPackage and initial group admission. Independent-device trust bootstrap, account/Guardian authority, durable membership transactions and revocation remain open.
- **Past data after revocation:** revoked clients must not read future content after rotation. A client cannot forget content it has already decrypted or stored; past access cannot be undone.
- **Guardian model:** explicit, limited and revocable access and recovery rights that preserve separation between family and group areas.
- **Malicious server and key substitution:** how clients detect and verify that keys have not been replaced by the server.
- **Replay and rollback:** authenticate ordering, version/epoch and membership state, and detect stale state.
- **Metadata:** exact inventory of visible IDs, routes, timestamps, sizes and retention.
- **Protocol choice:** MLS is under evaluation; no production choice has been made.
- **Push granularity:** trade-offs between timely updates and inferences from delivery timing.

## Security guidelines until resolved

Do not log plaintext, keys or access tokens. Use synthetic relay data. Do not claim that E2EE hides routing metadata, push timing, already-read data or compromised devices.
