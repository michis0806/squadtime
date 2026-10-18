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

### A-006: Let players initiate onboarding without a parent account

**Decision:** Start with one player profile, a nickname/avatar and automatically
created local device identity. A parent does not first need to install the app or
create a player profile. Required parental consent uses a separate focused flow;
optional Guardian management can be linked later and can cover multiple children.

**Boundary:** Local preparation does not authorize remote personal-data processing
or group membership. Required consent, age/region eligibility, Guardian authority
and device trust remain distinct checks. Download approval is not automatically
app-specific consent. Login/consent does not grant decryption or recovery rights.
Independent profile management does not prove adulthood.

**Status:** Product direction accepted; verification mechanisms and the legal basis
remain to be reviewed. Public registration is still disabled. See
[onboarding.md](onboarding.md).

## Open

- **Key lifecycle:** generation, device binding, rotation, backup, recovery and deletion.
- **Device approval and membership:** the [independent admission proof](independent-admission.md) ties native P-256 signatures to actual MLS identities, KeyPackage and initial one-administrator/one-joiner admission to a two-member group, using separate role-local secret state, encrypted rows, revision CAS and resumable public outboxes. A local harness exchanges public envelopes via a local file transport between independent app processes with pre-provisioned test pins. Both Apple-to-Android and Android-to-Apple exchanges passed with process restarts between phases. Cloudflare-backed onboarding/transport, production trust bootstrap, account/Guardian authority, general membership changes and revocation remain open. The older [same-process proof](mls-device-binding.md) is retained as a separate experiment.
- **Past data after revocation:** revoked clients must not read future content after rotation. A client cannot forget content it has already decrypted or stored; past access cannot be undone.
- **Guardian model:** explicit, limited and revocable access and recovery rights that preserve separation between family and group areas.
- **Malicious server and key substitution:** how clients detect and verify that keys have not been replaced by the server.
- **Replay and rollback:** authenticate ordering, version/epoch and membership state, and detect stale state.
- **Metadata:** exact inventory of visible IDs, routes, timestamps, sizes and retention.
- **Protocol choice:** MLS is under evaluation; no production choice has been made.
- **Push granularity:** trade-offs between timely updates and inferences from delivery timing.

## Security guidelines until resolved

Do not log plaintext, keys or access tokens. Use synthetic relay data. Do not claim that E2EE hides routing metadata, push timing, already-read data or compromised devices.
