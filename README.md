# Squadtime

Shared play sessions for friend groups, with safe defaults and optional parent management.

**Development status:** technical foundation and protocol experiments only. This is not a finished product and is not approved for real children’s or users’ data. Separate iOS and Android development apps now expose a local profile, mutual QR key confirmation, an experimental foreground Bluetooth comparison flow, one direct test contact, and a fixed encrypted MLS probe through a disposable LAN relay. These are synthetic test apps; production onboarding and messaging are not implemented. Native proofs now cover device approval, encrypted MLS receive state, and a bounded initial admission between separate administrator and joining-client processes. The admission harness exchanges public envelopes through local file transport using pre-provisioned test pins. Both Apple-to-Android and Android-to-Apple exchanges passed with fresh app processes between phases. Cloudflare onboarding/transport, account and Guardian authority, recovery, and general membership remain open. See [native/README.md](native/README.md), [docs/independent-admission.md](docs/independent-admission.md), and [docs/device-pairing-proof.md](docs/device-pairing-proof.md).

## Components

- `docs/prototype-testing.md`, `docs/prototype-contract.md`: build/run guide and shared contract for the interactive local device prototypes.
- `docs/bluetooth-prototype.md`: experimental Bluetooth commitment, comparison and authenticated key-transfer contract; hardware verification is separate from build and protocol tests.
- `backend/`: Cloudflare Worker with an authenticated relay for opaque encrypted events; D1 migration.
- `api/openapi.yaml`: shared API contract for the DEV relay.
- `crypto/mls-spike/`: runnable MLS protocol tests with freshly generated test identities.
- `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions.md`: architecture, boundaries and open decisions.
- `docs/onboarding.md`: accepted player-initiated onboarding, separate consent and optional Guardian access; implementation remains open.
- `docs/crypto-spike.md`: library comparison, evidence and known integration limits.
- `docs/mls-state-transactions.md`: staged MLS receive behavior and transaction boundaries.
- `docs/durable-native-state.md`: native encrypted MLS checkpoint/inbox proof and its limits.
- `docs/mls-device-binding.md`: earlier same-process native-signature binding proof.
- `docs/independent-admission.md`: successor proof for separate administrator and joining-client processes, with public-envelope exchange and encrypted admission state.
- `native/README.md`, `docs/device-pairing-proof.md`: implemented device-approval proof and its limited scope.
- `squadtime-konzept.md`: product concept, including the revised onboarding direction; architecture decisions govern technical deviations.

## Run locally

Requirements: Node.js 22 or later and npm. Rust 1.90.0 and a C compiler are needed only for the separate MLS evaluation.

```sh
npm ci
npm run hooks:install
npm run types
npm run typecheck
npm test
npx wrangler d1 migrations apply DB --local
npm run dev
```

`GET /health` is public. Group routes require a pre-provisioned test device with a random 256-bit bearer token. Only the token’s SHA-256 hash is stored in D1; the token has limited validity. There is no public registration or bootstrap API.

## Relay boundaries

The relay can check authorization, format, size and concurrent writes. It cannot prove that a Base64 payload is actually encrypted or that an MLS membership change is authorized. Authorized clients must perform those checks.

Events remain available through the API for at most seven days. Hourly cleanup removes up to 1,000 expired records per run; provider backups may persist longer. The group revision is retained. Missing history returns HTTP 410 and requires an authorized state-resynchronization flow, which is not yet implemented. This is not a durable calendar backup.

The group history returns at most 100 events per page. Identical event retries are idempotent during the event’s retention period. After expiry, the client must use the current revision and create a new event. The server revision protects against ordinary write conflicts, not a malicious server.

For MLS application messages, `ApplicationReceiver` stages candidate state and persists it only after successful authentication and policy checks. The native proof now connects the real Rust MLS receive path to encrypted SQLite storage that atomically checkpoints MLS state with a pending inbox item, using platform-keystore-protected AES keys and revision compare-and-swap. This is limited synthetic two-peer receive proof; it does not prove power-loss durability, malicious-database rollback protection, complete app integration or production E2EE. See [docs/durable-native-state.md](docs/durable-native-state.md) and [docs/mls-state-transactions.md](docs/mls-state-transactions.md).

## Cloudflare development

The public `wrangler.jsonc` contains only a local placeholder database. The remote setup is described in [docs/development.md](docs/development.md). Deployment configuration, credentials and local state stay outside Git. Worker observability is disabled in DEV; application code does not log request headers or content.

## Publication and checks

```sh
npm run check:secrets
npm run check:secrets -- --staged
```

The local guard checks common secret formats and filenames; it is not a guarantee. Gitleaks also runs in GitHub Actions. CI runs the backend and MLS tests. A separate native workflow performs build-only checks with Apple Xcode 26.3 on macOS 15 and Android JDK 17 on Ubuntu 24.04; native runtime test results are local. No deployment secrets are needed in GitHub.

Public source enables inspection but does not replace an independent security audit. An open-source license has not yet been chosen; public visibility alone does not grant a general license.
