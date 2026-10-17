# Squadtime

Shared play sessions for friend groups, within boundaries set by parents.

**Development status:** technical foundation and protocol experiments only. This is not a finished product and is not approved for real children’s or users’ data. The native iOS and Android apps are not implemented. A limited native device-signing and approval proof now has simulator and emulator evidence; it is neither complete enrollment nor MLS integration. Guardian permissions and recovery are also open. See [native/README.md](native/README.md) and [docs/device-pairing-proof.md](docs/device-pairing-proof.md).

## Components

- `backend/`: Cloudflare Worker with an authenticated relay for opaque encrypted events; D1 migration.
- `api/openapi.yaml`: shared API contract for the DEV relay.
- `crypto/mls-spike/`: runnable MLS protocol tests with freshly generated test identities.
- `docs/architecture.md`, `docs/threat-model.md`, `docs/decisions.md`: architecture, boundaries and open decisions.
- `docs/crypto-spike.md`: library comparison, evidence and known integration limits.
- `docs/mls-state-transactions.md`: application-message receive with staged MLS state and its transaction boundaries.
- `native/README.md`, `docs/device-pairing-proof.md`: implemented device-approval proof and its limited scope.
- `squadtime-konzept.md`: original product concept; newer architecture decisions govern technical deviations.

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

For MLS application messages, `ApplicationReceiver` stages candidate state and persists it only after successful authentication and policy checks. Under atomic-storage and single-writer assumptions, this addresses the observed generation consumption in direct raw receive. It does not provide a durable mobile inbox or crash, rollback or multi-process safety. See [docs/mls-state-transactions.md](docs/mls-state-transactions.md) for details and open limits.

## Cloudflare development

The public `wrangler.jsonc` contains only a local placeholder database. The remote setup is described in [docs/development.md](docs/development.md). Deployment configuration, credentials and local state stay outside Git. Worker observability is disabled in DEV; application code does not log request headers or content.

## Publication and checks

```sh
npm run check:secrets
npm run check:secrets -- --staged
```

The local guard checks common secret formats and filenames; it is not a guarantee. Gitleaks also runs in GitHub Actions. CI runs the backend and MLS tests. A separate native workflow performs build-only checks with Apple Xcode 26.3 on macOS 15 and Android JDK 17 on Ubuntu 24.04; native runtime test results are local. No deployment secrets are needed in GitHub.

Public source enables inspection but does not replace an independent security audit. An open-source license has not yet been chosen; public visibility alone does not grant a general license.
