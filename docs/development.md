# Development operations

## Accounts and local configuration

Cloudflare access is handled locally through Wrangler OAuth (`npx wrangler login`). A limited API token may be used for automated deployment later; it belongs in a secret store, not the repository. No automated deployment is configured.

Before remote commands, verify the correct account with `npx wrangler whoami`. Account and database IDs are not authentication secrets, but keep them local to separate source code from operations.

Create a new, dedicated `squadtime-dev` database with `--jurisdiction=eu`. Then set the non-secret IDs in the `CLOUDFLARE_ACCOUNT_ID` and `SQUADTIME_D1_ID` environment variables and run:

```sh
node scripts/configure-dev.mjs
npx wrangler d1 migrations apply DB --remote --config .local/wrangler.json
npx wrangler deploy --config .local/wrangler.json
```

`configure-dev.mjs` writes an ignored file with access mode 0600. It does not overwrite an existing remote configuration. It aborts without explicit IDs. Public configurations containing the null ID must not be used for remote deployment.

EU jurisdiction limits the D1 database; it does not automatically make all Worker processing EU-exclusive. Do not log content, request bodies or Authorization headers.

## Real MLS transport test

```sh
cd crypto/mls-spike
cargo build --locked --example relay_roundtrip
cd ../..
node scripts/smoke-remote.mjs
```

Set `SQUADTIME_DEV_URL` to the previously confirmed HTTPS workers.dev address of the DEV Worker. The script checks the local configuration name, creates one-time device tokens only in memory and provisions short-lived synthetic test records in the DEV database. SQL files contain only hashes and technical IDs and are deleted after use. Tokens are not put in command lines or logs.

A separate Rust process creates a real MLS message. The test sends its ciphertext through the relay, retrieves it as an authorized recipient and has the Rust process decrypt it. It also checks missing authentication, foreign membership and revocation. Test data is deleted in a `finally` block. If the test is interrupted or a network error occurs, data may remain; tokens expire within 15 minutes and events within seven days.

This is a host/backend proof. It does not replace native iOS/Android tests, device approval or recovery tests.

## Checks required before real user data

- Native key storage, atomic protocol state and restart/backup behavior.
- Authorized device enrollment, Guardian rights, membership changes and recovery.
- The redelivery case described in docs/crypto-spike.md.
- Abuse protection, quota monitoring, operational deletion/backups and deployment hardening.
- Shared test vectors for local time/game planning, time zones and daylight saving time.
