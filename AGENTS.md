# Squadtime development instructions

## Scope and safety

This repository is public source for a development-stage family scheduling app.
Read README.md, docs/decisions.md and docs/threat-model.md before architectural changes.
Do not claim production E2EE, native-app validation or recovery support based on the protocol spike.

## Secrets and external state

- Never put credentials, private keys, access tokens, live test identities or user data in Git, logs, command arguments or documentation.
- Deployment identifiers belong in ignored .local/wrangler.json. Credentials belong in local environment configuration or provider secret stores.
- Never run remote migrations against an inferred account. Verify the selected account and use the explicit local configuration.
- Use synthetic data for the DEV relay. No public signup until identity and authorization are designed.
- Before a push: inspect staged scope, run npm run check:secrets -- --staged and a redacted Gitleaks scan. No token values in output.
- Automatic workflows have read-only repository permissions and no deployment credentials.

## Delegation

The project owner explicitly requests delegation wherever useful, using the smallest suitable model.
Use a small model for documentation and bounded routine tasks; use a stronger model when cryptographic or security-critical reasoning warrants it.
Give agents disjoint file ownership. The integrating agent reviews changes and verifies results.

## Validation

- Backend: npm run types after Wrangler/config changes; npm run typecheck; npm test.
- Crypto: cargo test --locked, cargo fmt --check, cargo clippy --locked --all-targets -- -D warnings from crypto/mls-spike.
- Preserve the checked-in lockfiles; review security advisories when changing dependencies.
- Tests must check observable security properties, not merely repeat implementation logic.
