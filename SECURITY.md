# Security

Squadtime is a development-stage prototype. Do not use it with real child/user data yet. Known limitations and the MLS redelivery finding are documented in `docs/threat-model.md`, `docs/crypto-spike.md` and `docs/validation.md`.

Please use GitHub private vulnerability reporting for sensitive findings once enabled on this repository. Do not include real credentials, personal data or exploitable details in public issues. For non-sensitive design discussion, a public issue is appropriate.

Public source and passing tests are not an independent security audit. The project does not currently offer a production security support or response-time commitment.

Credentials must never be committed. If one is exposed, revoke or rotate it first; removing the file or rewriting history alone does not invalidate the credential.
