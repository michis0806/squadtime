# Squadtime threat model

## Assets

- Private profiles and game inventories
- Availability, invitations, responses and group events
- Separate family and group areas, including Guardian rights
- Device and group keys, plus the integrity of membership and history
- DEV relay credentials and operational data

## Assumptions and boundaries

Clients encrypt content end to end; the server holds no master key. IDs, routes and necessary operational metadata remain visible. Availability calculations and suggested times are local. A compromised or unlocked device can expose decrypted data. E2EE cannot prevent screenshots or stop an authorized member from retaining content already read.

The first relay is only for synthetic test clients. Random, scope-limited bearer credentials are stored as hashes. There is no public account creation or finished identity onboarding.

## Threats and mitigations

| Threat | Impact | Required treatment / status |
| --- | --- | --- |
| Database, storage or backup access | Disclosure of profiles, inventories or group content | Store application content only as ciphertext; do not store keys server-side. Metadata remains a residual risk. |
| Malicious or compromised server replaces public device keys | A client encrypts future content to an attacker; the server can interpose between devices | Key binding and authenticity must be independently verifiable. The independent admission proof verifies native P-256 signatures against separately pre-provisioned pins and binds the actual MLS identities, KeyPackage and initial admission across role-separated states. A local file-transport harness carries public envelopes between independent app processes; production trust bootstrap, Cloudflare transport and key-change flows remain open. A directory alone does not prevent server substitution. |
| Revoked device or member | Access to future group data | Revocation and key rotation must protect future content. Already received content cannot be unlearned or reliably recalled. Rotation and membership protocol remain open. |
| Replay, reordering or rollback | Old availability, membership or events become valid or appear again | Native proof persists the admission outbox, MLS state and receive inbox with revision CAS, and rejects consumed phases/messages in its bounded flow. Malicious database rollback, general membership/state history and server-side replay/fork defenses remain open. |
| Installation or invitation mistaken for parental authorization | Child data is shared without the required authorization, or a stranger gains management rights | Keep local preparation separate from remote activation. Verify any required scoped consent and Guardian authority independently; installation, email access, invite possession and self-managed status are not proof of parental authority or adulthood. The concrete verification mechanism remains open. |
| Abuse of Guardian rights or recovery | Unauthorized reading or permanent lockout of a child | Guardian access must be explicit, limited and revocable. Recovery must not rely on a hidden server master key. The authorization model remains open. |
| Logs, error reports or traces contain plaintext/secrets | Disclosure of content or credentials | Do not log plaintext, keys, tokens or private payloads. Limit structured logs to minimal status and correlation data; redact before output. |
| Visible IDs, routes, sizes and timestamps | Relationship, activity or usage profiling despite E2EE | Minimize the metadata inventory; limit access and retention. Hiding all routing and timing metadata is not promised. |
| Game proxy/IGDB requests | Server IP address and request time reach IGDB; requested games may reveal information about users | Clients do not call IGDB directly. Send only required IDs through the proxy, cache results and limit retention; do not send user or group IDs to IGDB. |
| Push timing and platform providers | APNs/FCM may see devices and delivery times; notification patterns reveal activity | Use neutral push text without private content. Prefer generic, batched pushes. Less precise notifications reduce timing leaks but delay updates; the exact trade-off is open. |
| Stolen relay credentials | Unauthorized access to the DEV system | Use random, purpose/scope-limited tokens; store only hashes; support rotation and revocation; never put credentials in Git or logs. Use synthetic data only. |

## Unresolved security questions

Before real user accounts, define and review key lifecycle, production trust bootstrap, approved devices, member authorization and revocation, Guardian access, recovery, key-substitution detection, and replay/rollback protection. The current admission proof uses pre-provisioned test pins and does not connect to Cloudflare onboarding, prove hardware-backed key storage, power-loss durability or malicious-database rollback resistance. MLS remains under evaluation and is not a committed production choice.
