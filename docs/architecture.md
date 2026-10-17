# Squadtime architecture

## Purpose and status

This document records the assumed target architecture and current development state. It complements the product concept; it does not change its product scope. Security details without a firm decision are listed as open.

## System overview

- **Clients:** native iOS and Android apps. They calculate availability overlaps and suggested times locally from decrypted data.
- **API:** Cloudflare Workers with TypeScript. The service relays encrypted records and group operations.
- **Database:** Cloudflare D1, EU location. D1 holds required operational data and encrypted application data.
- **Object storage:** Cloudflare R2 in the EU is planned for later use; it is not required for the first relay.
- **Third parties:** the game proxy queries IGDB and serves game metadata and covers. Push notifications use APNs and FCM.

Cloudflare is a US company. An EU region limits the geographic location of stored data, but does not remove the need to assess data processing terms, access controls and potential cross-border access.

## Encryption boundaries

End-to-end encryption is intended for private profile data and game inventories, as well as availability and events within each group. The server and storage receive ciphertext; they have no general decryption or master key.

The family area is logically and cryptographically separate from group areas. Guardian access and recovery must be explicitly authorized; neither may follow from a shared account key or server administration alone.

Login/passkeys and device encryption keys are separate. Successful login alone must not replace or decrypt existing device key material. The DEV relay is not a finished identity or end-user onboarding solution.

At least the routing and operational metadata needed by the server remain visible, including IDs, membership/access relationships, timestamps and requested routes. The exact metadata inventory still needs to be defined and minimized. The server must not decrypt content.

## DEV relay status

The first backend step is a development relay for synthetic test clients. It uses random, purpose- and scope-limited bearer credentials; only their hashes are stored. There is no public account creation or finished end-user identity onboarding. Credentials must not appear in Git, documentation, logs or example configuration.

## Data flow

1. Clients encrypt content using locally held key material.
2. They send ciphertext and metadata required for routing and authorization to the Worker.
3. The Worker checks access, stores or returns ciphertext and does not put plaintext in logs.
4. Devices decrypt data and calculate availability overlaps and suggested times locally.
5. Push notifications remain neutral and contain no private content; their timing may still reveal activity.

## Still to decide

Before end-user operation, define key lifecycle and device approval, explicit member authorization, Guardian access and recovery, protection against key substitution by a malicious server, replay and rollback protection, and deletion and rotation. MLS is under evaluation and is not a committed production choice.
