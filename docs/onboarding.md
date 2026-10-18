# Onboarding initiated by the player

Status: accepted product direction, 2026-10-18. This is a design, not implemented
registration, consent verification, Guardian authorization or production onboarding.
The existing native admission proof uses synthetic identities and pre-provisioned
trust pins. The DEV relay remains closed to public registration.

## First useful action

A player can start without a parent first installing Squadtime or creating a
player account. One player profile persists as devices, login methods and Guardian
relationships are added later; these changes do not create a replacement player.

1. Open an invitation link, scan a QR code, or choose to start a play group.
2. Pick a nickname and a built-in avatar. Generate the local player identifier
   and device keys automatically; do not ask for email or a password at this step.
3. Prepare a game/time choice locally. Keep the draft on the device while any
   required eligibility or consent decision is unresolved. Do not upload profile
   data, fetch private group rosters, register push tokens or contact game providers
   as an implicit side effect of this local preview. Bundled examples can show value.
4. Before remote personal-data processing or joining, resolve the applicable
   eligibility/legal-basis requirements and obtain any required authorization.
   A group invitation does not itself supply parental consent or device-key trust.
5. Verify the invitation and device binding, obtain the group's membership approval,
   and join. Add a complete game library, recurring availability and optional parent
   management after the first useful planning action.

Do not promise a legally unrestricted social connection before parental involvement
for every child. The accepted simplification removes mandatory parent account setup;
it does not waive a required authorization. An unresolved requirement keeps the
profile in local preparation rather than silently enabling sharing.

## Three separate relationships

| Purpose | User-facing setup | Minimum conceptual record |
| --- | --- | --- |
| Play and plan | Nickname/avatar; local device setup happens automatically | Player identity and authorized devices |
| Give required parental consent | A focused browser flow, without installing the app or creating a player profile | Scoped, verifiable authorization evidence; mechanism and retention remain to be reviewed |
| Manage or assist a child later | Optional secured Guardian access; one person can manage multiple children | Guardian identity and explicit per-child permission grants |

These are separate responsibilities, not a requirement for two manually created
accounts per player. A Guardian who also plays can add a player profile, but need
not choose an avatar, maintain games or join a group to manage a child.

Independent account management is not evidence of adulthood. Age/region eligibility,
parental authority, account login, group membership and cryptographic device trust
must not be inferred from one another.

## Required consent without full account setup

Where parental consent is required, provide a short browser flow with understandable
information about Squadtime's processing, its scope, the applicable notice version,
and withdrawal. Establish the required evidence of parental authority through a
reviewed mechanism. A child pressing a confirmation, an ordinary forwarded link,
or an email click alone must not be treated as proof of that authority.

Keep evidence sufficient for the approved legal basis and minimize collected data;
exact fields, age-assurance method, verification mechanism and retention are open.
There is no committed automatic conversion from this evidence into Guardian access.
A later management link requires its own authenticated, authorized grant.

Platform download approval can reduce practical friction when parents already
participate in installation. It is not assumed to be enabled for every installation,
provided to Squadtime as reliable evidence, or to cover Squadtime's own processing.
Avoid asking twice only if a reviewed platform integration supplies adequate evidence
for the particular purpose and jurisdiction. Until then, installation alone never
marks app-specific consent as satisfied.

Apple describes Ask to Buy as approval of purchases/downloads; Google similarly
provides configurable Play purchase/download approval. GDPR Articles 7 and 8 address
proof and conditions of consent, including parental authorization where Article 8
applies. These sources support keeping the questions separate; they do not approve
this proposed browser verification flow:

- [Apple: Ask to Buy](https://support.apple.com/en-us/105055)
- [Google: Play purchase approvals](https://support.google.com/googleplay/answer/7039872?hl=en)
- [GDPR Articles 7 and 8](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679)

## Parent management and default boundaries

Without a Guardian link, use product-wide defaults: invitation-only groups, no public
profile search, built-in avatars and preset messages instead of free chat. These
reduce exposure but do not establish a safe group or prove who is using a device.
Do not label limits as parent-approved when no parent set them. Individual time
windows and approved-friend thresholds belong to explicitly managed profiles.

Present management, schedule visibility, membership approval, deletion and recovery
as separate permissions. Granting consent does not disclose content keys, make a
parent a group member, or authorize recovery. Any encrypted schedule overview needs
its own reviewed sharing path; login alone cannot decrypt prior history.

Removing or reducing a Guardian role preserves the player profile and group identity
when authorized. It does not prove the player is an adult. The conditions for a
minor to change these permissions remain part of the authorization design, not an
unrestricted child-controlled toggle.

## Device loss and later setup

Offer a separate, understandable recovery setup once a player has an active group.
Until it is configured, device loss or app-data deletion can mean losing access to
identity and encrypted history. Do not imply that adding an email, passkey or parent
contact automatically backs up MLS keys. Recovery rights and any future backup are
explicit, separate cryptographic features, currently unimplemented.

## Acceptance criteria for the future implementation

- Starting a local profile never requires a parent player account or parent app.
- Local preparation survives restart without publishing private data.
- Remote processing remains blocked while an applicable authorization is unresolved;
  a group invitation, installed app or unchecked parental claim cannot bypass it.
- Required consent can be handled without creating a parent player profile.
- A parent can manage multiple children through separately authorized links.
- Adding login or Guardian access preserves the same player identity and never
  silently grants group-content decryption or recovery authority.
- Production identity bootstrap, age/region handling, parental verification, mixed-age
  group policy, withdrawal/deletion and recovery must be reviewed before real users.
