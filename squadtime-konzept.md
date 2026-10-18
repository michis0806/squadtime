# Squadtime — Concept

Date: 2026-10-18

## Problem and idea

Children who play online together have a hard time finding times that work for everyone. They use different platforms (PS5, Switch, iPhone), and coordination happens across scattered chats.

Squadtime solves this with groups, entered play times and a view that suggests the best shared time. The core principle: **children start planning with friends; product defaults apply, and parents can add individual boundaries through optional management.**

The initial audience is children around 8 to 15 and their parents; teenagers and adults can join with their own account.

## Market overview

Similar apps exist, but none is designed for children or includes parents. Most are small, new projects for adult gamers.

| App | Platform | What it does | What is missing |
| --- | --- | --- | --- |
| [WellPlayed GG](https://mwm.ai/apps/6758271397) | iOS | Ready-to-play ping, friends by QR code, session planning | No child safety or parents |
| [Squadling](https://peerpush.com/p/squadling) | Web | Shared group calendar, ready-to-play signal | No app or child safety |
| [Party Planner](https://www.producthunt.com/@mikey963) | Web | Suggested times, RSVP link without an account, iCal | Scheduling only |
| Discord | All | Server events, chat | No availability calendar ([user request](https://support.discord.com/hc/sv/community/posts/5945192274967-Built-In-Scheduling-Calendar-Request)); age 13+ |

**The gap:** a child-friendly, cross-platform app with parent-set boundaries, a game inventory and ratings.

## Core features (MVP)

The first version focuses on planning. Everything else comes later.

- **Child-first profile:** the child creates one player profile with a nickname and an avatar from a fixed selection; no photos. The app creates a local identity and device keys automatically. No email, password or parent player profile is required initially.
- **Local-first start:** before any remote personal-data processing for which the required consent is unresolved, the child can make a local offline scheduling draft. The child can establish contacts under the contact policy or create a group. Group activation depends on the required consent, verified membership and key verification; these are separate checks.
- **Groups require eligible contacts:** no public friend directory or general
  forwardable invitation links. A new profile can connect directly through a
  mutual short-lived QR exchange confirmed on both devices, or accept a one-time,
  revocable-pending introduction from a personally connected mutual friend who is
  personally connected to both exact recipient profiles. Both recipients accept introductions.
  Contact eligibility also gates every new group membership and group sharing;
  group consent details remain open. See the accepted, unimplemented
  [contact policy](docs/onboarding.md#accepted-contact-policy). Around 10 members
  maximum. Public profiles and free-form chat are out of scope for the safe default.
- **Availability:** recurring weekly times (“Mon/Wed 4–6 pm”) plus exceptions for specific days.
- **Overlap view:** the core feature. It suggests the best time, for example, “4 of 5 can do Wed 5–6 pm, and everyone has Mario Kart on Switch.”
- **Sessions:** suggest a time, game and platform; others tap “Join” or “Can’t make it.”
- **“I’m online” button:** expires automatically after one hour. For now, this replaces connections to PSN or Nintendo, which do not offer official APIs for this.
- **Quick messages instead of chat:** preset phrases such as “I’ll be 10 min late” or “Who’s up for a game?” This avoids moderation and bullying problems.

## Game inventory and ratings

Each child has a “shelf” of games by platform and rates how much they like each one. Both feed into time suggestions.

**Inventory**

- Flow: search for a game, tap a platform, done. An automatic import from PlayStation and Nintendo is not officially available.
- Covers come from the IGDB game database (Twitch). It also provides square covers styled like console menus, which work well in a shelf layout.
- The stores themselves (PlayStation Store, eShop, Google Play) do not offer an open API; Amazon’s API requires participation in its partner program.
- IGDB is free for non-commercial use (4 requests/second). Commercial use requires a partnership and a visible source credit ([details](https://macmyths.com/apps/igdb/)).

**Rating: how much do you like it?**

- Four child-friendly levels instead of stars: favorite, like it, it’s okay, not in the mood right now. Changeable at any time because preferences change quickly.
- Ratings are visible only within the child’s own group; there are no public leaderboards.
- **Group favorites:** games that the most members own and like best in each group.
- **Better suggestions:** the overlap view picks the game that the available children like most in common.
- **Discover:** “Three people in your group love Minecraft, and you have it too.” Deliberately no purchase recommendations or store links, to avoid pressure to buy.

## Parent features

Parental consent and optional guardian management are separate from the child’s player profile. A lightweight web approval can be used for parental consent; it does not require a parent app or parent player profile. The exact proof method and legal basis remain open. App-store download approval is not assumed to cover consent for Squadtime’s own data processing or to be enabled for every installation. No integration that supplies adequate evidence for that purpose is implemented; see [the source-backed distinction](docs/onboarding.md#required-consent-without-full-account-setup).

An optional later guardian-management feature may let a guardian link to multiple children and receive explicitly scoped permissions, such as time limits, an overview, deletion or recovery actions. Each permission needs its own clear scope and lifecycle. Consent does not automatically authorize access to a child’s group keys, private group content or recovery material. A child who manages their own profile is still a child, not an adult.

**How joining a group works**

1. The child creates a player profile and keeps a local scheduling draft.
2. The child connects directly, accepts an eligible introduction, or creates a group.
3. The app verifies membership and keys; remote group activation waits for the required consent and verification checks.
4. Every new member must meet the same contact eligibility policy. A QR exchange
   alone does not prove physical presence, identity, age or Guardian authority.
   There is no assumption that knowing one member is enough to consent to every
   other member. Blocking is available; no schedules or inventory are shared before
   consent. Guardian settings may tighten the baseline, while unlinking a Guardian
   or switching to self-managed status does not remove it. Mixed-age restrictions
   remain in force.

**Settings per linked child**

- **Additional restrictions:** a Guardian may add stricter contact or group
  approval rules for linked profiles. These do not replace the baseline contact
  eligibility, establish identity or age, or relax mixed-age restrictions.
- **Time window:** for example, “weekdays 3–7 pm.” The child plans only within those times. The console itself does not lock the app; the app points parents to Sony and Nintendo parental-control apps for that.
- **Age ratings as information:** parents see USK/PEGI ratings for games in the inventory (from IGDB), without blocking.
- **Weekly overview:** planned sessions at a glance.
- **Delete profile:** an explicitly authorized deletion request, subject to a defined local/remote deletion flow. Already copied or decrypted data held by others cannot be recalled.

## Account types and sharing

The initial player profile belongs to the child and is created locally without email or password. It is not created inside a parent account. A parent need not have a player profile; a parent who plays may create one optionally. Guardian links and permissions, if introduced later, are separate from player identity. Identity, consent, guardian authority and recovery protocols remain design work; see [docs/onboarding.md](docs/onboarding.md).

| Profile | Initial setup | Rights |
| --- | --- | --- |
| Child player profile | Nickname and avatar; local identity and device keys are created automatically | Can make an offline scheduling draft; remote group use follows consent, membership and key-verification requirements |
| Optional adult player profile | Adult’s own sign-in, if they choose to play | Adult player features; does not itself grant guardian rights |

Parental consent may be obtained through a separate lightweight web approval. The parent does not need an app account or player profile to approve. The approval’s exact proof method and legal basis remain open, and approval is not treated as blanket authorization to read a child’s group content or keys.

**Adults in groups with children**

- Adult-only groups have no child-specific Guardian limits; the baseline contact policy still applies.
- The existing target restriction remains: adults may join a group with children only as an authorized parent or approved contact for at least one child in that group. How this authority is established for profiles without a guardian link remains open; simplifying onboarding does not silently relax this restriction.
- A direct personal connection under the contact policy does not by itself mean
  that a Guardian has approved an adult for a child.
- In mixed groups, all children can see that an adult is a member.

**Optional progression of guardian settings**

1. **Guided:** linked guardian settings may add stricter contact and group
   approval rules and set time windows.
2. **More autonomy:** the guardian may relax or remove those limits; the child retains their own player profile.
3. **Unlinked:** guardian links and permissions may end without converting the child into an adult account. Any retained data, consent and key handling need an explicit flow.

No date of birth is planned for the profile. Applicable consent requirements and age-related transitions need legal review; a reminder date does not establish age or consent eligibility.

**Implication for app stores:** with adult accounts, this is not an app exclusively for children. A standard category with an appropriate age rating would make more sense than Apple’s “Kids” category; the rules against ads and tracking still apply.

## Technology and data minimization

Native iOS and Android apps use a shared API. Cloudflare Workers and EU-jurisdiction D1 are the accepted starting architecture; see [docs/decisions.md](docs/decisions.md). The alternatives below are historical exploration. Only data needed for planning is stored.

**Architecture**

- **Apps:** native Swift/SwiftUI (iOS) and Kotlin/Jetpack Compose (Android). Child player flows are primary. A separate lightweight web approval may handle parental consent; optional guardian-management views can be designed later. This is product direction, not evidence of implemented onboarding.
- **Shared API contract:** an OpenAPI specification generates the network layer for both apps to keep them consistent.
- **Game proxy:** the server queries IGDB and caches covers. Devices never contact third parties directly; IGDB requires a server proxy anyway.
- **Push:** APNs for iOS and Firebase Cloud Messaging for Android, triggered by the backend.

**Previously considered backend options**

| Option | Components | Advantages | Disadvantages |
| --- | --- | --- | --- |
| **Hetzner** (Germany) | Docker cloud server: Caddy, API (for example Kotlin/Ktor), PostgreSQL; object storage and Storage Box for covers and backups; optional Coolify for deployments | Cheapest, full control, servers in Germany | Self-managed updates, firewall, backups and database |
| **Scaleway** (France) | Serverless Functions/Containers, Serverless SQL (PostgreSQL), Object Storage | No server operations, real Postgres, clear EU regions | Less predictable costs; push is trickier in short-lived functions |
| **Bunny.net** (Slovenia) | Edge Scripting, Bunny Database (SQLite-based), Bunny Storage (S3-compatible), Magic Containers | Closest to Cloudflare Workers/D1/R2, very simple | Edge runs globally; check EU data restrictions and data-processing terms first |

The earlier provider comparison is retained for context, not as the current recommendation. The accepted Cloudflare direction in [A-001](docs/decisions.md#a-001-cloudflare-backend-with-eu-data-storage) supersedes it. Cloudflare remains a US company; EU storage alone does not settle data-processing or cross-border-access questions.

**Data stored**

| Who | Stored | Not stored |
| --- | --- | --- |
| Child player profile | Nickname, avatar ID, platforms, game IDs with rating, time slots; local identity and device-key material on the device | No email or password required at initial setup; no legal name, date of birth, photos, location or address-book contacts planned |
| Parental consent | Minimum evidence needed to record an approval, subject to a defined proof and retention design | Parent player profile or parent-app account is not required; no assumption that store download approval alone satisfies app-data consent requirements |
| Optional guardian link | Child-to-guardian relationship and explicitly granted permission scopes, if this later feature is built | Automatic access to group keys, private group content or recovery material |

**Other rules**

- **Deletion timelines:** past sessions after 7 days; online status is not stored long-term.
- **Push notifications:** neutral wording (“Something new in your group”), since they pass through Apple and Google servers.
- **No ads, no tracking:** no analytics or advertising SDKs. Google (“Families” policy) and Apple require this for apps used by children.
- **Consent:** consent requirements for remote processing, the legal basis, proof method, retention and revocation flow remain open and require legal review. A separate web approval is the proposed lightweight path; store download approval is not assumed to satisfy it, and no verification integration is implemented. Local offline drafting precedes remote personal-data processing where the required consent is unresolved.

## Open questions and next steps

**Open questions**

- What proof method and legal basis are appropriate for parental consent, and which remote processing must wait for it?
- How should the separate web approval be verified, revoked and retained without requiring a parent player profile?
- What explicit guardian permission scopes are useful, and how do unlinking, deletion and recovery work without granting key access by default?
- What group-consent experience should explain and approve all proposed members?
- Free, one-time purchase or parent subscription? This determines whether an IGDB partnership is needed.
- Should both parents have access to a child profile?

**Next steps**

- [ ] Build a clickable prototype of the overlap view and test it with a son and his friends
- [ ] Ask other parents in the group about interest and concerns
- [ ] Create an IGDB account and clarify commercial terms
- [ ] Have consent, age-related and privacy questions reviewed by counsel (including GDPR Article 8 where applicable and store policies)
- [ ] Design the player-initiated onboarding screens and authorization flow before connecting them to the existing Cloudflare DEV relay
