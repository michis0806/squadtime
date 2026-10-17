# Squadtime — Concept

Date: 2026-10-17

## Problem and idea

Children who play online together have a hard time finding times that work for everyone. They use different platforms (PS5, Switch, iPhone), and coordination happens across scattered chats.

Squadtime solves this with groups, entered play times and a view that suggests the best shared time. The core principle: **parents set the boundaries; children plan freely within them.**

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

- **Child profile without email:** parents set a nickname and choose an avatar from a fixed selection; no photos. The child signs in from the parent app by QR code, without a password.
- **Groups by invitation:** join only with a code or QR code; no public search. Around 10 members maximum.
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

Parents build trust through friends rather than approving individual groups. A child may join any group with at least *n* approved friends.

**How joining a group works**

1. The child scans an invitation code.
2. The app counts approved friends in the group.
3. At least *n* are found: the child joins immediately and the parents get a notice.
4. Fewer than *n*: the parents receive a request and see the members.

**Settings per child**

- **Mode:** threshold *n* (for example 1 or 2), “always free” or “always ask.” This lets the app adapt as the child grows.
- **Approve friends:** someone who scans in person by QR code is automatically counted as approved. Parents can turn this off and approve friends manually.
- **Time window:** for example, “weekdays 3–7 pm.” The child plans only within those times. The console itself does not lock the app; the app points parents to Sony and Nintendo parental-control apps for that.
- **Age ratings as information:** parents see USK/PEGI ratings for games in the inventory (from IGDB), without blocking.
- **Weekly overview:** planned sessions at a glance.
- **Delete profile:** at any time, with all data.

## Account types and sharing

There are two account types: child accounts managed by parents, and adult accounts with their own sign-in. A child account can later become an independent account without losing data.

| Account type | Sign-in | Rights |
| --- | --- | --- |
| Child account | QR pairing by a parent | Plans freely within the parent settings |
| Adult account | Own email with passkey or magic link | Full rights; can also take the parent role for child accounts |

The parent role is therefore a feature of an adult account, not a separate account type. This lets parents who play games use the app themselves.

**Adults in groups with children**

- Groups for adults only work without restrictions.
- Adults may join a group with children only if they are listed as a parent or approved contact for at least one child in that group, such as an older sibling.
- In mixed groups, all children can see that an adult is a member.

**Three steps for granting independence to a child account**

1. **Guided:** group joining uses the approved-friend threshold *n*; time windows are active.
2. **Free:** mode is “always free,” with no time windows; parents see only the weekly overview.
3. **Independent:** parents hand over the account. The child adds their own email and passkey and gives their own privacy consent; parent access ends. Groups, inventory and ratings remain.

Because no date of birth is stored, parents trigger each step themselves. They may optionally set a reminder date, for example for the child’s 16th birthday (the GDPR consent age in Germany).

**Implication for app stores:** with adult accounts, this is not an app exclusively for children. A standard category with an appropriate age rating would make more sense than Apple’s “Kids” category; the rules against ads and tracking still apply.

## Technology and data minimization

Native iOS and Android apps use a shared API in the EU. Three backend options are considered; only data needed for planning is stored.

**Architecture**

- **Apps:** native Swift/SwiftUI (iOS) and Kotlin/Jetpack Compose (Android). Parent, child and adult views live in the same app and are separated by account type.
- **Shared API contract:** an OpenAPI specification generates the network layer for both apps to keep them consistent.
- **Game proxy:** the server queries IGDB and caches covers. Devices never contact third parties directly; IGDB requires a server proxy anyway.
- **Push:** APNs for iOS and Firebase Cloud Messaging for Android, triggered by the backend.

**Backend options**

| Option | Components | Advantages | Disadvantages |
| --- | --- | --- | --- |
| **Hetzner** (Germany) | Docker cloud server: Caddy, API (for example Kotlin/Ktor), PostgreSQL; object storage and Storage Box for covers and backups; optional Coolify for deployments | Cheapest, full control, servers in Germany | Self-managed updates, firewall, backups and database |
| **Scaleway** (France) | Serverless Functions/Containers, Serverless SQL (PostgreSQL), Object Storage | No server operations, real Postgres, clear EU regions | Less predictable costs; push is trickier in short-lived functions |
| **Bunny.net** (Slovenia) | Edge Scripting, Bunny Database (SQLite-based), Bunny Storage (S3-compatible), Magic Containers | Closest to Cloudflare Workers/D1/R2, very simple | Edge runs globally; check EU data restrictions and data-processing terms first |

Cloudflare itself offers EU data storage for D1 and R2, but remains a US company. **Recommendation:** Scaleway if server operations are not desired; Hetzner if admin work is acceptable. Test Bunny with a small deployment before deciding. ([Bunny changelog](https://bunny.net/docs/changelog.md), [Scaleway Serverless](https://www.scaleway.com/en/build-scalable-applications-with-serverless/))

**Data stored**

| Who | Stored | Not stored |
| --- | --- | --- |
| Child | Nickname, avatar ID, platforms, game IDs with rating, time slots | Legal name, date of birth, photos, location, contacts |
| Parents | Email address, settings | Postal address, payment data (in MVP) |

**Other rules**

- **Deletion timelines:** past sessions after 7 days; online status is not stored long-term.
- **Push notifications:** neutral wording (“Something new in your group”), since they pass through Apple and Google servers.
- **No ads, no tracking:** no analytics or advertising SDKs. Google (“Families” policy) and Apple require this for apps used by children.
- **Consent:** through the parent account under GDPR Article 8, confirmed by email. Obtain legal review.

## Open questions and next steps

**Open questions**

- What happens if approved friends leave a group and the threshold is no longer met? Proposal: the child stays in the group and parents get a notice.
- Free, one-time purchase or parent subscription? This determines whether an IGDB partnership is needed.
- Should both parents have access to a child profile?

**Next steps**

- [ ] Build a clickable prototype of the overlap view and test it with a son and his friends
- [ ] Ask other parents in the group about interest and concerns
- [ ] Create an IGDB account and clarify commercial terms
- [ ] Have privacy questions briefly reviewed by counsel (GDPR Article 8, store policies)
- [ ] Choose a backend: Hetzner, Scaleway or Bunny, with a small trial deployment for each
