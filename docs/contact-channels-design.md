# Ministry Contact Channels — exploration

Exploration session, 2026-07-12. Output = design direction, not an implementation
plan. If pursued: deep-solver detailed design + auditor adversarial review per
domain-floor slice before build.

## Context

Email/phone are bearer secrets: once leaked you can't tell who leaked them, can't
revoke, can't rotate without social cost. Relay services (Firefox Relay etc.)
half-fix it but leak your real address on reply, get blocklisted, and have no
identity layer. Tyler's long-standing contacts-app idea (per-relationship
addresses, live-updating contact info, revocable pathways) folds into Ministry as
revocable, relationship-scoped contact channels. Email only; phone is out
(unsalvageable); Signal = disclose username via a grant, nothing deeper.

## Thesis

One email string plays three roles: identity, inbox locator, unrevocable bearer
capability. Split them: identity = Ministry DID; inbox locator = private
destination; capability = the alias (mintable, policy-gated, pausable,
revocable). SMTP stays dumb transport; all innovation is control plane — and the
request→policy→consent→grant→revoke loop already exists in Minister as the OIDC
consent flow, here pointed person-to-person.

Two features no relay competitor can build (no identity layer):

1. **Badge-gated contact requests** — satisfying a badge policy (reuse
   `apps/minister/src/lib/oidc-policy.ts` allOf/anyOf/atLeast + minimization) is
   the price of asking. Spam becomes structurally unaddressed, not filtered.
2. **Attribution with teeth** — per-relationship alias names the leaker;
   revocation is per-relationship, not scorched-earth.

The contacts-app sync problem mostly dissolves: stable alias + rotatable
destination = nobody needs your new address because nobody ever had it.

## Decisions (Tyler, this session)

- **Full vision scope**: relay + gated requests + share-link contact buttons +
  per-relationship contact card.
- **Double-blind is a hard requirement.** Reply must never leak the real address
  (the Firefox Relay failure). Minister↔Minister channel = a PAIR of aliases, one
  facing each side. External counterparty: relay knows their address; the
  Minister user's is always hidden via reverse aliases.
- **Mail plane: AWS SES both directions.** Re-compose as a new message, never
  verbatim forward (sidesteps SPF/SRS entirely).
- **Domains: BYO from day one** + Ministry-hosted alias domain. Hosted domain =
  NEW sibling registrable domain, never ministry.id (blocklists key on
  registrable domain; reputation isolation for the IdP). Hosted aliases are
  **free and unlimited for the alpha** — no billing built yet; pricing
  (~$1/mo was the working number) decided later from real usage.
- **Contact requests need a Ministry account** (v1).
- **Share-link contact button**: ShareLink can expose "contact me"; each
  distinct visitor gets a unique alias attributed to that link (same visitor
  re-clicking gets the same alias — see abuse controls). Resume use case: each
  company gets its own alias → "this email came from my resume".

## Two-sided UX (refined 2026-07-12)

**Naming: "line."** The user-facing noun for a contact pathway is a **line** —
open a line, cut a line, "this line came from your resume." Fits the Ministry
register ("a direct line"). Wallet page: `/lines`. The Prisma model can follow
(`Line`) — the doc's `ContactChannel` references below are the same object.

**Request shape: the message rides along.** A contact request = disclosed badges

- a short size-capped message. The owner judges it like a pitch: badges prove
  standing, the message proves intent. Approve = the message is delivered as the
  first email through the newly opened line + the line appears in both wallets.
  Deny/ignore = never delivered. No "approved, now go compose an email" dead end.
  The request message is control-plane data: stored only until resolved, then
  delivered-and-deleted (approve) or deleted (deny/expiry) — keeps the
  minimal-storage story honest.

**Notifications: tokenized deny, wallet approve.** Requests chase the owner to
their delivery inbox (Minister is bursty-use; a wallet-only inbox rots). The
notification email shows requester, badges, and message. Deny/ignore is one
click on a signed single-use token, no sign-in (closing a door is low-stakes).
Approve links into the wallet and requires the signed-in session — same
discipline as `resumeViaPendingToken`, so a forwarded notification can't open a
line on someone else's account.

**Gate display: after sign-in, always.** Anonymous profile visitors see only a
"Request contact" button on `/u/[id]`. A signed-in requester sees the owner's
policy with their satisfying badges preselected (reuse the OIDC consent
machinery: satisfiability + most-anonymous minimal set). An unqualified
requester sees exactly which badge they're missing — deliberately: "earn the
year-old-GitHub badge to contact this person" turns rejected requesters into
badge-earning Ministry users (growth loop).

**Requester after approval:** the line shows up in their `/lines` too (paired
aliases; each side sees only its facing alias). Their reply path is plain email
from then on — no wallet round-trips to converse.

**Paired-line mechanics, worked example.** Tyler↔Scott line mints two aliases,
one OWNED by each side: `tyler.y2@tyler-domain` (Tyler's alias, faces Scott —
what Scott writes to, what Tyler cuts) and `scott.x1@scott-domain` (Scott's,
faces Tyler). Scott mails `tyler.y2` → relay verifies him → lands in Tyler's
real inbox showing `From: scott.x1@scott-domain` → Tyler hits reply (MUA
addresses `scott.x1` automatically) → relay verifies Tyler → Scott receives it
`From: tyler.y2`. No real address in any header, either direction; each side
holds an independent kill switch; the `ra_` reverse-alias machinery is not
involved (it exists only for non-Ministry counterparties).

## Contact card (refined 2026-07-12)

The card generalizes the existing profile-grant-split pattern (field-level
disclosure, never fall back to upstream identity): contact fields live ONCE on
the profile; lines grant visibility. Update a field once → every line disclosing
it sees the new value. This is the original live-updating-contacts idea, with
per-line revocation for free.

**Disclosure model: named cards + per-line exceptions.** The user composes a few
named cards ("Friends" = Signal, city, birthday; "Work" = website, calendar).
Every line points at one card; any line can add/remove specific fields on top
("Work card, +phone for this one person"). Effective fields = card ± overrides.
Model: `Card`, `CardField`, `Line.cardId`, `LineFieldOverride(lineId, fieldId,
grant|deny)`. The who-sees-what audit view must render exceptions explicitly
("Work +phone") — the override layer can't be invisible fine print.

**Consumption: web page AND CardDAV, both at launch** (Tyler's call — full
vision). Each line gets a stable card URL showing exactly its effective fields,
plus a per-line read-only CardDAV feed (minimal RFC 6352 subset: one
addressbook, one vCard; per-line credentials) so phone contacts apps auto-update
(iOS native; Android via DAVx5). The vCard's EMAIL is always the line's alias —
a card NEVER carries a real address, so a re-shared card leaks nothing.

**Honest limitation (document in-product):** cutting a line kills the card URL
and the DAV feed (401), but can't remote-wipe the contact already synced to
someone's phone — their copy goes stale-frozen, not deleted. Still strictly
better than today, where the stale copy is also a working address forever.

## Service lines and machine mail (refined 2026-07-12)

Machine senders (signups, newsletters, receipts, OTP codes) will dominate
day-one traffic and are where the spam-attribution pain actually lives. A
service line is the same `Line` object with no card and no counterparty:
wallet **quick-mint** (label + domain, two clicks) ships in slice 1. The
browser extension (mint-at-the-signup-form, riding the existing
`apps/extension` skeleton) is a fast-follow, **planned as a paid feature** —
human↔human contact is the current priority. Migration off the real address is
manual and per-service, as accounts get touched (SimpleLogin pattern); no
import wizard.

**OTP latency budget**: relay hop must not break password resets. Target p50
< 10s, p95 < 30s inbound-to-forwarded; make relay latency a first-class metric
from slice 1.

## Group threads (refined 2026-07-12)

**Reverse-alias every participant.** Inbound to your alias with third parties
in To/Cc: each participant address gets its own reverse alias on your line,
and To/Cc are rewritten to those. You see the group shape, and reply-all
routes every recipient back through the relay. This is the only model that
survives the reply-all trap: preserving real third-party addresses in visible
headers would let one reply-all send your REAL address directly to strangers,
bypassing the relay. (Amends the header-allowlist rule: To/Cc are
rewritten-to-reverse-aliases, not dropped.) Cost: more `ReverseAlias` rows and
rewrite logic — bounded by real usage.

## Delivery inboxes (refined 2026-07-12)

Users register multiple verified delivery inboxes (magic-link verify); each
line routes to one, set at creation and changeable (work lines → work inbox).
**Honesty requirement**: the product states plainly that the delivery inbox's
provider still sees message content — Ministry is a control plane, not a
mailbox, deliberately (see Avoid). Double-blind protects addresses between
parties; it does not hide content from your own mail provider.

## Line-state semantics (refined 2026-07-12)

- **Active** — relay both directions.
- **Paused / cut / expired** — all silent-drop inbound, metadata-counted,
  surfaced to the owner ("N dropped"). **Deliberately indistinguishable to the
  sender**: any observable difference between pause and cut invites
  "am I blocked?" probing.
- **Auto-generated mail from the destination never relays outward** — OOO
  replies carry real signatures and contact blocks (identity leak); the
  existing Auto-Submitted handling drops them at the relay. Documented
  consequence: counterparties don't get your OOO.
- **Bounce containment**: a bounce from the user's real inbox (mailbox full
  etc.) must never propagate outward — it names their provider. Counterparty
  gets at most the synthesized generic failure notice (authenticated senders
  only); the owner gets a "your delivery inbox is bouncing" wallet warning.

## Policy presets and hosted aliases (refined 2026-07-12)

**Policy setup ships as curated presets** over the existing policy builder:
"anyone with a Ministry account," "any OAuth badge ≥ 1 year old" (the
deforum-proven human gate), "invite-code holders only," "age-verified adults."
Presets are canned policy trees; the advanced builder stays available. Default
for a new user: any-OAuth-≥1yr (a gate, but a passable one).

**Hosted alias naming: chosen prefix + random suffix** (`tyler.x7k2@<domain>`) —
SimpleLogin-proven: resists enumeration and squatting without being fully
opaque. No bare vanity localparts on the shared domain (squatting + phishing
surface). BYO domains: the owner picks localparts freely.

## Substrate (scout-confirmed)

- Mail today is outbound-only: `apps/minister/src/lib/mailer.ts` (nodemailer;
  SMTP_URL → Resend → console). Zero inbound infrastructure.
- Plugins are badge-issuance-shaped (no webhook mounts, no background jobs) —
  this is a NEW subsystem composing with badges, not a plugin.
- Reusable: `oidc-policy.ts` evaluate/minimize; ShareLink primitive;
  `plugins/dns-txt/resolve.ts` resolver plumbing + its verify-retry UX;
  `src/lib/rate-limit.ts` limiter factory; `src/lib/secrets.ts` SSM pattern;
  audit log. VC/KMS issuance available if grants ever become portable VCs (YAGNI
  v1; DB rows are truth).

## Architecture (pressure-tested; SES facts verified against current AWS docs)

**Inbound path**: MX → SES receipt rule (one condition-less catch-all rule —
matches every domain whose MX points at us, so BYO onboarding never touches
receipt rules; note the active rule set is an account/region singleton) →
S3 action (SSE-KMS) → S3 event notification → SQS (14d retention, DLQ at
maxReceive 5) → relay worker → SESv2 `SendEmail` (raw; 40MB — NOT v1
SendRawEmail, which caps at 10MB) → delete S3 object. S3 lifecycle delete-after-7d
as the storage-free backstop. Receipt rules cannot target SQS directly; S3-events
route skips SNS. **Spike q:** do SPF/DKIM/DMARC verdicts reach the S3 object as
injected headers, or SNS-only? If SNS-only, switch to S3-action+SNS→SQS
(one-line infra change). `ScanEnabled` injects spam/virus verdict headers.

**Region**: us-east-2 supports SES receiving (confirmed; expanded Sept 2023).
Everything stays beside existing KMS/SSM.

**SES production access is a real project risk**: AWS scrutinizes forwarding
services. File the request day 1 of any build with abuse controls written up;
bounce/complaint wiring is effectively a prerequisite for approval. Account-level
SES reputation is shared across all tenants — one abuser threatens everyone's
mail, hence the feedback-loop auto-pause below.

**Worker placement**: `services/relay-worker/` in the compose stack, plain Node,
long-polls SQS, imports the Prisma client directly from the same schema (no
internal API — more code for zero gain on one box; add the API seam only if the
worker ever leaves the box). All badge-policy machinery runs in the app at
channel-creation time; the worker's per-message decision is row lookup + status
enum + verdicts. Box down = latency only (SQS holds). Serial processing
(concurrency 1-2), ~25MB relay cap with bounce-note (mailparser buffering on a
2GB box; >25MB bounces at most destinations anyway).

**Idempotency**: dedup key = SES messageId (== S3 key), `@unique` on
ChannelMessageLog, insert-first. Crash between send and status update ⇒ rare
duplicate forward, accepted (no exactly-once theater).

## Double-blind protocol (the domain-floor core)

- **Header ALLOWLIST, never strip-list** (strip-lists are how Relay-class leaks
  happen). Copy: Subject, Date, MIME-Version, rebuilt content headers, translated
  In-Reply-To/References, Auto-Submitted. Regenerate: From, To, Message-ID,
  Return-Path. Everything else dies (Received, origin DKIM/ARC,
  Disposition-Notification-To, X-*, and especially **Reply-To** — the user's MUA
  sets it to their real address; on outbound, omit or set to the alias).
  To/Cc are NOT dropped but rewritten to per-participant reverse aliases — see
  "Group threads"; Bcc never survives.
- **Display names**: external→user keeps sender's name ("Alice Smith (via
  domain)"); user→external copies NOTHING from the user's From — channel has a
  required display-name field chosen at creation (mirrors the oidc-claims
  never-fall-back-to-upstream-identity discipline).
- **Reverse alias** = per (channel, canonicalized external address), row stores
  the external address plaintext; outbound destination comes from the row, never
  from headers (structurally kills open-relay). Reply accepted only if header-From
  AND envelope MAIL FROM match the channel's delivery address AND inbound DMARC
  passes (or aligned SPF when no DMARC). Fail ⇒ silent drop. Residual
  forgeability for DMARC-less custom destinations: accepted, documented.
- **Threading**: deterministic invertible Message-ID translation via AES-SIV on a
  per-channel-pair key (derived from one relay master secret in SSM, same pattern
  as OIDC_PAIRWISE_SECRET). Try-decrypt each ID in References: success ⇒ emit
  plaintext (recipient's original ID), fail ⇒ encrypt. Stateless, no mapping
  table, threads correctly in both MUAs, leaks nothing (synthetic IDs carry the
  alias domain the counterparty already sees).
- **Leak vectors handled**: calendar invites (ORGANIZER/ATTENDEE mailto — detect
  text/calendar, bounce-with-note on outbound/paired), read receipts (allowlist
  kills), S/MIME/PGP signature parts (detect, warn/bounce in paired; broken by
  rewrite anyway), Date TZ (normalize to UTC in paired), DSNs (never relay raw;
  synthesize minimal failure notice), no footer injection ever on the
  external-facing copy. Body content (mailto links, signatures) is explicitly out
  of scope — no body rewriting, UI education instead.
- **Loop protection**: stamp `X-Minister-Relay: <opaque>` outbound; drop inbound
  bearing our stamp; honor Auto-Submitted and null MAIL FROM; cap Received count.

## Abuse controls

- Share-link minting (anonymous surface): per-IP `contactMintLimiter`, per-link
  cap (~25, owner-adjustable), same-visitor dedup returns the same alias,
  **unused-alias expiry** (zero inbound in 14d ⇒ auto-revoke — makes cap-draining
  self-healing). Revoking the link stops minting; existing aliases live.
- Channel-factory abuse: per-user new-external-counterparty/day limit + daily
  outbound quota + SES bounce/complaint events (configuration set → SNS) auto-
  pausing offending channels.
- Inbound spam: virus FAIL ⇒ drop; spam FAIL ⇒ forward with [SPAM] tag + per-user
  drop toggle (storage-free forbids quarantine); auto-pause chronic spam-magnet
  aliases; complaint rate <0.1% is a production metric.
- Revoked alias ⇒ **silent drop** + metadata log + "N dropped" surfaced to owner.
  Never DSN an unauthenticated sender (backscatter). No SES Bounce action.

## BYO domains

4 DNS records: 1 MX (inbound-smtp.us-east-2) + 3 DKIM CNAMEs (SESv2
CreateEmailIdentity → tokens; DKIM-based verification, no TXT needed; SES retries
detection 72h so "pending" is durable state). Optional _dmarc TXT recommended.
Skip custom MAIL FROM in v1 (aligned DKIM alone satisfies DMARC). SES is the
authority for DKIM; we check MX ourselves (SES never validates MX — extend
`dns-txt/resolve.ts` with an MX lookup; single resolver fine, checks are advisory
UI). **Footgun**: MX is exclusive — takeover of all mail for that name. Look up
existing MX first, hard-warn on apex, default to `relay.yourdomain.com`
subdomain. Same domain in multiple SES accounts is fine (not a failure mode).
ContactDomain deletion also deletes the SES identity.

## Data model (draft)

- `ContactDomain` — kind byo|hosted, domain unique, ownerUserId, dkimTokens,
  dkimStatus, mxCheckedAt
- `ContactChannel` — owner, alias, label, source manual|request|share-link,
  shareLinkId?, nullable unique self-relation `peerChannelId` (paired
  double-blind), deliveryEmail ref, required displayName, status
  active|paused|revoked, timestamps
- Per-user verified `deliveryEmail` (reuse magic-link verify) — NOT the auth
  email; users will want a different delivery mailbox
- `ReverseAlias` — channelId, externalAddress (plaintext; reply path needs it),
  token, `@@unique([channelId, externalAddress])`, lastUsedAt
- `ContactRequest` — requester, target, message, policy snapshot, disclosed
  badges, status, resulting channelId?
- `ChannelMessageLog` — direction, sesMessageId unique, verdicts, size, status,
  timestamps. **No Subject** (subject is content; excluding it keeps
  "metadata only" honest)
- Card models (slice 6, see "Contact card"): `Card`, `CardField`,
  `Line.cardId`, `LineFieldOverride(lineId, fieldId, grant|deny)`
- Naming note: `ContactChannel` above = the "line" object; the Prisma model
  should just be `Line` to match the product language

## Avoid / lean into

Avoid: owning an MTA, storage/IMAP/webmail/quarantine, phone, new E2EE protocol,
body rewriting, cross-instance federation (later), native app (wallet web UI).
Relay reads plaintext — say so plainly in-product; opt-in PGP-at-relay later.

Lean into: badge-gated requests (the moat), attribution + one-click
revoke-and-remint, share-link-sourced aliases (every distribution surface becomes
a traceable channel), BYO domains (the real blocklist antidote), contact card =
per-relationship disclosed fields (Signal username etc.) at a stable revocable
URL — live-updating for free since it's fetched, not pushed.

## Build slices (riskiest first; ★ = domain floor, adversarial review required)

1. ★ **Relay core on hosted domain** — models, SES receiving + S3→SQS + worker,
   manual alias mint in wallet, both directions with allowlist rewrite,
   reverse-alias sender verification, loop guard, drop-on-revoked,
   bounce/complaint wiring. File SES production access day 1.
2. ★ **Protocol hardening + threading** — SIV Message-IDs, References
   translation, DSN synthesis, calendar/receipt/signature handling, verdict
   policy, size caps. Leak audit against real MUAs (Gmail/Outlook/Apple Mail).
3. **BYO domains** — CreateEmailIdentity onboarding, DKIM/MX checklist UX,
   existing-MX warning, subdomain default.
4. ★ **Contact requests + paired channels** — badge-policy gating at request
   time, disclosure snapshot, wallet inbox, paired-alias double-blind.
5. ★ **Share-link contact buttons** — anonymous per-click minting + full abuse
   kit (limiter, caps, dedup, unused expiry), attribution in channel list.
6. **Contact cards** — named cards + per-line exceptions, card URL per line,
   minimal read-only CardDAV feed. (Grew from one line to a real slice —
   see "Contact card" section.)
7. ~~Hosted domain billing~~ — **deferred post-alpha**: hosted aliases free and
   unlimited during alpha; pricing decided from real usage. No Stripe work now.

Slices 1-2 first: SES production access and the rewrite protocol are the only
things that can kill the project. Week-1 spikes: (a) file the SES
production-access request; (b) verify whether auth verdicts land as injected
headers on the S3 object or SNS-only.

## Verification (when built)

- Slice 1: end-to-end double-blind check with two real mailboxes (Gmail +
  Fastmail): full conversation both directions, assert neither side's real
  address appears in ANY received header (script the header dump); revoke ⇒
  silent drop; spoofed reverse-alias injection rejected.
- Slice 2: threading verified in Gmail/Outlook/Apple Mail across a 5+ message
  chain; leak checklist run against captured raw messages.
- Slices 4-5: auditor pass (Fable per subagent-model memory) with the paired-case
  and anonymous-attacker checklists from this doc.
