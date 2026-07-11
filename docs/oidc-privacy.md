# OIDC privacy posture & disclosure

## What a relying-party client can see today (verified 2026-06-27, `main`)

- **`sub`** - pairwise pseudonymous id, `base64url(HMAC-SHA256(OIDC_PAIRWISE_SECRET,
userId || clientId))`. Different per client; never email, never a stable global id.
- **Default (`openid` only)** - sub + `iss/aud/iat/exp/nonce`. Nothing identifiable.
- **`profile` scope** - split into two independent claims, each an opt-in consent toggle
  defaulting OFF: `name` (from the user-curated `displayName`) and `picture` (from
  `avatarUrl`). The user may share one, both, or neither. A claim is emitted only when its
  toggle was approved AND the curated value is set; it is never sourced from the upstream
  auth identity (`User.name` / `User.image`), so a Google/GitHub login can't leak its real
  name or avatar.
- **`badge:<type>` scopes** - only the specific badge VCs the user ticks on consent. The RP
  requests only the types a room requires; with a structured `minister_policy` requirement
  the disclosure is minimized server-side to one minimal satisfying set (see "Disclosure
  model" in `CLAUDE.md` / `docs/status.md`).
- **`sybil-score` scope** - a single coarse claim, `sybil_bucket` (an integer 0-4), the
  user's account-strength band. Opt-in, default OFF, snapshotted at consent (see below).
- **Email is never disclosed.** There is no `email` scope and no email claim anywhere
  in the OIDC code. `scopes_supported` = `openid`, `profile`, `sybil-score`, `badge:*`; the
  claims resolver (`oidc-claims.ts`) never even loads an email field.

## Anti-sybil bucket (`sybil_bucket`) — resolution & correlation posture

The `sybil-score` scope discloses one integer, `sybil_bucket ∈ {0,1,2,3,4}` — a coarse
"how hard is this account to fake" band, never the raw score and never the underlying
badges. Privacy properties, all load-bearing:

- **~2.3 bits of entropy, dominated by the pairwise `sub`.** Five buckets carry at most
  `log2(5) ≈ 2.32` bits. The `sub` an RP already holds is a full pairwise pseudonym
  (128-bit HMAC), so the bucket adds a _negligible_ within-RP fingerprint on top of an
  identifier that is already unique. As a **cross-RP** correlator it is near-useless: two
  colluding RPs see different pairwise `sub`s and, at best, a 5-way bucket that a large
  fraction of users share — far too coarse to join on.
- **Do NOT increase the resolution without a fresh privacy re-review.** The whole
  guarantee rests on the bucket being coarse (5 bands). Widening it (more buckets,
  exposing the raw score, or adding per-category detail) turns a negligible correlator
  into a real cross-RP / fingerprinting vector and MUST be re-reviewed before shipping.
- **It leaks the aggregate existence of undisclosed holdings, by design.** The bucket is
  computed over _all_ the user's native, unexpired badges — including ones they did NOT
  disclose to this RP. So a high bucket tells the RP "this account holds strong
  credentials somewhere" without saying which. This is intentional (it is the point of an
  anti-sybil signal) and the consent copy states it plainly: _"This shows how hard your
  account is to fake. It does not reveal which badges you have."_
- **Snapshotted once, at consent — never recomputed.** The bucket is computed a single
  time in `approveConsent`, stamped onto the authorization code (`sybilScore` grant bool +
  `sybilBucket`), and denormalized onto the access token. `/oidc/token` and
  `/oidc/userinfo` read that stored value back verbatim; they never re-score. So the value
  an RP sees reflects the user's holdings _at the moment they consented_, and later badge
  changes do not silently alter an outstanding grant. Compute failure at consent
  fail-closed-omits the claim (audited, login unaffected).

## Decided intent (Tyler, 2026-06-17)

No identifiable information is shared by default. If a client requests it and the user
opts in, the consent screen must state EXACTLY what is being shared. Email is never
shared through normal OIDC claims; a curated display name is the most a user reveals.

## Resolved (the intent is now enforced in code)

1. **`profile` no longer falls back to the real auth identity.** `resolveUserClaims`
   (`oidc-claims.ts`) takes only the user-curated `displayName` / `avatarUrl`; the upstream
   `User.name` / `User.image` is not a parameter, so it cannot leak. A granted-but-uncurated
   claim is omitted rather than filled from upstream.
2. **The consent copy describes exactly what is sent.** `consent-screen.tsx` shows the literal
   value per claim - "Name: <displayName>" and the avatar thumbnail, or "(none set) — nothing
   to share" when uncurated - with no email mention anywhere.

The optional hardening was also taken: `profile` is split into independent name / avatar
toggles, and the consent screen previews the actual value the user would disclose, not just a
scope label.

## Future idea - per-client relay email (DOCUMENT ONLY, not building yet)

For a later messaging protocol: when a client (e.g. FreedInk) wants to message a user,
Minister mints a **per-(client, user) relay email address** unique to that link, which
forwards to the user's real inbox. The client only ever sees the relay address, never
the real email; the user can revoke the relay per client to cut off messaging without
exposing or changing their real address. Preserves the "client never sees identifiable
info" invariant while still enabling contact. Not scheduled.
