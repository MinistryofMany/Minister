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
- **Email is never disclosed.** There is no `email` scope and no email claim anywhere
  in the OIDC code. `scopes_supported` = `openid`, `profile`, `badge:*`; the claims
  resolver (`oidc-claims.ts`) never even loads an email field.

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
