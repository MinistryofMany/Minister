# OIDC privacy posture & disclosure

## What a relying-party client can see today (verified 2026-06-17, `main`)

- **`sub`** - pairwise pseudonymous id, `base64url(HMAC-SHA256(OIDC_PAIRWISE_SECRET,
userId || clientId))`. Different per client; never email, never a stable global id.
- **Default (`openid` only)** - sub + `iss/aud/iat/exp/nonce`. Nothing identifiable.
- **`profile` scope** (opt-in; consent toggle defaults OFF) - `name` and `picture`.
- **`badge:<type>` scopes** - only the specific badge VCs the user ticks on consent.
- **Email is never disclosed.** There is no `email` scope and no email claim anywhere
  in the OIDC code. `scopes_supported` = `openid`, `profile`, `badge:*`; the claims
  resolver (`oidc-claims.ts`) never even loads an email field.

## Decided intent (Tyler, 2026-06-17)

No identifiable information is shared by default. If a client requests it and the user
opts in, the consent screen must state EXACTLY what is being shared. Email is never
shared through normal OIDC claims; a curated display name is the most a user reveals.

## Fixes owed (current code violates the intent)

1. **`profile` must not fall back to the real auth identity.** `resolveUserClaims`
   currently sends `displayName ?? name` and `avatarUrl ?? image` - so a user who signed
   in with Google/GitHub and never set a curated display name silently shares their REAL
   name and avatar. Change: expose ONLY the user-curated `displayName` / `avatarUrl`;
   send `null` (or omit) when uncurated. Never fall back to upstream `user.name` /
   `user.image`.
2. **The consent copy falsely says it shares your email.** `consent-screen.tsx` reads
   "Share your Minister display name (or fall back to your email) and avatar." The code
   never sends email. Fix the copy to describe exactly what is sent (display name +
   avatar), no email mention. This is a direct "make it clear" violation.

Optional hardening to consider: split `profile` into separate name / avatar toggles;
show the literal value that will be sent (e.g. "Name: Cipher" + avatar thumbnail) so the
user sees the actual data, not just a scope label.

## Future idea - per-client relay email (DOCUMENT ONLY, not building yet)

For a later messaging protocol: when a client (e.g. FreedInk) wants to message a user,
Minister mints a **per-(client, user) relay email address** unique to that link, which
forwards to the user's real inbox. The client only ever sees the relay address, never
the real email; the user can revoke the relay per client to cut off messaging without
exposing or changing their real address. Preserves the "client never sees identifiable
info" invariant while still enabling contact. Not scheduled.
