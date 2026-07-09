# Social-account badge providers

Minister issues an `oauth-account` badge (and, where the provider exposes an
account-creation date, a coarse `account-age` badge) by having the user prove
control of a third-party account. Each provider is a plugin under
`apps/minister/src/plugins/<id>/`.

Every provider that needs credentials is **fail-closed**: it is offered in the
"Add a badge" menu, and its wizard will start, **only** when its environment
variables are set. Leave the vars unset and the provider stays hidden. Set them
to turn it on. Steam and Hacker News need no credentials and are always
available.

For most providers the immutable, un-renameable account identifier is used only
as an internal Sybil anchor: it is nullified and discarded by the wizard runtime
and never lands in the credential or wizard state, and only the renameable handle
(username, persona, or verified email) is disclosed in the badge. The exception
is **Hacker News**, whose username IS both the immutable anchor and the disclosed
handle (there is no separate id), so the anchor legitimately appears in the
credential by design (the badge opts out of the anchor-leak guard via
`revealsAnchor`); `email-exact` is the same shape. The anchor is always nullified
for dedup. It is never written to the audit log either, with the same Hacker News
exception: HN logs its disclosed handle only on the verified event, because for
Hacker News the handle IS the anchor.

All redirect/callback URLs below use the production host `https://ministry.id`.
For local development, substitute your dev origin (for example
`http://localhost:3000`); the plugin builds the redirect URI from the request
origin, so register whichever origin you actually run on.

---

## Mirror + drift-check (READ BEFORE gating an RP on a new provider)

The `OAUTH_PROVIDERS` list lives in `packages/shared/src/badge-types.ts` AND is
hand-transcribed into the separate `@minister/client` repo
(`minister-client/src/badges`). This repo just added `reddit`, `steam`,
`hackernews`, and `x` to that list. The SDK mirror and the planned cross-repo
drift-check are **not** updated by this change. Before any relying party
(FreedInk, Discreetly, etc.) gates on a badge from one of these new providers,
update the `@minister/client` mirror and the drift-check, or the RP will
silently reject the badge (strict drift fails closed).

---

## Reddit

- **Register at:** https://www.reddit.com/prefs/apps -> "create another app" ->
  type **web app**.
- **Redirect / callback URI:** `https://ministry.id/badges/new/reddit/callback`
- **Scopes:** `identity`
- **Env (.env):**
  ```
  REDDIT_CLIENT_ID=...
  REDDIT_CLIENT_SECRET=...
  ```

Notes: the token exchange authenticates the client with HTTP Basic and requires
a descriptive `User-Agent`; both are handled by the plugin. Issues
`oauth-account` (handle = username) and `account-age` (from `created_utc`).

## Steam

- **Register at:** nothing to register for the core proof. Steam OpenID 2.0 needs
  no client registration and no secret.
- **Redirect / callback URI:** `https://ministry.id/badges/new/steam/callback`
  (sent as the OpenID `return_to`; no dashboard to enter it in).
- **Scopes:** none (OpenID identity assertion only).
- **Env (.env):** none required. Optional, only to include the player's public
  persona name in the badge:
  ```
  STEAM_WEB_API_KEY=...   # from https://steamcommunity.com/dev/apikey
  ```

Notes: the core ownership proof is an OpenID 2.0 assertion verified by a
`check_authentication` post-back to `steamcommunity.com` - **no key needed**.
Without `STEAM_WEB_API_KEY` the badge still issues; it just omits the persona
handle. The Sybil anchor is the 64-bit `steamid64`.

## Hacker News

- **Register at:** nothing. Hacker News has no OAuth or app API.
- **Redirect / callback URI:** none (no redirect flow).
- **Scopes:** none.
- **Env (.env):** none. Always available.

Notes: a challenge flow. The user enters their HN username, Minister shows a
one-time token, the user pastes it into their HN profile "about" field, and
Minister confirms it via the public, keyless API
(`https://hacker-news.firebaseio.com/v0/user/<id>.json`). Hacker News caches
profile edits for a few minutes, so the verify step has a "Verify again" retry
affordance. Issues `oauth-account` (handle = username, which is also the
immutable anchor) and `account-age` (from `created`).

## Google / YouTube

- **Register at:** https://console.cloud.google.com/apis/credentials -> "Create
  credentials" -> "OAuth client ID" -> **Web application**.
- **Redirect / callback URI:** `https://ministry.id/badges/new/google/callback`
- **Scopes:** `openid email` (both non-sensitive; **no Google security review**).
- **Env (.env):**
  ```
  GOOGLE_CLIENT_ID=...
  GOOGLE_CLIENT_SECRET=...
  ```

Notes: tier-1 only. This issues a plain Google-account `oauth-account` badge
whose handle is the user's **verified** email; the Sybil anchor is the immutable
`sub`. **Follow-on (not built):** YouTube channel-ownership proof needs the
`youtube.readonly` scope, which is a **sensitive scope requiring Google app
review and verification**. That is deliberately out of scope here; wire it as a
separate flow once the review is done.

## Instagram - deferred (do not build)

Instagram has **no personal-account identity API** since Basic Display was shut
down (the Graph API covers only Business/Creator accounts via a linked Facebook
Page, which is not a personal-account ownership proof). An Instagram badge is
**deferred to the TLSNotary track** (prove control by notarizing an
authenticated instagram.com session), not built as an OAuth provider.
