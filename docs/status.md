# Minister — Status

Last updated: 2026-05-15 (after Stage 5).

This document is a snapshot of where the codebase actually is, what
remains for each upcoming stage, and the load-bearing design decisions
we've made (with the _why_ attached so we don't relitigate). The
canonical design lives in [`CLAUDE.md`](../CLAUDE.md); this doc is its
operational counterpart.

---

## What's built

### Stage 0 — foundation ✅

- pnpm workspace (`apps/*`, `packages/*`, `services/*`).
- Next.js 15 App Router app with Tailwind v4, Prisma 6.
- Auth.js v5 with Passkey + email-magic-link providers; magic links are
  printed to the minister container's stdout (`src/lib/mailer.ts`) — no
  mailhog, per your call during Stage 0.
- Prisma schema with the full domain model from CLAUDE.md (auth tables
  - Minister domain), pushed via `prisma db push` on container start.
- docker-compose with postgres, minister, and the seed one-shot.

### Stage 1 — VC + did:web ✅

- `@minister/vc` package: Ed25519 issuer, `issueVc` / `verifyVc`,
  `getDidDocument`, `loadIssuer` with env-driven prod + persistent
  dev-key file.
- `/.well-known/did.json` + `/.well-known/jwks.json` route handlers,
  serving the same Ed25519 key with matching `kid`.
- Profile page with badge grid, public/private toggle, drag-drop
  reordering (`@dnd-kit/sortable`).
- Public profile route `/u/[userId]` showing only `isPublic = true`
  badges.

### Stage 2 — plugins + email-domain ✅

- `@minister/plugin-sdk`: `Plugin`, `PluginManifest`, `WizardStep` (with
  per-kind payload types), `PluginContext` (origin / audit / sendMail),
  `HandleStepResult` discriminated union.
- `@minister/shared`: badge type registry with Zod schemas for each
  initial badge type.
- Wizard runtime (`apps/minister/src/server/wizard.ts`): starts
  sessions, persists state, lifts `pendingToken` from magic-link and
  redirect steps, validates `IssuedBadge.claims` against the badge
  type's schema before signing the VC.
- `email-domain` plugin end-to-end: form → magic-link →
  oauth-account-less VC issuance.

### Auth hardening ✅

- JWT-strategy sessions, 24h sliding TTL, 1h refresh.
- Edge middleware route protection on `/profile`, `/settings`,
  `/badges`, `/oidc/authorize`.
- Two-layer model: middleware verifies JWT signature on Edge
  (`auth.config.ts`), server components verify via `getCurrentSession`
  in Node (`lib/session.ts`).
- Per-user `sessionGeneration` counter; `revokeAllSessions` bumps,
  next protected request fails the staleness check.
- "Sign out of all devices" button on `/settings`.

### Stage 3 — OIDC provider ✅

- `/.well-known/openid-configuration` (RFC 8414 / OIDC Discovery).
- `/oidc/authorize` page: validates params per RFC 6749 + OIDC Core
  (response_type=code, scope, state, nonce, PKCE S256), renders consent
  screen with per-badge toggles. Validated request is HS256-signed via
  `lib/oidc-request-token.ts` so the consent form POST doesn't trust
  hidden fields. The disclosure model (per-room minimal disclosure,
  anonymity-aware OR/threshold selection, profile grant split) is below
  under "Disclosure model."
- `/oidc/token`: client auth via Basic or form body, Argon2id verifies
  `client_secret`. Race-safe code consumption via `updateMany`. Mints
  Ed25519 ID + access tokens.
- `/oidc/userinfo`: bearer-token auth, looks up the access token row by
  `jti`, returns claims (sub, name/picture, minister_badges).
- Admin seed-client script (`scripts/seed-client.ts`) with idempotent
  upsert; auto-run in compose for the demo client.

### Disclosure model ✅

Minister discloses the minimum an RP needs and lets the user pick the
most-anonymous way to satisfy a requirement.

- **Per-room minimal disclosure.** The RP requests only the badge types a
  room (or gated action) requires, as `badge:<type>` scopes. Consent shows
  nothing beyond those; the user discloses only the specific badge VCs they
  tick. Declining a badge doesn't abort the flow.
- **Anonymity-aware OR/threshold selection.** A room can send its
  requirement as a structured boolean policy on the authorize request via
  the **`minister_policy`** param (base64url JSON: `allOf` / `anyOf` /
  `atLeast{n,of}` / badge leaves with optional `where` / `maxAgeDays`).
  The policy model mirrors Discreetly's policy package
  (`lib/oidc-policy.ts`), kept honest by `oidc-policy.drift.test.ts`.
  `parseMinisterPolicy` (`lib/oidc-authorize.ts`) validates it fail-closed:
  base64url + JSON decode, strict Zod schema, 4 KB byte cap, breadth bounds
  (`MAX_ATLEAST_N` 16, `MAX_NODE_CHILDREN` 16, `MAX_POLICY_NODES` 64),
  depth cap (`MAX_POLICY_DEPTH` 8), and every type in the policy must be in
  the requested scope — so a policy can only structure the permitted scope
  menu, never widen it. The validated policy rides into consent inside the
  signed request token.
- For a satisfiable policy, Minister computes per-type holder counts
  (`anonymity-sets.ts`: `COUNT(DISTINCT userId)` per type, in-process cache
  ~60s, server-side only) and preselects the minimal satisfying set with
  the largest anonymity (`selectMinimalAnonymitySet`), tie-broken by fewest
  badges. Consent renders the requirement as a choice (radio for one-of,
  pick-n for n-of, checkboxes for all-of) with a coarse per-type anonymity
  bucket (`anonymity-hint.ts`) so the user can make an informed override.
  Neither the user nor the RP sees the raw count.
- The preselection/override is advisory. The authoritative over-disclosure
  guard is server-side minimization on consent submit
  (`oidc-consent-minimize.ts:minimizeToPolicy`, from
  `oidc-actions.ts:approveConsent`): the submitted owned ∩ requested badges
  are trimmed to one minimal satisfying set before persistence, so a
  tampered POST that ticks two branches (or extra badges past `atLeast n`)
  can never reach `minister_badges` as more than one minimal set. No policy
  ⇒ identity, falling back to the flat per-scope menu.
- **Profile grant split.** The `profile` scope is consented per claim —
  `approveName` and `approveAvatar` are independent toggles, default OFF,
  persisted as `profileName` / `profileAvatar` on `OidcAuthorizationCode`
  (denormalized onto `OidcAccessToken`). `resolveUserClaims`
  (`oidc-claims.ts`) emits `name` and `picture` independently, only from
  the user-curated `displayName` / `avatarUrl`, only when granted and set —
  never from the upstream auth identity (`User.name` / `User.image` isn't a
  parameter), so a Google/GitHub login's real name and avatar can't leak.

### Stage 4 — demo client ✅

- `apps/demo-client/`: Auth.js generic OIDC provider pointing at
  Minister. Pages: `/` (sign in), `/me` (decoded tokens + verified VC),
  `/badges/email-domain` (gated by an email-domain VC signature-checked
  against `/.well-known/jwks.json`).
- Compose: `minister-seed` one-shot upserts the OidcClient row with
  deterministic dev creds; demo-client runs on host (avoids
  issuer-URL-mismatch with the discovery doc).

### Stage 5 — github plugin + redirect step ✅

- Second concrete plugin exercising the `redirect` step kind.
  `RedirectStepPayload.expectedState` lifts to `pendingToken` exactly
  like magic-link's `expectedToken`.
- `RedirectStep` renderer in the wizard UI.
- `/badges/new/github/callback` page handles the OAuth bounce-back.
- `resumeViaPendingToken({token, userId, origin, input})` is the
  generic round-trip helper; `consumeMagicLinkToken` is a compat shim.
- Live e2e against github.com requires real OAuth app creds — the user
  sets `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.

### Stage 7 — shareable proof links ✅

- `/share/[token]` public landing. Looks up by token, checks expiry +
  revocation + `requiresAccount`, records a `ShareLinkView` row
  (with `viewerUserId` populated when signed in, `null` for anonymous
  reads — and `null` is also written when a `requiresAccount` link is
  hit by an unauthenticated viewer, so the owner can see the
  attempted access).
- `/shares` user dashboard: lists every link the user has created,
  shows status (active / expired / revoked), view count, and a
  revoke button.
- `createShareLink` / `revokeShareLink` server actions in
  `src/server/share-actions.ts`. Optional `sendToEmail` triggers the
  existing `sendMail` (console-log in dev; real transport is Stage 9).
- Token entropy: 32 random bytes (256 bits) → 43 base64url chars.
- Default TTL 7 days, capped at 90.
- Owners can revoke; revoked + expired both surface "Link
  unavailable" rather than leaking which state it's in.

### Stage 6 — TLSNotary, Minister-side ◐ partial

What's wired:

- `tlsn-attestation` plugin (generic; specific TLSN plugins extend it
  in Stage 8).
- `extension-action` step kind: payload carries
  `expectedSubmissionToken` which the wizard runtime lifts onto
  `WizardSession.pendingToken`. Same resolution path as magic-link and
  OAuth redirect — `resumeViaPendingToken`.
- `extension-action` renderer in the wizard UI
  (`apps/minister/src/components/wizard-client.tsx`).
- `POST /api/tlsn/submit` route. CORS-permissive (the extension hits
  it from `chrome-extension://...`), allowlist via
  `TLSN_SUBMIT_ALLOWED_ORIGINS`. Enforces the token belongs to the
  signed-in user, then hands `{ presentation }` to the plugin.
- `services/tlsn-verifier/` — real Rust Axum HTTP service with two
  modes:
  - `passthrough` (dev default): base64-decode + JSON-parse the
    "presentation," enforce serverName match, return the transcript.
  - `real`: stubs `verify_real()` and refuses to run so a
    misconfigured prod doesn't silently rubber-stamp. TODO: pin the
    `tlsn-verifier` crate and implement the function.
- `services/notary/` — pinned to
  `ghcr.io/tlsnotary/tlsn/notary-server:v0.1.0-alpha.11` in
  docker-compose. Persisted notary key in a named volume.
- `apps/extension/` — MV3 manifest, background service worker, popup.
  The background already knows how to POST a presentation to
  `/api/tlsn/submit`; it just doesn't have one to send yet.

What's left to finish Stage 6:

- Integrate `tlsn-js` in the extension. Prover runs in an offscreen
  document (MV3 service workers can't host heavy WASM in the worker
  context).
- Implement `ws-proxy` in Rust or Go. Stays an alpine stub until the
  extension's prover actually needs a TCP relay.
- Pin the `tlsn-verifier` crate in
  `services/tlsn-verifier/Cargo.toml` and implement `verify_real()`.
  Cross-check the crate version matches the `notary-server` image we
  pinned.

---

## What's left

### Stage 6 — TLSNotary

The largest unbuilt stage. Three new processes + a browser extension +
a third plugin.

**Browser extension (`apps/extension/`, doesn't exist yet)**

- WebExtension MV3 manifest, background service worker, content script,
  popup UI.
- TLSNotary prover (likely via the `tlsn-js` WASM package, runs in the
  extension's offscreen document for performance + same-origin
  isolation).
- Communicates with `ws-proxy` for the target HTTPS connection and
  `notary-server` for the co-signature.
- Submits the finalized presentation to Minister via a new endpoint
  (TBD: `POST /api/tlsn/submit`).
- Dev story: load unpacked extension into Chrome; talks to
  `http://localhost:3000` (configurable).

**`services/ws-proxy/`**

- Replace the alpine stub with a real implementation (Rust or Go
  preferred for the TCP socket handling). Accepts a WebSocket from the
  extension, opens a TCP socket to `{host}:{port}` provided in the
  request, relays bytes.
- Rate limiting + allow-list of target hosts (id.me, github.com, etc.).
  Defense against using us as an open proxy.

**`services/notary-server/`**

- Replace the alpine stub with the official `tlsn` notary binary
  pinned to a known version. Provides the trusted co-signature; runs
  on its own port (default 7047).
- Minister's `did:web` includes the notary's public key alongside our
  signing key, or notary key lives in its own well-known endpoint —
  decision pending.

**`services/tlsn-verifier/`**

- Replace the alpine stub with a small Rust HTTP service wrapping the
  `tlsn-verifier` crate. Accepts a finalized presentation + expected
  domain, returns the verified transcript or an error.
- Minister's wizard runtime calls this via HTTP.

**Plugin runtime additions**

- `extension-action` step kind needs a renderer (third unused step).
- New Minister endpoint that the extension POSTs the presentation to —
  resolves wizard session by sessionId (passed from the extension),
  calls verifier sidecar, hands result to the plugin.
- Plugin SDK may need an `onExtensionPresentation` callback shape, or
  reuse `handleStep` with an `{ presentation }` input.

**Plugin: `tlsn-attestation` (generic)**

- Stage 6 ships at least a generic TLSNotary plugin that lets the user
  prove "I control X at domain Y" by selecting an endpoint and a
  selector. The id.me-specific plugin is Stage 8.

### Stage 7 — shareable proof links

- `/share/[token]` route: bearer-token URL, server-side validation of
  `expiresAt` + `requiresAccount` + `revokedAt`.
- Server actions: `createShareLink`, `revokeShareLink`.
- UI on `/profile` to generate a link (pick badges, set expiry, copy
  URL).
- Track views via `ShareLinkView` (Stage 0 schema already has it).
- Email send for share links — needs a real mail transport (Resend),
  not console-log.

### Stage 8 — age via id.me + Eligibility

- `id.me` plugin: TLSNotary the page that shows the user's verified
  age, extract `birthYear`, compute `age-over-N` claims for the
  current `N` and future `Eligibility` rows for higher thresholds
  with ±30 day fuzz.
- Background job to auto-issue from eligible Eligibility rows
  (need a worker — Inngest, BullMQ, or a tiny cron container).

### Stage 9 — hardening

- Rate limiting on `/oidc/token`, `/oidc/authorize`,
  `/api/auth/signin/*`, share-link views. Probably Upstash Redis +
  middleware.
- KMS-backed signing key (envelope encryption around the private JWK).
- Real email transport (Resend or SES) for share-link emails + future
  account notifications.
- Audit-log review tooling — a `/admin/audit` page that paginates
  entries with filters.
- OIDC security review pass: check error-response side channels, code
  TTL strictness, refresh-token decisions, scope-creep prevention.
- Production deploy guide (Postgres + Minister + Redis + KMS),
  health-check endpoints, structured logging, OpenTelemetry hooks.

---

## Design decisions, with the _why_

These are choices we've made that aren't obvious from reading the code.
Documented so we don't relitigate.

### Authentication

- **JWT-strategy sessions.** Lets middleware verify auth on the Edge
  Runtime without a DB hit. Trade-off: revocation isn't instant by
  default; we layered `sessionGeneration` to fix it.
- **`sessionGeneration` revocation** rather than per-JTI deny list.
  User-granularity is sufficient for "sign out everywhere"; per-device
  revocation would need a separate table and isn't worth it yet.
- **Two-layer enforcement** (Edge middleware verifies sig, server
  components verify gen). Required so the home page and header don't
  enter an infinite redirect loop with a stale-but-cryptographically-
  valid JWT — both ends of any redirect must look at the same
  staleness signal.
- **`getCurrentSession` / `requireSession`** are the only safe API for
  user-specific data. Raw `auth()` skips revocation.
- **24h sliding TTL, 1h refresh.** Minister is bursty (wallet-shaped),
  not daily. 24h hits the security/UX sweet spot.

### OIDC provider

- **Hand-rolled, not `node-oidc-provider`.** CLAUDE.md preference; we
  wanted to read every line. Worth the ~1000 lines for educational
  value + control of the consent UX.
- **Pairwise pseudonymous `sub`.** Two RPs can't correlate users by id.
  Implementation: `HMAC-SHA256(OIDC_PAIRWISE_SECRET, userId:clientId)`.
- **Access tokens are JWTs (RFC 9068) but reference a server-side
  row.** First cut embedded `minister_uid` (raw user id) in the JWT,
  which defeated the pairwise sub for any RP that decoded the access
  token. Fixed: `jti` claim in JWT → `OidcAccessToken` row → server-
  side userId lookup at `/userinfo`. Reverse-engineering the user id
  from the access token is now no longer possible.
- **Signed consent-request token** between `/authorize` page and the
  consent server action. Prevents a malicious browser extension from
  modifying hidden form fields to escalate scopes or change client_id.
  Uses HS256 with `AUTH_SECRET` (same secret as session JWTs — Stage
  9 may want to separate).
- **Auth codes single-use, 60s TTL, race-safe consumption** via
  `updateMany(where: { code, consumedAt: null })`.
- **Pages use `redirect()` to external `redirect_uri`s.** This required
  turning `typedRoutes` off in `next.config.ts` (it only accepts
  literal internal routes).
- **`minister_policy` is validated, never trusted.** The param arrives on
  the front-channel authorize URL, so it's bounded (bytes, breadth, depth)
  and constrained to types already in the requested scope before it's
  signed into the request token. The bounds aren't cosmetic: a flat,
  shallow `atLeast{n, of: [many leaves]}` stays small and shallow yet drives
  quartic+ combination enumeration in selection — the breadth caps are the
  defense depth alone can't give.
- **Anonymity preselection is advisory; minimization is authoritative.**
  The consent radio/pick-n is UX. `minimizeToPolicy` on submit is the real
  over-disclosure guard, so the disclosed set is one minimal satisfying set
  regardless of what a tampered POST ticks. Holder counts are server-side
  only and bucketed for the user — a live integer per type would be a
  per-type side channel.
- **`profile` split into independent name/avatar grants.** A user may want
  to share a handle but not a face (or vice versa); one `profile` toggle
  can't express that. The grant is two booleans end-to-end, and the resolver
  emits each claim only from the curated value — never the upstream auth
  identity, which closes the silent-real-name-leak the earlier `displayName
?? name` fallback had.

### Plugins

- **In-process modules, no dynamic loading.** Per CLAUDE.md. Adds a
  plugin = imports it from `plugins/registry.ts`.
- **Per-step-kind renderer.** Plugins return `WizardStep` payloads; the
  built-in `WizardClient` dispatches on `kind`. Most plugins write zero
  React.
- **`WizardSession.pendingToken` is the round-trip key** for both
  magic-link (`expectedToken`) and OAuth-redirect (`expectedState`).
  Same column, same lookup. `resumeViaPendingToken({token, userId,
origin, input})` is the generic callback path.
- **Plugins are responsible for state.** Wizard runtime just persists
  whatever the plugin returns. State is JSON in `WizardSession.state`.
- **Claims validated against badge type's Zod schema before signing.**
  `issueBadgesAndComplete` calls `BADGE_TYPES[type].schema.parse(claims)`
  — plugins can't issue VCs with claim shapes the registry doesn't know
  about.

### Data privacy

- **Minimum-PII.** The email-domain plugin stores only the domain, not
  the email. Eligibilities allow age verification once with ±N day
  fuzz on auto-issuance, never storing the DOB.
- **The signed VC is the authoritative artifact.** `Badge.attributes`
  is denormalized for query/display; the `vcJwt` is what gets
  disclosed. If they disagree, the VC wins.
- **Private by default.** All badges have `isPublic=false` on
  issuance. Public profile (`/u/[id]`) only shows what the user
  explicitly flagged.

### Repo hygiene

- **`Cipher <cipher@heart.engineering>`** is the AI author per your
  global instructions.
- **Conventional commits.** Each feat/fix/refactor commit ends with a
  Claude co-author line.
- **Worktrees per stage.** Branch off main, build, verify, fast-forward
  merge, remove. Avoids touching main directly mid-work.
- **No `any` / `@ts-ignore` without an inline justification.**
- **RSC boundary discipline.** Zod schemas (class instances) can't
  cross from server to client components. Use plain-object view types
  (e.g. `BadgeMetaView`) at the seam. TypeScript won't catch this; it
  fails at runtime.
- **`server-only` is NOT imported** anywhere — Next.js's bundle splits
  ensure modules under `src/server/` never reach the client, and the
  RSC convention guards the rest. If we ever do a runtime sanity check,
  this is the dep to grab.

### Infra

- **docker-compose for postgres + minister + minister-seed.** demo-client
  runs on the host (issuer-URL match with the discovery doc).
- **TLSNotary services as alpine stubs** until Stage 6. Their
  Dockerfiles + READMEs are in place; commented out in
  docker-compose.yml.
- **Magic-link emails to stdout in dev.** Real transport (Resend) is
  Stage 9.

---

## Hardening / known gaps (intentionally incomplete)

- **OIDC grants outlive a ban only at the RP boundary — no back-channel
  logout yet.** Banning a user (`setUserBanned`) and "sign out of all devices"
  (`revokeAllSessions`) now revoke that user's outstanding `OidcAccessToken`
  rows in the same transaction as the `sessionGeneration` bump, closing the
  ≤1h window where `/oidc/userinfo` would keep answering a banned/signed-out
  user's access token. **Still missing:** Minister cannot terminate sessions
  the user already holds _inside_ relying-party apps — that requires OIDC
  back-channel logout (deferred — Stage 9+). Until then, an RP that minted its
  own session from a now-revoked grant keeps that session until its own TTL.

- **TLSN verifier URL SSRF allowlist not yet enforced — warns at startup.**
  `TLSN_VERIFIER_URL` is operator-set and reached via server-side `fetch` in
  `src/lib/tlsn-verifier.ts`, so a misconfigured or attacker-influenced value
  is an SSRF vector. The allowlist infra is not deployed yet, so the full fix
  (hard-rejecting out-of-allowlist hosts) is not in place. Current mitigation:
  `validateTlsnVerifierConfig()` runs at startup (wired through
  `src/instrumentation.ts`) and WARNS when `TLSN_VERIFIER_URL` is unset, not a
  valid `http(s)` URL, or — when `MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS` is set —
  its host is outside the allowlist; it also warns when no allowlist is
  configured. The call site rejects non-`http(s)` schemes as defense-in-depth.
  Nothing throws; it nags every boot. **Finish when verifier infra lands:** make
  the allowlist mandatory and turn the warning into a hard rejection.

---

## Deploy notes

- **Crypto-core Phase 4 — `NullifierRpCheck` table (additive).** M5 adds the
  salted stage-2 drift cache `NullifierRpCheck` (`@@unique([entryRef, clientId])`,
  per-row random `salt`, `check = SHA-256(salt || N_rp)`). It is additive and
  starts EMPTY, so the existing `prisma db push` on container start creates it
  with zero data risk — no data backfill, no destructive change. Migrations are
  still manual (#47): if a prod deploy uses `prisma migrate deploy` instead of
  `db push`, generate the migration from this schema and apply it in the same
  boot step. **The migration is CONSEQUENTIAL, not cosmetic.** With the table
  absent, `prisma.nullifierRpCheck.findUnique` throws `P2021` inside the
  per-badge disclosure try, so EVERY nullifier-bearing badge is fail-closed
  OMITTED from every disclosure (RP badge gating silently goes dark — audit rows
  only) until the table exists. Logins themselves are unaffected. So: run
  `db push` / `migrate deploy` BEFORE relying on any nullifier gating; do not
  deprioritize this step reading it as "drift detection is merely inert."

- **Crypto-core Phase 4 — DEPLOY-ORDERING gate (SDK before Minister).** Phase 1
  dropped `OAuthAccountClaims.accountId` and Phase 4 strips it from legacy
  re-disclosures. An RP still on the PRE-branch SDK (whose `OAuthAccountClaims`
  REQUIRES `accountId`) schema-rejects every disclosed `oauth-account` badge the
  moment Minister deploys — fail-closed deny on gated joins (login unaffected).
  Therefore **merge + relink/repin every badge-consuming RP to SDK ≥ the
  crypto-core commit BEFORE (or atomically with) deploying Minister's
  crypto-core branch.** Discreetly consumes the SDK via `link:` today so it
  follows the local checkout; if its CI clones `minister-client` main, merge the
  SDK branch there first. FreedInk requests no badge scopes, so it is unaffected.

- **Crypto-core Phase 4 — interim→signet backend FLIP runbook.** In the interim
  window (`MINISTER_NULLIFIER_BACKEND=interim`), disclosed `N_rp` values, every
  `Badge.nullifierRef`, and every `NullifierRpCheck` row live in the interim
  namespace and are NOT byte-compatible with the Signet construction (interim
  uses one global `k_int`; Signet uses per-RP `k_disc(clientId)`). Flipping the
  backend to `signet` therefore RESETS every RP's gating tags. The flip is only
  safe under the ADR's enforced `users == 0` gate; if that still holds, the flip
  is a clean re-key. **Runbook at the flip:** (1) re-register every anchor into
  Signet's ledger (re-issue the ref-bearing badges); (2) `TRUNCATE
"NullifierRpCheck"` (its interim baselines are meaningless against Signet
  values, and a stale baseline would false-positive as drift and fail every
  affected badge closed); (3) notify RPs that gating tags reset (any bans/dedup
  state keyed on interim `mnv1:` values must be cleared — they will not match the
  new values). **Pre-deploy check:** confirm which backend serves disclosure in
  prod and that `users == 0` still holds; if real users have arrived, freeze the
  window (ADR risk #2) rather than flipping and burning live RP ban state.

- **Crypto-core Phase 4 — OUTSTANDING pre-sign-off e2e gate (not yet landed).**
  The build-plan Phase 4 gate requires a compose-staging e2e asserting the
  nullifier is **present + signed** in the badge-gated OIDC flow, **equal** across
  two logins of the same user at one RP, **different** across two RPs, and
  **byte-equal** across the serial-identity path (account A issues from the
  fixture credential → discloses → A deleted / entry released → account B issues
  from the SAME credential → discloses → assert equal `N_rp`). No Playwright spec
  covers this yet — it needs the full compose stack with the REAL Signet service,
  two registered OIDC clients, the github OAuth fixture, and an account-deletion
  path (Minister has no self-serve delete today). Compensating UNIT coverage
  exists and is green (`remint.test.ts` signature binding + per-RP stamping,
  `oidc-claims.nullifier.test.ts` disclosure seam + fail-closed omission,
  `share-links-disclosure.test.ts` nullifier absence, `signet-live.fixture.test.ts`
  frozen `N_dedup`/`N_rp` vectors; cross-account equality holds by construction —
  `ownerHandle` never enters the derivation). This full-flow spec MUST be landed
  and green in the compose stack before Phase 4 deploy sign-off; do not treat the
  passing unit suites as satisfying the gate.

---

## Process notes (so we keep the bar where it is)

- Each feature in its own worktree branched off main; merged with
  fast-forward only.
- Each work block has an explicit verify step before commit — typecheck,
  build, and live e2e via Playwright where possible.
- Real bugs found during e2e (not just typecheck) get their own commit
  with the fix described, so the history shows the catch.
- Before moving to the next stage, audit the previous one — this doc
  exists because we're about to do exactly that for Stages 0–5 before
  Stage 6 lands.
