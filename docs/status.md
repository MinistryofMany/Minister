# Tessera — Status

Last updated: 2026-05-15 (after Stage 5).

This document is a snapshot of where the codebase actually is, what
remains for each upcoming stage, and the load-bearing design decisions
we've made (with the *why* attached so we don't relitigate). The
canonical design lives in [`CLAUDE.md`](../CLAUDE.md); this doc is its
operational counterpart.

---

## What's built

### Stage 0 — foundation ✅
- pnpm workspace (`apps/*`, `packages/*`, `services/*`).
- Next.js 15 App Router app with Tailwind v4, Prisma 6.
- Auth.js v5 with Passkey + email-magic-link providers; magic links are
  printed to the tessera container's stdout (`src/lib/mailer.ts`) — no
  mailhog, per your call during Stage 0.
- Prisma schema with the full domain model from CLAUDE.md (auth tables
  + Tessera domain), pushed via `prisma db push` on container start.
- docker-compose with postgres, tessera, and the seed one-shot.

### Stage 1 — VC + did:web ✅
- `@tessera/vc` package: Ed25519 issuer, `issueVc` / `verifyVc`,
  `getDidDocument`, `loadIssuer` with env-driven prod + persistent
  dev-key file.
- `/.well-known/did.json` + `/.well-known/jwks.json` route handlers,
  serving the same Ed25519 key with matching `kid`.
- Profile page with badge grid, public/private toggle, drag-drop
  reordering (`@dnd-kit/sortable`).
- Public profile route `/u/[userId]` showing only `isPublic = true`
  badges.

### Stage 2 — plugins + email-domain ✅
- `@tessera/plugin-sdk`: `Plugin`, `PluginManifest`, `WizardStep` (with
  per-kind payload types), `PluginContext` (origin / audit / sendMail),
  `HandleStepResult` discriminated union.
- `@tessera/shared`: badge type registry with Zod schemas for each
  initial badge type.
- Wizard runtime (`apps/tessera/src/server/wizard.ts`): starts
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
  hidden fields.
- `/oidc/token`: client auth via Basic or form body, Argon2id verifies
  `client_secret`. Race-safe code consumption via `updateMany`. Mints
  Ed25519 ID + access tokens.
- `/oidc/userinfo`: bearer-token auth, looks up the access token row by
  `jti`, returns claims (sub, name/picture, tessera_badges).
- Admin seed-client script (`scripts/seed-client.ts`) with idempotent
  upsert; auto-run in compose for the demo client.

### Stage 4 — demo client ✅
- `apps/demo-client/`: Auth.js generic OIDC provider pointing at
  Tessera. Pages: `/` (sign in), `/me` (decoded tokens + verified VC),
  `/badges/email-domain` (gated by an email-domain VC signature-checked
  against `/.well-known/jwks.json`).
- Compose: `tessera-seed` one-shot upserts the OidcClient row with
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
- Submits the finalized presentation to Tessera via a new endpoint
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
- Tessera's `did:web` includes the notary's public key alongside our
  signing key, or notary key lives in its own well-known endpoint —
  decision pending.

**`services/tlsn-verifier/`**
- Replace the alpine stub with a small Rust HTTP service wrapping the
  `tlsn-verifier` crate. Accepts a finalized presentation + expected
  domain, returns the verified transcript or an error.
- Tessera's wizard runtime calls this via HTTP.

**Plugin runtime additions**
- `extension-action` step kind needs a renderer (third unused step).
- New Tessera endpoint that the extension POSTs the presentation to —
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
- Production deploy guide (Postgres + Tessera + Redis + KMS),
  health-check endpoints, structured logging, OpenTelemetry hooks.

---

## Design decisions, with the *why*

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
- **24h sliding TTL, 1h refresh.** Tessera is bursty (wallet-shaped),
  not daily. 24h hits the security/UX sweet spot.

### OIDC provider
- **Hand-rolled, not `node-oidc-provider`.** CLAUDE.md preference; we
  wanted to read every line. Worth the ~1000 lines for educational
  value + control of the consent UX.
- **Pairwise pseudonymous `sub`.** Two RPs can't correlate users by id.
  Implementation: `HMAC-SHA256(OIDC_PAIRWISE_SECRET, userId:clientId)`.
- **Access tokens are JWTs (RFC 9068) but reference a server-side
  row.** First cut embedded `tessera_uid` (raw user id) in the JWT,
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
- **docker-compose for postgres + tessera + tessera-seed.** demo-client
  runs on the host (issuer-URL match with the discovery doc).
- **TLSNotary services as alpine stubs** until Stage 6. Their
  Dockerfiles + READMEs are in place; commented out in
  docker-compose.yml.
- **Magic-link emails to stdout in dev.** Real transport (Resend) is
  Stage 9.

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
