# Minister — Project Context

## What this is

Minister is an identity platform where each user holds a profile decorated with **badges** — verifiable credentials attesting to facts about them (owns an email at a given domain, owns a particular GitHub/Google account, has beaten a given Steam game, is over 21, is a Maryland resident, etc.). Third-party web apps log users in via Minister using OpenID Connect, and the user explicitly chooses which badges to disclose to each relying party. Minister also supports shareable proof links — signed, time-limited artifacts the user can hand to another person out of band.

### Acronyms used throughout

- **VC** — Verifiable Credential (W3C standard)
- **DID** — Decentralized Identifier
- **OIDC** — OpenID Connect (authentication layer on top of OAuth 2.0)
- **PKCE** — Proof Key for Code Exchange (OAuth 2.0 extension defending against authorization code interception)
- **JWS / JWT** — JSON Web Signature / JSON Web Token
- **JWKS** — JSON Web Key Set
- **RSC** — React Server Component
- **WASM** — WebAssembly
- **RP** — Relying Party (a third-party app that authenticates users via Minister)
- **WS** — WebSocket

## Architecture overview

Four services run together via `docker compose`:

1. **minister** — Next.js (App Router) app. Frontend, server actions, and OIDC Provider endpoints (Stage 3+). Connected to Postgres via Prisma. Holds the issuer signing key.
2. **postgres** — Application database.
3. **notary-server** — Stage 6+. Official TLSNotary notary binary. Co-signs TLS sessions for the user's browser extension.
4. **ws-proxy** — Stage 6+. WebSocket relay between the browser extension and the target HTTPS server. The extension cannot open raw TCP sockets, so it tunnels through this proxy to reach servers like id.me.

The user runs the **Minister browser extension** (`apps/extension/`, Stage 6+). It performs the actual TLSNotary proving in their browser, talking to the WS proxy and the notary server, then submits the finalized proof to Minister for verification and badge issuance.

## Tech stack

- TypeScript everywhere. Strict mode (`strict: true`, `noUncheckedIndexedAccess: true`).
- Next.js 15 (App Router), React 19, Tailwind v4, Prisma 6, NextAuth/Auth.js v5.
- App-internal calls use Next.js **server actions**. No tRPC for now — server actions cover what we need through Stage 2; reach for tRPC if we need typed RPC across the app/demo-client boundary.
- Auth into Minister: Passkeys (WebAuthn) primary, email magic links fallback. No passwords in v1. **JWT-strategy sessions** with 24h sliding TTL and per-user `sessionGeneration` revocation (see "Authentication and session model" below).
- UI: shadcn/ui-style components built on Tailwind + `class-variance-authority`. Drag-and-drop via `@dnd-kit/sortable`.
- VC format: W3C VC Data Model 2.0, serialized as JWT-VC. Signing algorithm Ed25519 (`alg: EdDSA`). Use the `jose` library.
- Issuer identity: `did:web:<minister-domain>` (dev default: `minister.local`). DID document at `/.well-known/did.json`; JWKS at `/.well-known/jwks.json`.
- OIDC provider: implement directly against the spec (Stage 3+). Don't depend on an off-the-shelf "OIDC provider for Next.js" library — most are abandoned, broken, or too opinionated about user/session models.
- TLSNotary: official `tlsn` Rust notary server, and a small Rust HTTP sidecar (`services/tlsn-verifier`) using the `tlsn-verifier` crate (Stage 6+). The Next.js app calls it over HTTP.
- Plugin system: in-process TypeScript modules under `apps/minister/src/plugins/<id>/`, registered through a central registry. No dynamic loading.

Package manager: pnpm. Node 20+.

## Monorepo layout

This repo is a pnpm workspace (`apps/*`, `packages/*`). **`packages/` is currently
empty** — the three `@minister/*` libraries live in _sibling git repos_ one level
above this one and are wired in by relative symlink, not as in-repo packages or
published npm deps. From `apps/minister/package.json`:

```
"@minister/plugin-sdk": "link:../../../minister-plugin-sdk",
"@minister/shared":     "link:../../../minister-shared",
"@minister/vc":         "link:../../../minister-vc",
```

So all three must be cloned as siblings of `Minister/`, or install/build breaks, and
editing them is live-editing this app (no publish step). The workspace-root
`../CLAUDE.md` describes the cross-repo picture.

```
MinistryOfMany/                  # workspace folder (not a git repo)
├── Minister/                    # this repo
│   ├── apps/
│   │   ├── minister/            # Main app (Next.js) — package @minister/app
│   │   ├── demo-client/         # Sample RP
│   │   └── extension/           # Browser extension skeleton (Stage 6+)
│   ├── packages/                # empty (see note above)
│   ├── services/
│   │   ├── notary/              # Stage 6+: tlsn notary binary (stub Dockerfile)
│   │   ├── ws-proxy/            # Stage 6+: WS relay (stub Dockerfile)
│   │   └── tlsn-verifier/       # Stage 6+: Rust HTTP sidecar (stub Dockerfile)
│   ├── docker-compose.yml
│   ├── pnpm-workspace.yaml
│   └── README.md
├── minister-vc/                 # @minister/vc          (linked in)
├── minister-shared/             # @minister/shared      (linked in)
└── minister-plugin-sdk/         # @minister/plugin-sdk  (linked in)
```

`apps/extension/` (browser extension) lands in Stage 6+.

## Core data model

Sketch — `apps/minister/prisma/schema.prisma` is canonical. Auth.js tables (User, Account, Session, VerificationToken, Authenticator) are managed by `@auth/prisma-adapter`; Minister domain models hang off `User.id`.

```prisma
model User {
  id            String    @id @default(cuid())
  // Auth.js-managed
  name          String?
  email         String?   @unique
  emailVerified DateTime?
  image         String?
  // Minister profile overrides (user-curated, independent of upstream auth)
  displayName   String?
  avatarUrl     String?
  // Monotonic counter embedded in every issued JWT. Bumping it invalidates
  // all outstanding sessions on the user's next protected request.
  sessionGeneration Int @default(0)
  // Gates /admin + admin server actions. Granted only via scripts/make-admin.ts.
  isAdmin  Boolean @default(false)
  // Banned users are treated as signed out by the session loader (layer 2).
  isBanned Boolean @default(false)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  accounts       Account[]
  sessions       Session[]            // unused under JWT strategy, kept for adapter contract
  authenticators Authenticator[]      // passkey credentials

  badges         Badge[]
  eligibilities  Eligibility[]
  shareLinks     ShareLink[]
  oidcClients    OidcClient[]
  wizardSessions WizardSession[]
}

model Badge {
  id           String   @id @default(cuid())
  userId       String
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  type         String   // e.g. "email-domain", "oauth-account", "age-over-21"
  attributes   Json     // denormalized non-sensitive attributes for query/display
  vcJwt        String   // the signed VC (JWT-VC). Authoritative artifact.
  issuer       String   // "did:web:ministry.id" for native; external DID/URL for imported
  issuedAt     DateTime @default(now())
  expiresAt    DateTime?
  isPublic     Boolean  @default(false)
  sortOrder    Int      @default(0)
  importedFrom String?  // null = native; non-null = source identifier
  pluginId     String?  // null for imported VCs
  @@index([userId, type])
}

model Eligibility {
  // The user hasn't yet been issued this badge, but on a fuzzed future date,
  // a background job will auto-issue it. E.g. user proved age 18 in 2026;
  // an Eligibility row says "X is eligible for age-over-21 on 2029-04-15".
  id         String   @id @default(cuid())
  userId     String
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  badgeType  String
  eligibleAt DateTime
  fuzzDays   Int      // ± days of fuzz applied at issuance time
  source     String   // plugin id that established eligibility
  @@unique([userId, badgeType])
}

model ShareLink {
  id              String   @id @default(cuid())
  userId          String
  user            User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  token           String   @unique          // URL-safe, ≥ 128 bits entropy
  badgeIds        String[]
  expiresAt       DateTime                  // default now + 7 days
  requiresAccount Boolean  @default(false)
  revokedAt       DateTime?
  createdAt       DateTime @default(now())
  views           ShareLinkView[]
}

model ShareLinkView {
  id           String    @id @default(cuid())
  shareLinkId  String
  shareLink    ShareLink @relation(fields: [shareLinkId], references: [id], onDelete: Cascade)
  viewerUserId String?                       // null if account not required
  viewedAt     DateTime  @default(now())
}

model OidcClient {
  id               String   @id @default(cuid())
  clientId         String   @unique
  clientSecretHash String?                   // null for public clients (PKCE-only)
  name             String
  redirectUris     String[]
  allowedScopes    String[]
  ownerUserId      String?
  createdAt        DateTime @default(now())
}

model OidcAuthorizationCode {
  code                String   @id
  clientId            String
  userId              String
  redirectUri         String
  scopes              String[]
  approvedBadgeIds    String[]
  codeChallenge       String
  codeChallengeMethod String
  expiresAt           DateTime
  consumedAt          DateTime?
}

model InviteCode {
  // Admin-minted, redeemed via the invite-code plugin. The code string
  // never lands in a VC or Badge.attributes — only `label` does.
  id            String    @id @default(cuid())
  code          String    @unique
  label         String              // campaign/cohort name; the VC claim
  usesTotal     Int                 // 0 = unlimited
  usesRemaining Int
  expiresAt     DateTime?
  revokedAt     DateTime?
  createdBy     String?
  createdAt     DateTime  @default(now())
  redemptions   InviteRedemption[]
}

model InviteRedemption {
  // Unique (inviteCodeId, userId) is the double-redeem guard; created in
  // the same transaction as the usesRemaining decrement.
  id           String     @id @default(cuid())
  inviteCodeId String
  userId       String
  redeemedAt   DateTime   @default(now())
  @@unique([inviteCodeId, userId])
}

model AuditLog {
  id        String   @id @default(cuid())
  userId    String?
  action    String
  metadata  Json
  createdAt DateTime @default(now())
}

model WizardSession {
  // Persists multi-step plugin flows across magic-link round trips.
  // Cleaned up on completedAt or after expiresAt.
  id           String    @id @default(cuid())
  userId       String
  user         User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  pluginId     String
  state        Json
  pendingToken String?   @unique             // indexed; verify routes look up by this
  createdAt    DateTime  @default(now())
  updatedAt    DateTime  @updatedAt
  completedAt  DateTime?
  expiresAt    DateTime
  @@index([userId, pluginId])
}
```

Notes:

- The signed VC (`vcJwt`) is the authoritative artifact. `attributes` is for query/display only.
- We store the VC even for imported credentials; the `issuer` field tells us whether to verify against Minister's key or an external DID.
- `Eligibility` is separate from `Badge` because the user hasn't actually been issued the future badge yet — it's a promise that on the eligible date a job will auto-issue it.

## Authentication and session model

**Strategy:** JWT-strategy Auth.js sessions. The cookie is a signed JWT (HMAC over `AUTH_SECRET`), not an opaque session-row id. This lets middleware verify auth at the Edge Runtime without a database hit.

**Config split:**

- `src/auth.config.ts` — edge-safe config: `providers: []`, JWT strategy, `jwt()` + `session()` callbacks, type augmentations. Imported by middleware and by the full auth module.
- `src/auth.ts` — spreads `authConfig`, layers on `PrismaAdapter`, `Passkey`, `ConsoleEmail` (dev) providers. Only loaded from Node runtime.
- `src/middleware.ts` — instantiates `NextAuth(authConfig)` and gates `/profile/*`, `/settings/*`, `/badges/*` with a 302 to `/?from=<path>` on missing/invalid JWT. `/`, `/u/[id]`, `/.well-known/*`, `/api/auth/*` stay public.

**TTL:**

- `session.maxAge: 24 * 60 * 60` (24h)
- `session.updateAge: 60 * 60` (1h)

Sliding window. An active user's JWT auto-refreshes at most once per hour, each refresh resetting the 24h clock. Idle for 24h → logged out. Minister is wallet-shaped (bursty use, not daily), so 24h hits the right point on the security/UX curve.

**Revocation (sessionGeneration):**

- Every `User` has `sessionGeneration: Int @default(0)`. At sign-in, the `jwt()` callback embeds `user.sessionGeneration` into `token.gen` — the adapter has already loaded the User row at this point, so no extra DB read.
- `src/lib/session.ts:getCurrentSession()` is the server-side session getter. It calls `auth()`, then compares the JWT's gen against the user's current gen via a `findUnique`. Mismatch → null. Wrapped in `React.cache()` so multiple call sites in one render (header + page) share one query.
- `src/server/account-actions.ts:revokeAllSessions()` increments the user's gen, audit-logs, and signs the current device out. Wired to a destructive "Sign out of all devices" button on `/settings`.

**Use `getCurrentSession()` / `requireSession()` — never raw `auth()` — anywhere that gates user-specific content. Raw `auth()` only verifies the JWT signature; it doesn't catch revoked sessions or bans.**

**Bans + admin:** the same cached session loader also enforces `User.isBanned` (banned ⇒ treated as signed out) and exposes `isAdmin` via `getSessionFlags()`. `requireAdmin()` gates `/admin` pages and admin server actions. The _first_ admin is minted via `pnpm --filter @minister/app admin:grant --email <email>` (bootstrap only); after that, admins promote/demote on `/admin/users`. Nobody can change their own admin flag (no self-demotion lockout). Banning a user bumps their `sessionGeneration`, killing live sessions on their next request; admins can't ban admins (demote first), and banned users can't be promoted (unban first).

**Per-request cost:**

| Page                             | DB hits for session                   |
| -------------------------------- | ------------------------------------- |
| Unauthenticated → protected      | 0 (Edge middleware bounces)           |
| Authenticated → protected page   | 1                                     |
| Authenticated → `/` or `/u/[id]` | 1 (header + page share via `cache()`) |
| `/u/[id]` viewed by anyone       | 1 (header only)                       |
| `/.well-known/*`                 | 0                                     |

**Two-layer model:**

- Layer 1 — Edge middleware: cheap JWT-signature check. Catches no-cookie and bad-signature.
- Layer 2 — server components via `getCurrentSession`: gen check against DB. Catches stale-but-cryptographically-valid (revoked) JWTs.

The home page (`/`) and the header both use `getCurrentSession` rather than raw `auth()` — otherwise a stale-but-valid JWT bounces between `/profile` (gen mismatch → `/`) and `/` (raw `auth()` truthy → `/profile`) in an infinite redirect. Both ends of any redirect loop must look at the same staleness signal.

## Verifiable Credential model

Each native badge is a VC issued by Minister. Imported badges keep their original issuer. JWT-VC payload shape:

```json
{
  "iss": "did:web:ministry.id",
  "sub": "did:web:ministry.id:users:<userId>",
  "iat": 1715000000,
  "exp": 1746536000,
  "nbf": 1715000000,
  "jti": "<badge id>",
  "vc": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential", "MinisterEmailDomainCredential"],
    "credentialSubject": {
      "id": "did:web:ministry.id:users:<userId>",
      "domain": "example.com"
    }
  }
}
```

`@minister/vc` (sibling repo `../minister-vc`, linked in) exports:

- `loadIssuer({ domain, privateJwk?, devKeyPath? })` → `Issuer`. Env-driven in prod (`ISSUER_PRIVATE_JWK`); ephemeral persistent key on first dev boot (`apps/minister/dev-keys/issuer.jwk`, gitignored).
- `issueVc(issuer, type, subjectId, claims, options?)` → `vcJwt`. Stamps `iat`/`nbf`/`exp`/`jti`; protected header carries `kid` matching the DID document.
- `verifyVc(issuer, vcJwt)` → typed credential or throws.
- `getDidDocument(issuer)` → DID document with a `JsonWebKey2020` verificationMethod.
- `buildDid`, `buildKid`, `buildUserDid` helpers.

Badge types each have a Zod schema for the `credentialSubject` claims, defined in `@minister/shared` (`../minister-shared/src/badge-types.ts`). The wizard runtime validates claims against this schema before signing.

### Initial badge types

- `email-domain` — `{ domain: string }` ✅ implemented
- `email-exact` — `{ email: string }` (less private, opt-in)
- `invite-code` — `{ label: string }` ✅ implemented (label = campaign name; the code string itself never enters the VC)
- `oauth-account` — `{ provider: "github" | "google" | "...", accountId: string, handle?: string }`
- `age-over-N` — `{ threshold: 16 | 18 | 21 | 25 | 30 | 35 | 40 | 45 | 55 | 65 }`
- `residency-country` — `{ country: string }` (ISO 3166-1 alpha-2)
- `residency-state` — `{ country: string, state: string }`
- `residency-city` — `{ country: string, state: string, city: string }`
- `tlsn-attestation` — generic, for arbitrary domain proofs; `{ domain: string, claim: string, ... }`

We never store the underlying PII used to derive these (no birthdates, no street addresses). For age, the user proves once and we record `Eligibility` rows for all higher thresholds at fuzzed future dates (fuzz ± 30 days by default).

## Plugin architecture

A plugin issues one or more badge types. It owns its wizard flow and verification logic. Plugins live in `apps/minister/src/plugins/<id>/` and are registered via `apps/minister/src/plugins/registry.ts`. No dynamic loading.

Plugin interface (`@minister/plugin-sdk`):

```ts
export interface PluginManifest {
  id: string;
  name: string;
  description: string;
  badgeTypes: string[];
  requiresExtension: boolean;
  iconKey?: string;
}

export type WizardStepKind = "form" | "redirect" | "extension-action" | "magic-link" | "info";

// Discriminated union on `kind`: switch(step.kind) narrows payload to
// the exact per-kind type. No `as` casts at the call sites.
export type WizardStep =
  | { id: string; kind: "form"; payload: FormStepPayload }
  | { id: string; kind: "redirect"; payload: RedirectStepPayload }
  | { id: string; kind: "extension-action"; payload: ExtensionActionStepPayload }
  | { id: string; kind: "magic-link"; payload: MagicLinkStepPayload }
  | { id: string; kind: "info"; payload: InfoStepPayload };

export interface WizardState {
  pluginId: string;
  userId: string;
  currentStep: WizardStep;
  data: Record<string, unknown>; // accumulated step data, server-side only
}

export interface IssuedBadge {
  type: string;
  attributes: Record<string, unknown>; // denormalized display, lands on Badge.attributes
  claims: Record<string, unknown>; // goes into VC credentialSubject; must pass the badge type's Zod schema
  expiresAt?: Date;
  eligibilities?: Array<{ badgeType: string; eligibleAt: Date; fuzzDays: number }>;
}

export interface PluginContext {
  userId: string;
  origin: string; // for building callback URLs (magic-link, OAuth, etc.)
  audit: { log(action: string, metadata: Record<string, unknown>): Promise<void> };
  sendMail(msg: { to: string; subject: string; text: string; html?: string }): Promise<void>;
}

export interface Plugin {
  manifest: PluginManifest;
  startWizard(ctx: PluginContext): Promise<WizardState>;
  handleStep(
    state: WizardState,
    input: unknown,
    ctx: PluginContext,
  ): Promise<
    | { kind: "continue"; state: WizardState }
    | { kind: "complete"; badges: IssuedBadge[] }
    | { kind: "error"; message: string }
  >;
}
```

**Wizard runtime** (`apps/minister/src/server/wizard.ts`):

- `startWizard(pluginId, userId, origin)` creates a `WizardSession` row and calls `plugin.startWizard`.
- `submitStep(sessionId, userId, origin, input)` calls `plugin.handleStep`. On `continue` with a `magic-link` step, lifts the step's `expectedToken` to `WizardSession.pendingToken` (indexed column) so the verify route can resolve the session by token without a JSON-column query.
- `resumeViaPendingToken({ token, userId, origin, input })` is the generic round-trip callback path — magic-link clicks, OAuth `state` callbacks, and extension submissions all resolve their wizard session through it. Enforces that the token belongs to the _currently signed-in user_ (so a forwarded email can't grant a badge to a different account).
- `issueBadgesAndComplete` validates the plugin's claims against the badge type's Zod schema, mints the JWT-VC (`jti = badge.id`, `exp = 1y`), inserts `Badge` with the signed VC, marks the wizard completed, audit-logs.

**Wizard UI** is built-in (`apps/minister/src/components/wizard-client.tsx`). It dispatches on `step.kind` to a per-kind renderer (form, magic-link, info, …). Most plugins write zero React — they define their step payloads and the runtime handles rendering.

**Current plugins:**

- `email-domain` — collect email → magic-link verify → issue `email-domain` badge. The user's email itself is _not_ stored; only the domain is.
- `github` — OAuth `redirect` step → /badges/new/github/callback → `oauth-account` badge with `{ provider: "github", accountId, handle }`. Requires `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.
- `invite-code` — form step → atomic redemption against admin-minted `InviteCode` rows → `invite-code` badge with `{ label }`. Invalid/revoked/expired/exhausted all return one uniform error so the form can't be used as a code oracle.
- `tlsn-attestation` — generic TLSNotary plugin. Issues an `extension-action` step, the browser extension produces a TLSNotary presentation and POSTs it to `/api/tlsn/submit`, Minister calls the `tlsn-verifier` sidecar to check it, then issues a `tlsn-attestation` badge. The extension's prover is not yet integrated — see Stage 6 status.

## OIDC provider (Stage 3+)

### Client registration

Relying parties are managed in the admin UI at `/admin/oidc-clients`: register (confidential with one-time-displayed secret, or public/PKCE-only), edit name/redirect URIs/allowed scopes, rotate secret, delete (revokes outstanding tokens in the same transaction). Validation lives in `src/lib/oidc-client-admin.ts` — redirect URIs are absolute, fragment-free, https-only except localhost. `scripts/seed-client.ts` remains only as the docker-compose bootstrap for the demo client; it is not the management path.

### Endpoints

- `GET  /.well-known/openid-configuration` — discovery
- `GET  /.well-known/jwks.json` — public signing keys ✅ live
- `GET  /.well-known/did.json` — DID document ✅ live
- `GET  /oidc/authorize` — start auth code flow; renders consent screen
- `POST /oidc/authorize` — consent submission
- `POST /oidc/token` — exchange code for ID + access token
- `GET  /oidc/userinfo` — return claims for the access token

### Scopes

- `openid` — required
- `profile` — basic display name + avatar
- `badge:<type>` — request a specific badge type, e.g. `badge:age-over-21`, `badge:oauth-account`

### Consent screen

For each `badge:<type>` scope the RP requests, the screen shows:

- The badge type and its human description
- The badges of that type the user holds (could be multiple — let them pick which to disclose, or decline)
- A toggle per badge

Declining a badge does not abort the flow; the RP receives whatever the user did approve.

### ID token

```json
{
  "iss": "https://ministry.id",
  "sub": "<pairwise pseudonymous id>",
  "aud": "<client_id>",
  "iat": ...,
  "exp": ...,
  "nonce": "...",
  "minister_badges": ["<vc jwt>", "<vc jwt>", ...]
}
```

Subject: `sub` is a **pairwise pseudonymous identifier**, computed as `base64url(HMAC-SHA256(OIDC_PAIRWISE_SECRET, userId || clientId))`. Different RPs see different `sub` values for the same user, preventing cross-RP correlation.

### Required security

- PKCE mandatory, `S256` only
- `state` and `nonce` required on `/authorize`
- Authorization codes single-use, 60-second TTL
- Redirect URI exact match
- Client secrets hashed at rest (Argon2id)
- Rate limiting ✅ — in-memory sliding window (`src/lib/rate-limit.ts`), per-IP, on `/oidc/token`, `/oidc/userinfo`, `/oidc/authorize`, `/api/auth/signin/*` (magic-link sends, enforced in middleware), `/api/tlsn/submit`, and `/share/[token]` views. Process-local; the interface survives a Redis swap if Minister ever scales horizontally. The per-IP key is resolved by `clientIpFrom`: a trusted header (`MINISTER_CLIENT_IP_HEADER`, default `cf-connecting-ip`), else a generic right-counted XFF (`MINISTER_TRUSTED_PROXY_HOPS`, default 0 = XFF untrusted), else one fail-safe bucket. **Deployment requirement:** trusting `CF-Connecting-IP` is only spoof-proof if the origin cannot be reached except through Cloudflare — use Cloudflare Tunnel, or restrict the origin to Cloudflare IP ranges / Authenticated Origin Pulls. A directly reachable origin lets a client forge the header and bypass every limiter.
- No implicit flow, no resource owner password flow

## TLSNotary integration (Stage 6+)

When we get to it:

- Extension performs the proof, talking to `ws-proxy` to reach the target server and `notary-server` for the co-signature.
- Extension POSTs the finalized presentation to `POST /api/tlsn/submit` with `{ sessionToken, presentation }` (the `sessionToken` resolves the wizard session via `resumeViaPendingToken`; the signed-in cookie identifies the user).
- Minister calls the `tlsn-verifier` Rust HTTP sidecar with the presentation and the expected domain; gets back a verified transcript.
- The plugin extracts the relevant facts (e.g., HTML from id.me's account page) and produces `IssuedBadge[]`.

Why a separate Rust sidecar over WASM in Node: simpler operationally, pins one tlsn version, easier to keep up with breaking changes upstream. Revisit if it becomes annoying.

## Security model (prototype level — not production hardened)

- All badges private by default. The public profile (`/u/[userId]`) returns only badges with `isPublic = true`.
- VC JWTs leave Minister only via (a) an ID token to an RP the user consented to (Stage 3+), (b) a share link the user generated (Stage 7+), (c) user-initiated export.
- Share links: bearer token in URL; `requiresAccount` and `expiresAt` enforced server-side; revocable. Default 7-day expiry.
- Audit-log every badge issuance, share link creation, OIDC consent decision, session revocation, signing-key access.
- The Minister signing key is the trust anchor for all native VCs. Dev: ephemeral, written to `apps/minister/dev-keys/issuer.jwk` (gitignored). Prod: KMS-backed (out of scope for now).
- Sessions: 24h sliding JWT + per-user `sessionGeneration` revocation. Two-layer enforcement (Edge middleware for signature, server-side `getCurrentSession` for revocation). See "Authentication and session model" above.
- Do **not** log raw VC JWTs, plugin step `data` payloads, magic-link tokens, or PKCE verifiers.
- No PII storage policy — see the badge type docs above. If a plugin would need to store DOB or street address to function, the plugin is wrong; rework it.

## Conventions

- Zod for all runtime validation at boundaries (server-action inputs, plugin step inputs, OIDC request params, env vars).
- Server actions for app-internal mutations. Raw Next.js route handlers for OIDC endpoints (Stage 3+, need full header/status/caching control).
- Use `getCurrentSession()` / `requireSession()` (from `src/lib/session.ts`), not raw `auth()`, anywhere that gates user-specific content.
- The RSC server→client boundary is a JSON-only serializer — class instances (e.g. Zod schemas) don't cross. When a server component renders a client component, build a plain-object view type at the seam (`BadgeMetaView` is an example). TypeScript won't catch this; it surfaces only at runtime.
- Tests: Vitest for unit tests (co-located `*.test.ts` next to source; `pnpm test` at the repo root) and Playwright for end-to-end (`pnpm --filter @minister/app test:e2e`). The e2e suite boots its own dev server on :3901 against a dedicated `minister_e2e` database on the compose postgres (which must be running) and reads magic links from a mail-capture file (`MINISTER_MAIL_CAPTURE_FILE`, wired automatically). Specs live in `apps/minister/e2e/`; two sessions (user, admin) are minted once in `auth.setup.ts` and reused via storage state.
- ESLint + Prettier with project defaults.
- Conventional commits, authored under the repo's configured git identity. No tool/assistant attribution anywhere in commits, code, or comments.
- No `any`. No `@ts-ignore` / `@ts-expect-error` without an inline justification comment.
- Don't add a dependency without a one-line reason in the commit message.
- Comments explain _why_, not _what_. The code says what.

## Stage plan

- **Stage 0** ✅ — Monorepo scaffold, T3-ish stack, Prisma schema, NextAuth (Passkey + magic link), base layout, docker-compose with postgres. Magic-link delivery through `src/lib/mailer.ts` (Resend HTTP transport when `RESEND_API_KEY` + `MAIL_FROM` are set; console-log fallback in dev/test; throws in prod if unset).
- **Stage 1** ✅ — `@minister/vc` (Ed25519 issuer, JWT-VC issue/verify, did:web). `/.well-known/did.json` and `/.well-known/jwks.json` live. Profile page with badge grid, public/private toggle, drag-drop ordering. Public `/u/[userId]` view.
- **Stage 2** ✅ — Plugin interface (`@minister/plugin-sdk`), badge type registry (`@minister/shared`), wizard runtime + UI, `email-domain` plugin end-to-end.
- **Auth hardening** ✅ — JWT-strategy sessions (24h sliding, 1h refresh), Edge middleware route protection, per-user `sessionGeneration` revocation with "Sign out of all devices" button.
- **Stage 3** — OIDC provider (`/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, openid-configuration discovery), client registration, consent screen.
- **Stage 4** — Demo client Next.js app doing the full OIDC dance, gated by a specific badge.
- **Stage 5** ✅ — GitHub OAuth plugin. Validated the plugin interface against the `redirect` step kind; `oauth-account` badge end-to-end (requires real GitHub OAuth app creds for the live flow). Briefly removed in a scope trim, then restored.
- **Consolidation** ✅ — invite-code plugin + admin panel (`/admin`: users with ban/unban, invite-code minting/revocation, audit-log viewer), ported from the prior Express/tRPC Minister iteration (since deleted after the port). `User.isAdmin` / `User.isBanned` added; ban enforcement folded into the session loader.
- **Stage 6** ◐ partial — TLSNotary integration. Minister-side complete: `tlsn-attestation` plugin, `/api/tlsn/submit` endpoint, `extension-action` step renderer, `tlsn-verifier` Rust sidecar (with `passthrough` mode for dev), `notary-server` running the pinned official binary, browser extension skeleton at `apps/extension/`. **Not yet wired:** `tlsn-js` prover inside the extension, `ws-proxy` real implementation, `tlsn-verifier` crate integration in the sidecar's `verify_real()` (currently throws).
- **Stage 7** ✅ — Shareable proof links. `/shares` lists + creates, `/share/[token]` public view with expiry/revocation/account-gate, optional email send via the existing mailer (console-log in dev). Views recorded in `ShareLinkView`. Tokens are 32 random bytes → 43 base64url chars.
- **Stage 8** — Age / id.me plugin via TLSNotary; eligibility records with month fuzzing.
- **Stage 9** — Hardening: rate limits, audit-log review, OIDC security review, key rotation, production deploy guide. (Real email transport via Resend already landed — see `src/lib/mailer.ts` and `docs/email-setup.md`.)

## Non-goals (current)

- Production deployment, KMS integration, secrets management beyond `.env`.
- Mobile apps.
- Selective disclosure inside a credential (zero-knowledge proofs, BBS+ signatures, SD-JWT). Stage 9+ topic.
- Refresh tokens. We use sliding-window JWT TTL instead; revocation works at user granularity via `sessionGeneration`. Per-device revocation ("sign this device out, keep others") would require a per-JTI revocation table — deferred until we actually need it.
- Federation with external OIDC IdPs as a _source_ of badges. We may do this later, but via plugins, not via the OIDC client side of NextAuth.
- A standalone wallet app, or external credential export beyond raw VC JWT download.

If anything is ambiguous, ask before guessing.
