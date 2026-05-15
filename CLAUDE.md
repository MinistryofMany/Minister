# Tessera — Project Context

## What this is

Tessera is an identity platform where each user holds a profile decorated with **badges** — verifiable credentials attesting to facts about them (owns an email at a given domain, owns a particular GitHub/Google account, has beaten a given Steam game, is over 21, is a Maryland resident, etc.). Third-party web apps log users in via Tessera using OpenID Connect, and the user explicitly chooses which badges to disclose to each relying party. Tessera also supports shareable proof links — signed, time-limited artifacts the user can hand to another person out of band.

### Acronyms used throughout

- **VC** — Verifiable Credential (W3C standard)
- **DID** — Decentralized Identifier
- **OIDC** — OpenID Connect (authentication layer on top of OAuth 2.0)
- **PKCE** — Proof Key for Code Exchange (OAuth 2.0 extension defending against authorization code interception)
- **JWS / JWT** — JSON Web Signature / JSON Web Token
- **JWKS** — JSON Web Key Set
- **WASM** — WebAssembly
- **RP** — Relying Party (a third-party app that authenticates users via Tessera)
- **WS** — WebSocket

## Architecture overview

Four services run together via `docker compose`:

1. **tessera** — Next.js (App Router) app. Frontend + tRPC API + OIDC Provider endpoints. Connected to Postgres via Prisma. Holds the issuer signing key.
2. **postgres** — Application database.
3. **notary-server** — Official TLSNotary notary binary. Co-signs TLS sessions for the user's browser extension.
4. **ws-proxy** — WebSocket relay between the browser extension and the target HTTPS server. The extension cannot open raw TCP sockets, so it tunnels through this proxy to reach servers like id.me. We run our own so we control rate limits and logging.

The user runs the **Tessera browser extension** (separate package, built in Stage 6+). The extension performs the actual TLSNotary proving in their browser, talking to the WS proxy and the notary server, then submits the finalized proof to Tessera for verification and badge issuance.

## Tech stack

- TypeScript everywhere. Strict mode (`strict: true`, `noUncheckedIndexedAccess: true`).
- T3 stack: Next.js (App Router), Tailwind, Prisma, tRPC, NextAuth.
- Authentication into Tessera: Passkeys (WebAuthn) primary, email magic links fallback. No passwords in v1.
- UI: shadcn/ui on top of Tailwind. Drag-and-drop via `@dnd-kit/core`.
- VC format: W3C VC Data Model 2.0, serialized as JWT-VC. Signing algorithm Ed25519 (`alg: EdDSA`). Use the `jose` library.
- Issuer identity: `did:web:<tessera-domain>`. DID document served at `/.well-known/did.json`.
- OIDC provider: implement directly against the spec. Don't depend on an off-the-shelf "OIDC provider for Next.js" library — most are abandoned, broken, or too opinionated about user/session models.
- TLSNotary: official `tlsn` Rust notary server, and a small Rust HTTP sidecar (`services/tlsn-verifier`) using the `tlsn-verifier` crate for server-side presentation verification. The Next.js app calls it over HTTP.
- Plugin system: in-process TypeScript modules under `apps/tessera/src/plugins/<id>/`, registered through a central registry. No dynamic loading.

Package manager: pnpm. Node 20+.

## Monorepo layout

```
tessera/
├── apps/
│   ├── tessera/                 # Main app (Next.js)
│   ├── demo-client/             # Sample RP that does "Login with Tessera"
│   └── extension/               # Browser extension (Stage 6+, stubbed for now)
├── packages/
│   ├── vc/                      # VC issuance/verification, DID document, signing keys
│   ├── plugin-sdk/              # Plugin interface types and helpers
│   └── shared/                  # Shared types (badge types, scope names)
├── services/
│   ├── notary/                  # docker-compose service; pinned tlsn notary binary
│   ├── ws-proxy/                # docker-compose service; minimal WS relay
│   └── tlsn-verifier/           # docker-compose service; Rust HTTP service wrapping tlsn-verifier
├── docker-compose.yml
├── pnpm-workspace.yaml
└── README.md
```

## Core data model

Prisma sketch. This is the prototype shape; expect evolution.

```prisma
model User {
  id            String   @id @default(cuid())
  createdAt     DateTime @default(now())
  displayName   String?
  avatarUrl     String?
  badges        Badge[]
  eligibilities Eligibility[]
  shareLinks    ShareLink[]
  // NextAuth-managed: Account, Session, Authenticator (Passkey), etc.
}

model Badge {
  id           String   @id @default(cuid())
  userId       String
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  type         String   // e.g. "email-domain", "oauth-account", "age-over-21"
  attributes   Json     // denormalized non-sensitive attributes for query/display
  vcJwt        String   // the signed VC (JWT-VC). Authoritative artifact.
  issuer       String   // "did:web:tessera.example" for native; external DID/URL for imported
  issuedAt     DateTime
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
  id           String   @id @default(cuid())
  shareLinkId  String
  shareLink    ShareLink @relation(fields: [shareLinkId], references: [id], onDelete: Cascade)
  viewerUserId String?                      // null if account not required
  viewedAt     DateTime @default(now())
}

model OidcClient {
  id               String   @id @default(cuid())
  clientId         String   @unique
  clientSecretHash String?                  // null for public clients (PKCE-only)
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

model AuditLog {
  id        String   @id @default(cuid())
  userId    String?
  action    String
  metadata  Json
  createdAt DateTime @default(now())
}
```

Notes:
- The signed VC (`vcJwt`) is the authoritative artifact. `attributes` is for query/display only.
- We store the VC even for imported credentials; the `issuer` field tells us whether to verify against Tessera's key or an external DID.
- `Eligibility` is separate from `Badge` because the user hasn't actually been issued the future badge yet — it's a promise that on the eligible date a job will auto-issue it.

## Verifiable Credential model

Each native badge is a VC issued by Tessera. Imported badges keep their original issuer. JWT-VC payload shape:

```json
{
  "iss": "did:web:tessera.example",
  "sub": "did:web:tessera.example:users:<userId>",
  "iat": 1715000000,
  "exp": 1746536000,
  "nbf": 1715000000,
  "jti": "<badge id>",
  "vc": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential", "TesseraEmailDomainCredential"],
    "credentialSubject": {
      "id": "did:web:tessera.example:users:<userId>",
      "domain": "example.com"
    }
  }
}
```

`packages/vc` exports:
- `issueVc(type, subjectId, claims, { expiresIn? })` → `vcJwt`
- `verifyVc(vcJwt)` → typed credential or throws
- `loadIssuerKey()` — env-driven in prod, ephemeral on first boot in dev with the pubkey written to a checked-out dev file
- `getDidDocument()` — returns the DID document to be served at `/.well-known/did.json`

Badge types each have a Zod schema for the `credentialSubject` claims, defined in `packages/shared/src/badge-types.ts`.

### Initial badge types

- `email-domain` — `{ domain: string }`
- `email-exact` — `{ email: string }` (less private, opt-in)
- `oauth-account` — `{ provider: "github" | "google" | "...", accountId: string, handle?: string }`
- `age-over-N` — `{ threshold: 16 | 18 | 21 | 25 | 30 | 35 | 40 | 45 | 55 | 65 }`
- `residency-country` — `{ country: string }` (ISO 3166-1 alpha-2)
- `residency-state` — `{ country: string, state: string }`
- `residency-city` — `{ country: string, state: string, city: string }`
- `tlsn-attestation` — generic, for arbitrary domain proofs; `{ domain: string, claim: string, ... }`

We never store the underlying PII used to derive these (no birthdates, no street addresses). For age, the user proves once and we record `Eligibility` rows for all higher thresholds at fuzzed future dates (fuzz ± 30 days by default).

## Plugin architecture

A plugin issues one or more badge types. It owns its wizard flow and the verification logic.

```ts
// packages/plugin-sdk/src/index.ts

export interface PluginManifest {
  id: string;                    // stable identifier
  name: string;
  description: string;
  badgeTypes: string[];          // types this plugin can issue
  requiresExtension: boolean;    // true for TLSNotary plugins
  iconUrl?: string;
}

export type WizardStepKind =
  | "form"              // collect input from the user
  | "redirect"          // send the user to an external URL (OAuth)
  | "extension-action"  // ask the extension to perform a TLSNotary proof
  | "magic-link"        // wait for the user to click a link / enter a code
  | "info";             // display info, user clicks continue

export interface WizardStep {
  id: string;
  kind: WizardStepKind;
  payload: unknown;     // shape depends on kind; each kind has a built-in renderer
}

export interface WizardState {
  pluginId: string;
  userId: string;
  currentStep: WizardStep;
  data: Record<string, unknown>;   // accumulated step data, server-side only
}

export interface IssuedBadge {
  type: string;
  attributes: Record<string, unknown>;
  expiresAt?: Date;
  eligibilities?: Array<{
    badgeType: string;
    eligibleAt: Date;
    fuzzDays: number;
  }>;
}

export interface PluginContext {
  userId: string;
  // request-scoped helpers: prisma client, audit logger, secret config, etc.
}

export interface Plugin {
  manifest: PluginManifest;
  startWizard(ctx: PluginContext): Promise<WizardState>;
  handleStep(
    state: WizardState,
    input: unknown,
    ctx: PluginContext
  ): Promise<
    | { kind: "continue"; state: WizardState }
    | { kind: "complete"; badges: IssuedBadge[] }
    | { kind: "error"; message: string }
  >;
}
```

The registry at `apps/tessera/src/plugins/registry.ts` imports each plugin and exposes lookup by id. Wizard UI lives in `apps/tessera/src/app/badges/new/[pluginId]/` and dispatches to a built-in renderer per `WizardStep.kind` — most plugins write zero React.

## OIDC provider

### Endpoints

- `GET  /.well-known/openid-configuration` — discovery
- `GET  /.well-known/jwks.json` — public signing keys
- `GET  /.well-known/did.json` — DID document
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
  "iss": "https://tessera.example",
  "sub": "<pairwise pseudonymous id>",
  "aud": "<client_id>",
  "iat": ...,
  "exp": ...,
  "nonce": "...",
  "tessera_badges": ["<vc jwt>", "<vc jwt>", ...]
}
```

Subject: `sub` is a **pairwise pseudonymous identifier**, computed as `base64url(HMAC-SHA256(server_secret, userId || clientId))`. Different RPs see different `sub` values for the same user, preventing cross-RP correlation.

### Required security

- PKCE mandatory, `S256` only
- `state` and `nonce` required on `/authorize`
- Authorization codes single-use, 60-second TTL
- Redirect URI exact match
- Client secrets hashed at rest (Argon2id)
- Rate limiting on `/oidc/token` and `/oidc/authorize`
- No implicit flow, no resource owner password flow

## TLSNotary integration (Stage 6+, deferred)

When we get to it:
- Extension performs the proof, talking to `ws-proxy` to reach the target server and `notary-server` for the co-signature.
- Extension POSTs the finalized presentation to `POST /api/tlsn/submit` with `{ pluginId, sessionId, presentation }`.
- Tessera calls the `tlsn-verifier` Rust HTTP sidecar with the presentation and the expected domain; gets back a verified transcript.
- The plugin extracts the relevant facts (e.g., HTML from id.me's account page) and produces `IssuedBadge[]`.

Why a separate Rust sidecar over WASM in Node: simpler operationally, pins one tlsn version, easier to keep up with breaking changes upstream. Revisit if it becomes annoying.

## Security model (prototype level — not production hardened)

- All badges private by default. The public profile endpoint returns only badges with `isPublic = true`.
- VC JWTs leave Tessera only via (a) an ID token to an RP the user consented to, (b) a share link the user generated, (c) user-initiated export.
- Share links: bearer token in URL; `requiresAccount` and `expiresAt` enforced server-side; revocable. Default 7-day expiry.
- Audit-log every badge issuance, share link creation, OIDC consent decision, signing-key access.
- The Tessera signing key is the trust anchor for all native VCs. Dev: ephemeral, written to a gitignored file. Prod: KMS-backed (out of scope for now).
- Do **not** log raw VC JWTs, plugin step `data` payloads, magic link tokens, or PKCE verifiers.
- No PII storage policy — see the badge type docs above. If a plugin would need to store DOB or street address to function, the plugin is wrong; rework it.

## Conventions

- Zod for all runtime validation at boundaries (tRPC inputs, plugin step inputs, OIDC request params, env vars).
- tRPC for app-internal calls. Raw Next.js route handlers for OIDC endpoints (need full control over headers, status codes, caching).
- Tests: Vitest for unit, Playwright for end-to-end (deferred until Stage 4).
- ESLint + Prettier with project defaults.
- Conventional commits.
- No `any`. No `@ts-ignore` without an inline justification comment.
- Don't add a dependency without a one-line reason in the commit message.
- Comments explain *why*, not *what*. The code says what.

## Stage plan

- **Stage 0** — Monorepo scaffold, T3 stack, Prisma schema, NextAuth (Passkey + magic link), base layout, docker compose with postgres + mailhog. ← **this stage only for now**
- **Stage 1** — VC data model, Tessera signing key + `did:web`, profile page, public/private toggle with drag-drop ordering
- **Stage 2** — Plugin interface + registry, email-domain plugin end-to-end, badge wizard UI
- **Stage 3** — OIDC provider (authorize, token, userinfo, consent screen, JWKS, discovery), client registration
- **Stage 4** — Demo client Next.js app doing the full OIDC dance, gated by a specific badge
- **Stage 5** — GitHub OAuth plugin (validates the plugin interface against a second real case)
- **Stage 6** — TLSNotary integration: extension skeleton, ws-proxy, notary-server, tlsn-verifier sidecar
- **Stage 7** — Shareable proof links (signed artifacts, expiry, optional account gate, email send)
- **Stage 8** — Age / id.me plugin via TLSNotary; eligibility records with month fuzzing
- **Stage 9** — Hardening: rate limits, audit log review, OIDC security review, key rotation, error states

## Stage 0 — what to build now

Deliverable: a fresh monorepo running on `docker compose up` where I can:

1. Sign up with a passkey or email magic link.
2. See an empty profile page.
3. Sign out.

Concretely:

- pnpm workspace with the directory layout above.
- `apps/tessera`: Next.js App Router, Tailwind + shadcn initialized, Prisma with the schema sketched above (run the initial migration), NextAuth configured with Passkey (`@simplewebauthn/server` via the official NextAuth WebAuthn provider) and Email (Resend in prod, Mailhog in dev) providers. Basic layout shell with header and footer. Three pages: `/` (landing + sign-in), `/profile` (authenticated empty state), `/settings` (placeholder card with a sign-out button).
- `apps/demo-client`: Next.js scaffold only. No logic yet. Just runs.
- `packages/vc`, `packages/plugin-sdk`, `packages/shared`: empty package skeletons with `package.json` and a placeholder `index.ts`. No real code yet.
- `services/notary`, `services/ws-proxy`, `services/tlsn-verifier`: stub Dockerfiles (`FROM alpine`, a one-line README explaining what goes here in a later stage).
- `docker-compose.yml` with `postgres`, `mailhog`, and `tessera`. Notary, ws-proxy, and tlsn-verifier services defined but commented out for now.
- Root `README.md` with run instructions, env var documentation, and a list of what's intentionally not implemented yet.
- `.env.example` at the root and in `apps/tessera` with every var the app reads, documented.

**Stop after Stage 0 and let me review.** Do not pre-emptively scaffold Stage 1+. I want to review the foundation first.

## Non-goals (current)

- Production deployment, KMS integration, secrets management beyond `.env`.
- Mobile apps.
- Selective disclosure inside a credential (zero-knowledge proofs, BBS+ signatures, SD-JWT). Stage 9+ topic.
- Refresh tokens (use longer access token TTLs in prototype; revisit at Stage 9).
- Federation with external OIDC IdPs as a *source* of badges. We may do this later, but via plugins, not via the OIDC client side of NextAuth.
- A standalone wallet app, or external credential export beyond raw VC JWT download.

## Open questions to confirm before assuming

- Domain name (affects `did:web` and OIDC `iss`). Use `tessera.local` in dev unless told otherwise.
- Magic link delivery in dev: Mailhog (default) or printed to console.
- Pairwise `sub` server secret rotation policy — assume not rotated for prototype.

If anything else is ambiguous, ask before guessing.
