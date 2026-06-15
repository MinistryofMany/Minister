# Minister

[![CI](https://github.com/MinistryofMany/Minister/actions/workflows/ci.yml/badge.svg)](https://github.com/MinistryofMany/Minister/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Postgres](https://img.shields.io/badge/Postgres-16-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org)

**Minister** is an identity platform. Each person holds a profile decorated with **badges** — verifiable credentials attesting to facts about them (owns an email at a given domain, controls a GitHub or Google account, is over 21, is a state resident, and more). Third-party apps sign users in via **OpenID Connect**, and the user explicitly chooses which badges to disclose to each relying party. Minister also issues **shareable proof links** — signed, time-limited artifacts you can hand to someone out of band.

Part of the [Ministry of Many](https://github.com/MinistryofMany) project. Home: [ministry.id](https://ministry.id).

See [CLAUDE.md](./CLAUDE.md) for the full design and data model.

## Status

A working prototype — not yet production-hardened, but the core platform is live end to end:

**Working today**

- **Sign-in** — passkeys (WebAuthn) and email magic links; JWT-strategy sessions with sliding TTL, per-user revocation, and admin ban enforcement.
- **Badges & credentials** — W3C Verifiable Credentials as JWT-VC (Ed25519 / `EdDSA`), issued under a `did:web` identity. DID document and JWKS served at `/.well-known/did.json` and `/.well-known/jwks.json`.
- **Profile** — badge grid with per-badge public/private toggle and drag-and-drop ordering; public `/u/[id]` view.
- **Plugins** — a typed plugin + wizard system. Live plugins: `email-domain`, `github` (OAuth), `invite-code`, and `tlsn-attestation`.
- **OIDC provider** — discovery, `/oidc/authorize` + consent screen, `/oidc/token`, `/oidc/userinfo`; PKCE-mandatory (S256), pairwise pseudonymous `sub`, client registration in the admin UI. (FreedInk signs in against this.)
- **Admin** — `/admin`: user management (ban/unban, promote/demote), invite-code minting, OIDC client management, and an audit-log viewer.
- **Proof links** — create/list at `/shares`, public view at `/share/[token]` with expiry, revocation, and an optional account gate.
- **Hardening** — per-IP rate limiting on auth/OIDC/share endpoints and an append-only audit log.

**In progress / planned**

- **TLSNotary** (◐) — Minister-side complete (the `tlsn-attestation` plugin, `/api/tlsn/submit`, the Rust `tlsn-verifier` sidecar, and the notary server). The in-browser prover (extension + `ws-proxy`) is not yet wired.
- **Age / id.me via TLSNotary** with fuzzed eligibility records.
- **Production**: KMS-backed signing keys, key rotation, and a deploy guide.

## Architecture

Four services run together via `docker compose`:

| Service         | Role                                                                                  |
| --------------- | ------------------------------------------------------------------------------------- |
| `minister`      | Next.js app — frontend, server actions, OIDC endpoints; holds the issuer signing key. |
| `postgres`      | Application database (Prisma).                                                        |
| `notary-server` | Official TLSNotary notary binary (Stage 6+).                                          |
| `tlsn-verifier` | Rust HTTP sidecar that verifies TLSNotary presentations (Stage 6+).                   |

```
Minister/
├── apps/
│   ├── minister/        # main app: Next.js · Prisma · Auth.js · OIDC provider
│   ├── demo-client/     # sample relying party (OIDC client)
│   └── extension/       # browser extension for in-browser TLSNotary proving
├── services/
│   ├── notary/          # TLSNotary notary server
│   ├── ws-proxy/        # WebSocket relay for the extension
│   └── tlsn-verifier/   # Rust sidecar verifying presentations
├── docker-compose.yml
└── pnpm-workspace.yaml
```

The reusable SDKs live in their **own repositories** (permissive `MIT OR Apache-2.0`) and are linked into this app during development via pnpm `link:`:

| Package                | Repo                                                                         | Purpose                                  |
| ---------------------- | ---------------------------------------------------------------------------- | ---------------------------------------- |
| `@minister/vc`         | [minister-vc](https://github.com/MinistryofMany/minister-vc)                 | JWT-VC issuance/verification, `did:web`. |
| `@minister/plugin-sdk` | [minister-plugin-sdk](https://github.com/MinistryofMany/minister-plugin-sdk) | Plugin interface types.                  |
| `@minister/shared`     | [minister-shared](https://github.com/MinistryofMany/minister-shared)         | Badge-type registry and schemas.         |

## Tech stack

TypeScript (strict) · Next.js 15 (App Router) · React 19 · Tailwind v4 · Prisma 6 / PostgreSQL · Auth.js v5 · `jose` (JWT-VC, EdDSA) · `did:web` · TLSNotary (Rust sidecar).

## Getting started

Minister depends on the three SDK repos as **siblings** (they're linked locally), so clone them into one folder:

```bash
mkdir ministry && cd ministry
git clone https://github.com/MinistryofMany/Minister.git
git clone https://github.com/MinistryofMany/minister-vc.git
git clone https://github.com/MinistryofMany/minister-plugin-sdk.git
git clone https://github.com/MinistryofMany/minister-shared.git
cd Minister
```

Then run on the host (Node 20+, pnpm 9+):

```bash
pnpm install
cp apps/minister/.env.example apps/minister/.env
# Generate AUTH_SECRET and OIDC_PAIRWISE_SECRET: openssl rand -base64 32
pnpm db:migrate         # sync the schema to a running postgres
pnpm dev                # http://localhost:3000
```

Or bring up the full stack with Docker:

```bash
docker compose up --build   # http://localhost:3000
```

### Signing in (dev)

- **Passkey** — works on `http://localhost:3000` (browsers special-case `localhost` for WebAuthn).
- **Email magic link** — type any address; in dev the link is printed to the app's stdout (no real email is sent unless an SMTP/Resend transport is configured).

## Development

```bash
pnpm typecheck      # tsc across the workspace
pnpm lint           # eslint
pnpm test           # unit tests (vitest)
pnpm format         # prettier --write
```

A husky + lint-staged pre-commit hook formats staged files automatically, so commits stay Prettier-clean.

> Heads up: because the SDKs are consumed via `link:`, building Minister in isolation (CI, a standalone clone, the Docker image) requires those sibling repos. Publishing the SDKs to npm and switching to versioned dependencies will remove that constraint.

## License

Copyright (c) 2026 AtHeartEngineering LLC. Part of the **Ministry of Many** project, authored by AtHeartEngineer.

Minister is licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0-only`) - see [LICENSE](./LICENSE). Running a modified version as a network service requires publishing your source under the same license. The reusable SDK packages (`@minister/plugin-sdk`, `@minister/vc`, `@minister/shared`) live in their own repositories under a permissive `MIT OR Apache-2.0` dual license. "Minister" and "Ministry of Many" are trademarks of AtHeartEngineering LLC; a fork must rename.
