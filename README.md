# Minister

Identity platform where each user holds a profile decorated with **badges** — verifiable credentials attesting to facts about them. Third-party apps log users in via Minister using OpenID Connect, and the user explicitly chooses which badges to disclose to each relying party.

See [CLAUDE.md](./CLAUDE.md) for the full design.

## Status

**Stage 0 — foundation.** A user can sign up, see an empty profile, and sign out. Everything else listed in CLAUDE.md is intentionally not yet implemented — see _What's not implemented yet_ below.

## Requirements

- Docker Desktop (or Docker Engine + Compose v2)
- Node 20+ and pnpm 9+ — only if you want to run apps directly on the host instead of via compose

## Quick start

```bash
# 1. Configure secrets
cp .env.example .env
# Generate values for AUTH_SECRET and OIDC_PAIRWISE_SECRET:
#   openssl rand -base64 32

# 2. Boot the stack
docker compose up --build

# 3. Open http://localhost:3000
```

On first boot, the `minister` container runs `prisma db push` to sync the schema to the empty postgres database, then starts Next.js in dev mode.

### Signing in (dev)

You have two options on the home page:

1. **Passkey** — uses WebAuthn. Works on `http://localhost:3000` because browsers special-case localhost for WebAuthn; will _not_ work over plain `http://minister.local`.
2. **Email magic link** — type any email address. The link is printed to the `minister` container's stdout (look for `[minister:auth] Magic link for ...`). Click it to complete sign-in. No real email is sent in Stage 0.

After signing in once via magic link, you can attach a passkey from `/profile` ("Add a passkey"), then sign in with that passkey next time.

## Repo layout

```
minister/
├── apps/
│   ├── minister/          # main app (Next.js, Prisma, NextAuth)
│   └── demo-client/      # sample relying party (placeholder until Stage 4)
├── packages/
│   ├── vc/               # VC issuance/verification (empty until Stage 1)
│   ├── plugin-sdk/       # plugin interface types (empty until Stage 2)
│   └── shared/           # shared types (empty until Stage 1)
├── services/
│   ├── notary/           # TLSNotary notary server (stub until Stage 6)
│   ├── ws-proxy/         # WebSocket relay (stub until Stage 6)
│   └── tlsn-verifier/    # Rust sidecar (stub until Stage 6)
├── docker-compose.yml
├── pnpm-workspace.yaml
└── README.md
```

## Local development (host, not compose)

If you want hot reload and a faster iteration loop, run the database in compose but Next.js on the host:

```bash
docker compose up -d postgres
cd apps/minister
cp .env.example .env.local
# edit .env.local — at minimum set AUTH_SECRET and switch
# DATABASE_URL host to localhost
pnpm install
pnpm prisma db push
pnpm dev
```

## Environment variables

Documented in [`.env.example`](./.env.example) (compose-level) and [`apps/minister/.env.example`](./apps/minister/.env.example) (app-level). Required:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | postgres connection string |
| `AUTH_SECRET` | Auth.js session/JWT signing secret. Must be ≥32 chars. |
| `AUTH_URL` | URL the browser sees the app on. WebAuthn requires exact origin match. |
| `AUTH_TRUST_HOST` | `"true"` when running behind a reverse proxy or in docker-compose. |
| `MINISTER_ISSUER_DOMAIN` | Domain for did:web and OIDC `iss`. Default `minister.local`. |
| `OIDC_PAIRWISE_SECRET` | Secret for deriving pairwise OIDC subs. Optional until Stage 3. |

## What's _not_ implemented yet

Stage 0 is foundation only. The following are documented in CLAUDE.md and arrive in later stages:

- VC issuance, signing keys, DID document at `/.well-known/did.json` — Stage 1
- Profile customization, badge display, public/private toggle, drag-drop ordering — Stage 1
- Plugin system, badge wizard UI, email-domain plugin — Stage 2
- OIDC provider (`/authorize`, `/token`, `/userinfo`, JWKS, consent screen) — Stage 3
- Demo client actually doing the OIDC dance — Stage 4
- GitHub OAuth plugin — Stage 5
- TLSNotary integration (extension, notary, ws-proxy, tlsn-verifier) — Stage 6
- Shareable proof links — Stage 7
- Age / id.me plugin, eligibility records — Stage 8
- Hardening (rate limits, key rotation, OIDC security review) — Stage 9

Per CLAUDE.md, this is a prototype. Not production hardened.

## License

Copyright (c) 2026 AtHeartEngineering LLC. Part of the **Ministry of Many** project, authored by AtHeartEngineer.

Ministry is licensed under the **GNU Affero General Public License v3.0** (`AGPL-3.0-only`) - see [LICENSE](./LICENSE). Running a modified version as a network service requires publishing your source under the same license. The reusable SDK packages (`@minister/plugin-sdk`, `@minister/vc`, `@minister/shared`) live in their own repositories under a permissive `MIT OR Apache-2.0` dual license. "Ministry" and "Ministry of Many" are trademarks of AtHeartEngineering LLC; a fork must rename.
