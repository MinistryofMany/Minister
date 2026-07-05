# signet-e2e — local/CI Signet test stack (crypto-core Phase 3)

Stands up a REAL Signet (mTLS, VOPRF PRF/dedup surface) sealed with the FROZEN
ecosystem test master seed, so Minister's `signet` nullifier backend can be
exercised end-to-end: blind → `/prf/evaluate` → DLEQ verify → finalize →
`/dedup/register` → `/prf/disclose`, byte-asserted against the frozen vectors
committed to both repos (`apps/minister/src/lib/nullifier/prf-vectors.json` ≡
`Signet/interop/prf-vectors.json`).

Everything generated here is a THROWAWAY TEST FIXTURE: the master seed is a
public vector, the KEK is random-per-run but written to disk, and the PKI is a
dev CA. Never point any of it at production.

## Layout

- `fixture/` — Rust tool (path-depends on the sibling `Signet` checkout, so
  the sealed keystore uses Signet's own code). Emits into `.stack/`:
  mTLS PKI (server SANs `signet`/`localhost`/`127.0.0.1`; client CN
  `minister`, matching `SIGNET_PRF_CLIENT_IDS`), `db/signet.db` (frozen seed
  sealed under a fresh KEK), `signet.env` (Signet side), `minister.env`
  (Minister side: `MINISTER_NULLIFIER_BACKEND=signet` + `MINISTER_SIGNET_*`),
  and `pk` (the derived pkS — asserted equal to the frozen vector).
- `up.sh` / `down.sh` — build + generate + boot Signet on `127.0.0.1:9443`
  (cargo binary, no docker needed), wait for readiness.
- The docker path: `infra/docker-compose.yml` (ministry-dev) has an opt-in
  `signet` service (profile `signet`) that mounts `.stack/`.

## Use

```sh
# from the Minister repo root; needs Rust 1.87+ and ../Signet checked out
signet-e2e/up.sh

# Minister side env
set -a; source signet-e2e/.stack/minister.env; set +a

# live fixture suite (also what the CI signet-interop job runs); needs a
# Postgres DATABASE_URL with the schema pushed (the release-race regression
# writes real rows to exercise the real pg advisory lock)
MINISTER_SIGNET_FIXTURE=1 pnpm --filter @minister/app exec \
  vitest run src/lib/nullifier/signet-live.fixture.test.ts

# or run the playwright e2e stack against the signet backend (the dev server
# inherits the sourced MINISTER_* env; specs behave identically today — no
# anchor-emitting wizard flow is e2e-drivable without live GitHub OAuth creds)
pnpm --filter @minister/app test:e2e

signet-e2e/down.sh
```

CI: the `signet-interop` job in `.github/workflows/ci.yml` runs the same
`up.sh` + live suite on every push/PR, after a byte-equality drift check of
the frozen vectors across the two repos. It needs the `SIGNET_READ_TOKEN`
secret (read access to the private Signet repo).
