# Sybil-dedup nullifier (crypto-core Phase 1 — interim backend)

Credential-anchored, one-credential-one-account gating. Cross-ref:
`ecosystem-planner/adr/minister-crypto-core.md` (§ Resolved) and
`ecosystem-planner/adr/signet-crypto-core-build-plan.md` §2.1, §2.2, §2.3, §2.6, §3
Phase 1. This directory is the **frozen `NullifierService` interface** the Signet
backend implements UNCHANGED in Phase 3.

## What it does

At issuance, a scarce credential (today: the github numeric account id) is
nullified into an opaque `Badge.nullifierRef` and the raw anchor is **discarded**.
The ledger's `UNIQUE(value)` refuses a second account proving the same credential
(`taken`). At disclosure (Phase 4), a per-RP `mnv1:` nullifier is derived from the
stored value + clientId, so an RP can gate/ban on "same credential across accounts"
without learning the credential, and different RPs get unlinkable tags.

## Two-stage construction (interim)

- `k_int = HKDF-SHA256(OIDC_PAIRWISE_SECRET, salt="", info="minister/v1/nullifier-interim", L=32)`
- dedup value = `HMAC(k_int, LP("dedup") || LP(anchor) || LP(badgeType))` — raw bytes,
  `UNIQUE`-indexed (`NullifierEntry.value`).
- disclosed = `"mnv1:" + base64url(HMAC(k_int, LP("rp") || LP(value) || LP(clientId)))`.
- `LP(x)` = 2-byte big-endian byte length followed by the bytes. **Never bare
  concatenation** — an attacker-influenceable, variable-length anchor could otherwise
  collide two distinct tuples into one PRF input.

## ⚠ Interim-window deviation (Phases 1–3, `users == 0` guarded)

The ADR moved the real dedup ledger into **Signet** precisely so a Minister-DB exfil
is not a cross-account linkage + email-dictionary oracle. This interim backend
deliberately deviates: `NullifierEntry.value` (deterministic HMAC outputs,
`UNIQUE`-indexed) lives in **Minister's Postgres**, with the deriving key
(`k_int`, from `OIDC_PAIRWISE_SECRET`) **co-resident** in Minister's env/SSM. That is
exactly the exfil/dictionary surface the ADR avoids — accepted **only** because prod
has zero users, the window is deliberately minimized, and every interim gate asserts
`users == 0`. At the Phase 3 flip the ledger moves into Signet (VOPRF), these values
are **replaced**, and every interim badge is reissued (free at zero users). The
`NullifierEntry` table is DROPPED in Phase 8 with a grep-clean check.

The interim golden vectors (`interim.test.ts`) are therefore **NON-forever** — unlike
the pairwise golden vectors, a value change here is not a permanent wire break.

### `users == 0` deploy gate

Every Phase 1–5 deploy asserts the window's precondition with
`pnpm --filter @minister/app users:count` (`scripts/count-users.ts`): it counts real
user rows — **excluding** operator accounts (`isAdmin`), tombstoned merge donors
(`mergedIntoUserId != null`), and an explicit email allowlist
(`--exclude-email <addr>` / `COUNT_USERS_EXCLUDE_EMAILS`) — and **exits non-zero if any
remain**, so a pipeline gates on it:

```sh
pnpm --filter @minister/app users:count && ./deploy.sh
```

A non-zero exit means real users have arrived: STOP and re-plan the interim window
(build plan risk #2), do not deploy an interim-backend build over live user data.

## ⚠ Two nullifier primitives — non-interchangeable (M3)

|                | `@ministryofmany/nullifier`  | Minister gating nullifier (this dir)             |
| -------------- | ---------------------------- | ------------------------------------------------ |
| Math           | Poseidon/BN254               | HMAC (interim) / RFC 9497 VOPRF + HMAC (Phase 3) |
| Anchor         | the per-RP `sub` (account)   | the credential (github id, email)                |
| Circuit-usable | YES (SNARK-provable)         | NO (plaintext gating only)                       |
| Catches        | same-account-across-contexts | same-credential-across-accounts                  |

The disclosed value is `mnv1:`-prefixed and typed as the branded
`MinisterGatingNullifier`, so it cannot flow where a BN254 field string is expected.
No code path converts between them. A future circuit-usable credential nullifier must
be a NEW Poseidon construction, not a bridge.

## Transaction discipline (§2.6)

Every `NullifierService` method does network I/O in the Signet backend. **Never call
one inside an open `prisma.$transaction`.** Collect refs/handles inside the tx,
commit, then run register/disclose/release/reassign post-commit with idempotent retry
(`runPostCommit`). The interim backend follows the same rule so the Phase 3 swap
changes no call-site structure.

## Migration runbook (issue #47 — migrations are manual in prod)

Phase 1 adds `Badge.nullifierRef` (nullable), `User.dedupHandle` (nullable unique),
and the `NullifierEntry` table. Prod applies schema via `prisma db push` at container
boot (`scripts/boot-migrate.ts`), so these land on the next deploy's boot push. The
change is additive and nullable, so the down path is a plain revert (no data loss):
an old-schema SDK rejects new-shape badges fail-closed (login unaffected) during any
skew window. **Retroactivity check before/at deploy:** scan stored `oauth-account`
VCs for `accountId` (`reMintVc` spreads stored claims, so a pre-fix VC keeps
disclosing it) and delete-and-reissue any found — zero users expected, but assert.
