# Anti-Sybil Score - Phase 2 Implementation Brief (Badge statistics + public page)

Companion to the design spec (`2026-07-11-anti-sybil-score-and-badge-stats.md`,
§5.5/§6/§7/§9/§10) and the Phase 1 brief. Phase 1 (config, scorer, disclosure,
admin editors) is committed on `feat/anti-sybil-score`. This brief pins Phase 2.

Branch: `feat/anti-sybil-score`. Gate every change on
`pnpm --filter @minister/app typecheck` **and** `test` **and** `build`. The
Semgrep Guardian hook is disabled this session - use `Edit` normally.

Privacy is the security surface here: the public page must never leak a rare
attribute value. Auditor signs off on the allowlist + k-suppression + rounding.

---

## 0. Architecture decisions

1. **Materialized, not live.** Cross-badge `COUNT(DISTINCT userId)` per request is
   too heavy; stats live in `BadgeStat`/`CohortStat`/`BucketStat`, refreshed by a
   job. Public + admin read the materialized rows.
2. **In-process interval, not host cron** (spec §7). Registered in
   `instrumentation.ts` (Node runtime only, production-guarded, jittered start),
   taking a Postgres **advisory lock** (distinct key from the recovery-config lock)
   so a second app instance is a no-op; also skip if `computedAt` is fresh
   (< interval). Keep a `stats:recompute` script and an admin "recompute now"
   button as the escape hatch + test surface. Interval ~ hourly (env-tunable).
3. **Attribute-value allowlist is mandatory and lives in code** (spec §6) - the
   recompute materializes/publishes ONLY closed-enum keys. This also closes a
   JSON-key injection hole (cohort keys are validated against the allowlist, never
   interpolated free-form).
4. **Three privacy layers on the PUBLIC surface**: allowlist (which keys exist at
   all) + k-suppression (k=5, cells < k show "<k") + count rounding (nearest 10, or
   ~5% for large). Admin view may show exact counts. No time series published.
5. **Bucket-class sizes** (the Phase-1-deferred §4.3 consent hint) are materialized
   here (`BucketStat`) and wired into the consent screen's account-strength card as
   an anonymity hint ("you'd be in a very small group").

---

## 1. Data model (Prisma additions)

Generate migration `add_badge_stats` (compose postgres up; dev DB creds are
`minister:minister` on :5433, the committed `.env` password is stale). Commit the
migration folder. Prod applies via `boot-migrate`.

```prisma
model BadgeStat {
  id             String   @id @default(cuid())
  badgeType      String
  attributeKey   String   // "" for the type-level total; else an ALLOWLISTED key
  attributeValue String   // "" for the type-level total; else the enum value
  count          Int      // distinct-user count
  computedAt     DateTime
  @@unique([badgeType, attributeKey, attributeValue])
  @@index([badgeType])
}

model CohortStatDef {
  id              String @id @default(cuid())
  label           String
  numeratorFilter Json   // CohortFilter (see §3), allowlist-validated
  denominatorFilter Json
  createdAt       DateTime @default(now())
}

model CohortStat {
  defId       String   @id
  def         CohortStatDef @relation(fields: [defId], references: [id], onDelete: Cascade)
  numerator   Int
  denominator Int
  computedAt  DateTime
}

model BucketStat {
  bucket     Int      @id  // 0-4
  count      Int           // distinct users currently scoring this bucket
  computedAt DateTime
}

// Singleton, tracks the last full recompute for freshness + "as of" display.
model StatsRun {
  id         String   @id @default("singleton")
  computedAt DateTime
  durationMs Int
}
```

All counts are **distinct native, unexpired** badge holders (mirror the scorer
hygiene: `issuer = getIssuer().did`, `expiresAt IS NULL OR expiresAt > now`).

---

## 2. Attribute-value allowlist (spec §6) - `src/lib/stats-allowlist.ts`

Publishable keys (closed enums only):
`provider, olderThanMonths, followersAtLeast, chain, event, threshold, kind, country`.
NEVER materialize/publish: `email, domain, fingerprint, state, city, handle`
(their existence leaks an individual/org). residency-country is OK (ISO enum);
residency-state / residency-city are NOT (only their type-level total may show).
Export the allowlist and a `isAllowlistedKey(type, key)` used by BOTH the
recompute (which keys to materialize) and cohort-def validation (reject a def that
references a non-allowlisted key - fail closed, and never string-interpolate a key
into SQL).

---

## 3. Cohort filter format (spec §10) - `src/lib/cohort-filter.ts`

A cohort side = a Zod-validated conjunction of 1-3 badge filters:
`{ type: string, where?: Record<allowlistedKey, string|number|boolean>, whereGte?: Record<allowlistedKey, number> }`.
Validation: every `type` in the registry; every key in `where`/`whereGte`
allowlisted for that type; ≤3 clauses. Distinct-user count via `EXISTS`
subqueries over unexpired native badges (see design spec §10 for the reference
SQL). `olderThanMonths`/`followersAtLeast` stored as the highest satisfied tier,
so `whereGte` sums the tiers correctly. Parameterize all values; never interpolate
keys (allowlist-checked identifiers only).

Built-in seeded cohort: denominator = `oauth-account{provider=github}` holders,
numerator = `account-age{provider=github, olderThanMonths>=24}` holders ("aged
github accounts as a fraction of github accounts").

---

## 4. Recompute job (spec §7) - `src/lib/stats-recompute.ts`

`recomputeAllStats()`:

1. `BadgeStat`: per type, the type-level total (distinct holders) + per allowlisted
   `(key,value)` the distinct-holder count. Delete-and-rewrite (or upsert) in one
   transaction; stamp `computedAt`.
2. `CohortStat`: per `CohortStatDef`, numerator + denominator distinct-user counts.
3. `BucketStat`: score every user (load their native unexpired badges, run the pure
   `sybilScore`), tally per bucket 0-4. This is the heavy one - it is the scheduled
   job's cost and is acceptable because it is materialized. Batch users to bound
   memory.
4. Update `StatsRun` singleton (`computedAt`, `durationMs`).

Wrappers:

- `scripts/recompute-stats.ts` + `pnpm --filter @minister/app stats:recompute`.
- An admin server action `recomputeStatsNow()` (adminAction-gated) behind a
  "Recompute now" button.
- `instrumentation.ts`: register a production-guarded, jittered `setInterval`
  (env `MINISTER_STATS_INTERVAL_MS`, default ~1h) that calls `recomputeAllStats`
  under a NEW advisory lock key (not the recovery-config key) and skips if
  `StatsRun.computedAt` is fresher than the interval. Wrap in try/catch - a
  recompute failure logs, never crashes the server.

---

## 5. Admin stats view (spec §5.5) - `/admin/stats`

`requireAdmin()` page. Per type: global holder count + global % (of total users).
Expandable to the allowlisted attribute distributions from `BadgeStat`. A cohort
section: list `CohortStatDef`s with their numerator/denominator/% (EXACT counts,
operator-gated), plus a small form to add a cohort def (type + where/whereGte,
validated by the cohort-filter schema). A "Recompute now" button + "as of
<StatsRun.computedAt>". No k-suppression/rounding here (admin sees exact).

---

## 6. Public transparency page (spec §6) - `/transparency` (public, read-only)

Two sections, both static-friendly (revalidate on the stats interval):

1. **The score model**: the category table + caps, the 5 buckets + their meaning,
   the raw per-`(type,qualifier)` `sybilWeight` table (published deliberately), and
   the **per-bucket dollar-cost table** (static content from design spec §3.7:
   bucket 1 = any single proof; 2 = free-but-slow; 3 = ~$2-5 + hours/identity; 4 =
   ~$50-150/identity or multi-year pre-provisioning). Frame it as a price list, and
   state plainly it is "how expensive to farm", NOT proof of unique personhood
   (spec §2).
2. **Badge statistics**: per-type totals + allowlisted attribute distributions +
   the reviewed cohorts, each passed through **k-suppression (k=5 → "<5")** and
   **count rounding** (nearest 10; ~5% for large). Show "as of <computedAt>". No
   time series. This page reads ONLY `BadgeStat`/`CohortStat` (already
   allowlist-filtered at materialization) - defense in depth: apply the allowlist
   again at render and never render a non-allowlisted key even if one slipped into
   the table.

Add a nav link. The k-suppression + rounding helpers live in
`src/lib/stats-public.ts` (pure, unit-tested: a count of 3 → "<5"; 47 → 50; a
non-allowlisted key → dropped).

---

## 7. Consent bucket-class hint (deferred §4.3) - consent screen

Wire the account-strength card (Phase 1) to show an anonymity hint from
`BucketStat`: reuse `anonymity-hint.ts` bucketing over the count of users in the
user's bucket class, so a user about to share a rare "bucket 4" on a small instance
sees "very small group" before consenting. Read `BucketStat` in the authorize page
(cheap - 5 rows), pass a hint prop; fail soft to no-hint if unavailable. This is
the only Phase-1-deferred item folded into Phase 2.

---

## 8. Build unit decomposition

- **P2-U0 Foundation**: schema + migration; `stats-allowlist.ts`;
  `cohort-filter.ts` (Zod + EXISTS SQL); `stats-recompute.ts`; the interval in
  `instrumentation.ts`; `recompute-stats.ts` script + `stats:recompute`;
  `recomputeStatsNow()` admin action; seed the built-in github cohort. Unit tests:
  allowlist enforcement, cohort-filter validation (rejects non-allowlisted key),
  recompute idempotency, k-suppression/rounding helpers.
- **P2-U1 Admin stats view**: `/admin/stats` + cohort-def CRUD (exact counts).
- **P2-U2 Public transparency page**: `/transparency` (privacy-critical:
  allowlist + k-suppression + rounding + dollar-cost table). **Auditor sign-off.**
- **P2-U3 Consent bucket hint**: wire `BucketStat` → consent anonymity hint.

P2-U1/U2 touch disjoint files (admin vs public) and may run back-to-back after
P2-U0. Each phase: typecheck + test + `next build` green. Auditor must sign off on
the allowlist + k-suppression + rounding before the public page merges.
