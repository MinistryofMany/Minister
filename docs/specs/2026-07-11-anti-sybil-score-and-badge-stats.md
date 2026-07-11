# Anti-Sybil Quality Score, Badge Statistics, and RP View-Gating

Status: draft v2 (deep-solver reviewed; pending owner sign-off, then auditor pass per phase)
Date: 2026-07-11
Scope: Minister (core), the `@ministryofmany/*` SDK packages (mirror + verify), Deforum (first consumer), Discreetly (optional, later)

## 0. Changes from v1 (deep-solver review)

- Recovery weights are **read live per re-proof**, not snapshotted at attempt
  start (v1 claimed the opposite). Guardrail model changed to **live-read +
  asymmetric delayed-apply** (§5.4).
- Scoring rule replaced: **family-collapse + geometric decay within a category +
  a qualifying-category breadth floor** on buckets 3-4, not `min(cap, sum)`, which
  was farmable with bulk-free badges (§3.3, §3.4).
- Concrete **calibration** added: full weight seed, qualifier chains, caps, bucket
  cutoffs, worked examples, per-bucket dollar costs (§3).
- Stats keyed on raw attribute values is a **PII leak by construction**; added a
  per-type **attribute-value allowlist** and count **rounding** on top of
  k-suppression (§6).
- Disclosure bucket is **snapshotted at consent**, not recomputed at
  disclosure/userinfo time (id_token/userinfo drift + consent-integrity) (§4).
- Scheduling flipped to an **in-process interval**, not host cron (§7).
- Deforum: bucket **persisted with a staleness policy**, home-feed/directory
  **row filtering** (not just page gating), a shared **gate choke-point** covering
  content API GETs, and scope/ops plumbing (§8).
- Scorer excludes **expired and non-native-issuer** badges (§3.5).

## 1. Goal

Give every badge a **cost-to-farm weight**, reduce a user's held badges to a
coarse **anti-sybil score bucket (0-4)**, and let a relying party gate on that
bucket **without learning which badges the user holds**. Ship operator tooling to
tune it well: an admin dashboard to edit the two weight columns (sybil +
recovery), categories, caps, and bucket cutoffs, plus badge statistics (global +
conditional cohorts) so tuning is informed. Publish a public transparency page.
Recompute stats on a schedule.

First consumer: Deforum requires a Minister login at or above a configurable
bucket to view gated surfaces, tunable per sub-forum and instance-wide, to deter
scraping while staying welcoming to real newcomers.

The score's defense is **cost, not secrecy**. We publish the recipe as a price
list. It is never a claim of unique personhood (§2).

## 2. Non-goals

- Proof of unique personhood. The score is "how expensive is this identity to
  farm", never "one distinct human". Copy and docs say so. Per-badge dedup
  nullifiers remain the strong Sybil control; this is a coarse, tunable overlay.
- Changing the per-badge disclosure model. Individual badge VCs disclose exactly
  as today; the bucket is an additional, opt-in, aggregate claim.
- A cross-RP reputation. The bucket is per-RP under the pairwise `sub`.
- Discreetly integration is documented but deferred past v1.

## 3. The score model

### 3.1 Two weight columns

Each `(badgeType, qualifier)` row carries two operator-editable integer weights
for two threat models that must not be conflated:

- **`sybilWeight`** (new) - cost to farm this credential as a fake human. Feeds
  only the RP-facing score.
- **`recoveryWeight`** (migrated) - contribution to the account-recovery
  threshold. Today hardcoded in `apps/minister/src/lib/assurance.ts`
  (`BADGE_ASSURANCE_WEIGHT`, `RECOVERY_WEIGHT_BY_TYPE`, the oauth-provenance
  table, `RECOVERY_THRESHOLD`). This spec moves them into the same DB config.
  **Behavior identical to today on first migration**; a parity test asserts it
  (§5.4).

The inert `sybilResistance` label on `BadgeTypeMeta` is not the score (it means
"is a dedup nullifier wired"). It stays informational; `sybilWeight` is
purpose-built.

### 3.2 Qualifier chain (not a flat per-type weight)

Farm cost varies within a type: `account-age` at 12 vs 60 months, `wallet-age`,
`social-following` buckets differ hugely. Each type defines a pure **qualifier
candidate chain** extracted from `Badge.attributes`, most-specific first, falling
back to `*`. The resolver walks the chain and uses the first row that exists:

- `oauth-account`: `[provider, "*"]`
- `account-age`: `[provider:months, provider, "*"]` (e.g. `github:24`)
- `wallet-age`: `[months, "*"]`
- `social-following`: `[provider:bucket, provider, "*"]`
- all others: `["*"]`

No combinatorial explosion - only rows an operator creates exist; the editor
groups by type and shows the resolved fallback.

### 3.3 Categories and caps

Each type belongs to an operator-editable **category** with a **cap**:

| Category          | Cap | Types                                        |
| ----------------- | --- | -------------------------------------------- |
| `email`           | 10  | email-domain, email-exact                    |
| `social-oauth`    | 30  | oauth-account, account-age, social-following |
| `wallet`          | 30  | wallet-control, wallet-age, onchain-event    |
| `human-attribute` | 40  | age-over-_, residency-_                      |
| `domain`          | 20  | domain-control                               |
| `attestation`     | 50  | tlsn-attestation, public-key                 |
| `invite`          | 15  | invite-code                                  |

### 3.4 Scoring rule (replaces min(cap, sum))

Per category:

1. **Family-collapse** fully-correlated badges to their max member: all
   `age-over-*` are one proof (Eligibility auto-issues the ladder);
   `residency-city` implies state implies country. Collapse each family to one
   contribution before summing.
2. **Geometric decay** on the remaining weights sorted descending:
   `c = Σ floor(w_i / 2^i)`, then `c = min(c, categoryCap)`. So a second same-kind
   badge is worth half, a third a quarter - bulk-free stacking dies.
3. A category **qualifies** if `c >= 8`.

`raw = Σ c`. Bucket (operator-editable seed cutoffs):

- **1**: raw >= 5
- **2**: raw >= 15
- **3**: raw >= 28 and >= 2 qualifying categories
- **4**: raw >= 60 and >= 3 qualifying categories

A user meeting a raw cutoff but failing the breadth floor lands at the highest
bucket they fully satisfy.

### 3.5 Scorer input hygiene

`sybilScore(heldBadges, config) -> { raw, bucket }` is a pure module
(`apps/minister/src/lib/sybil-score.ts`), never throws, computed over badges the
user **holds**. It MUST exclude:

- **expired** badges (`Badge.expiresAt < now`), and
- **non-native-issuer** badges (scope to Minister's own DID, mirroring
  `oidc-claims.ts` issuer scoping) - an imported VC must never buy bucket.

An unknown type contributes 0 and is logged for the admin to categorize. A
**boot-time check** asserts every registry type has a `BadgeWeight` row (loud on
seed drift, mirroring the KMS boot-verify pattern).

### 3.6 Seed weights (auditor-tunable via the dashboard afterward)

| Type / qualifier                                                            | sybilWeight                |
| --------------------------------------------------------------------------- | -------------------------- |
| email-domain `*`, email-exact `*`                                           | 5, 5                       |
| oauth-account github / google / discord / steam / reddit / hackernews / `*` | 8 / 12 / 4 / 5 / 4 / 4 / 4 |
| account-age github:12/:24/:36/:60                                           | 10 / 15 / 18 / 22          |
| account-age reddit\|hackernews :12/:24/:36/:60                              | 6 / 10 / 12 / 15           |
| account-age `*`                                                             | 6                          |
| social-following github:10/:50/:100/:500/:1000                              | 4 / 6 / 8 / 10 / 12        |
| social-following `*`                                                        | 4                          |
| wallet-control `*`                                                          | 2                          |
| wallet-age 12/24/36/60                                                      | 6 / 10 / 13 / 16           |
| onchain-event eth2-genesis-depositor / `*`                                  | 30 / 10                    |
| age-over-* (all)                                                            | 25                         |
| residency-country / -state / -city                                          | 10 / 14 / 16               |
| domain-control `*`                                                          | 10                         |
| tlsn-attestation `*`                                                        | 10                         |
| public-key `*`                                                              | 1                          |
| invite-code `*`                                                             | 12                         |

### 3.7 Worked examples

- Fresh account: raw 0 -> **bucket 0**.
- Newcomer, one verified email: 5 -> **bucket 1** (clears a default gate of 1; a
  zero-proof scraper does not). Invited newcomer + email: 12+5=17 -> **bucket 2**.
- Dev (github oauth + account-age>=24 + email): social `[15,8]` -> 15+4=19; email
  5; raw 24 -> **bucket 2**. Add a second real root (domain-control 10 or
  wallet-age 24mo) -> raw >= 34, 2 qualifying -> **bucket 3**.
- Free farmer (5 oauth, 2 email, 30 wallets, 20 keypairs): 11+7+3+1 = 22, 1
  qualifying -> **bucket 2 ceiling**. Cannot reach 3 without spending.
- Spending farmer: + one $2 domain -> raw 32, 2 qualifying -> bucket 3 at ~$2-5 +
  hours/identity. Bucket 4 needs >=3 qualifying categories of aged/scarce assets
  (~$50-150/identity or multi-year pre-provisioning).

Per-bucket dollar-cost estimates are published on the transparency page (§6):
the recipe reads as a price list, which is the honest framing.

### 3.8 Anti-farming residual (stated openly)

Bucket 2 is reachable free-but-slow; bucket 3 for a few dollars per identity.
This is consistent with the non-goal and documented publicly. `Badge` has no
per-user-per-type uniqueness (`schema.prisma` index is not unique; multi-hold is
real), which is exactly why decay + breadth floors, not a naive cap, carry the
defense.

## 4. Disclosure (OIDC)

### 4.1 Scope + claim

- New opt-in scope **`sybil-score`** (in an RP's `allowedScopes` like a badge
  scope). Add it to `scopes_supported` and the new claim to `claims_supported` in
  the discovery doc (`oidc-config.ts`).
- New claim **`sybil_bucket`** (integer 0-4). Add `sybilBucket?: number` to
  `ResolvedUserClaims`; `minister_badges` is untouched.

### 4.2 Snapshot at consent (not at disclosure time)

Compute the bucket **once at consent-approve** and stamp it, because (1) OIDC
requires id_token and userinfo to agree for one grant and `resolveUserClaims` was
centralized to make that structural, and (2) recomputing at userinfo could
disclose a higher bucket the user never consented to (they earned a badge between
consent and userinfo). Wiring:

- Add a `sybilScore Boolean @default(false)` grant to `OidcAuthorizationCode`
  (denormalized to `OidcAccessToken`), mirroring the profile grant split.
- Add `sybilBucket Int?` to the code row (and access token); set it at
  `approveConsent` from the pure scorer over the user's held badges.
- `resolveUserClaims` takes the bucket as a parameter (it stays pure/DB-free) and
  emits `sybil_bucket` **only** when the grant boolean is true.

### 4.3 Consent + withholding

- Consent line when the scope is present: "Share your account-strength level:
  **3 of 4**. This shows how hard your account is to fake. It does not reveal
  which badges you have." (Precise: it reveals _that_ you hold more, never _what_.)
- Surface the **bucket-class size** as an anonymity hint (reuse the
  `anonymity-hint.ts` bucketing) so a user in a tiny "bucket 4" class on a small
  instance sees "very small group" before sharing.
- No grant -> **omit** the claim entirely. Never emit `0` as a substitute (0 is a
  real value). Config unreadable at consent -> omit + audit, login unaffected
  (fail-closed-omit, mirroring the per-badge path).

### 4.4 Privacy

5 buckets ~= 2.3 bits under pairwise `sub`: a negligible cross-RP correlator and
within-RP fingerprint; documented in `docs/oidc-privacy.md` with a hard "do not
add resolution without re-review". The bucket cannot identify which badges (many
preimages per bucket); it does leak _aggregate existence_ of undisclosed
holdings, which is the product's intent and the consent copy's exact wording.

### 4.5 SDK mirror + verify

`@ministryofmany/minister-verify`'s `VerifiedIdentity` must carry the verified
`sybil_bucket` (Deforum's callback verifies through it), and the client's
scope/claims types + drift-check gain `sybil-score`. The score **config is
server-only**; the SDK consumes the disclosed bucket, never recomputes it. This
is Phase 3 and gates any RP score-gate.

## 5. Admin dashboard (Ministry)

Operator-gated (mirrors `/admin`). Sections:

### 5.1 Weights editor

Every `(badgeType, qualifier)` row, two editable columns (`sybilWeight`,
`recoveryWeight`), its `category` (dropdown), and a **holder-count** column. In
Phase 1 the holder count comes from the existing 60s-cached
`anonymity-sets.ts` counts; Phase 2 swaps in the materialized stats. The recovery
column is **greyed out for recovery-ineligible types** (§5.4). Edits are
transactional, validated, **audit-logged** with before/after.

### 5.2 Categories + caps, 5.3 bucket cutoffs

Add/rename categories, assign types, edit caps; edit the four cutoffs with a live
preview ("a user holding {github oauth + verified email} scores raw N -> bucket
B").

### 5.4 Recovery guardrails (security-critical; auditor sign-off)

Recovery weights are **read live per re-proof** today
(`recovery-threshold.ts:184`; only `requiredScore` is snapshotted at attempt
start, `:106-127`). Keep live-read (a defensive emergency cut takes effect
instantly). Mandatory guardrails:

- **Bounds/clamps**: `recoveryWeight in [0,100]`; `threshold in [100,1000]` (never
  below today's 100 - "recovery at least as hard as the front door"). Hard-block
  any single type's weight `>= threshold` unless it carries an explicit
  `allowSoloRecovery` flag, seeded only for `tlsn-attestation` (the deliberate
  IAL3 solo path). This blocks "email weight = 100 -> one inbox recovers any
  account".
- **Asymmetric apply timing** (the strongest control): weight _decreases_ and
  threshold _increases_ apply **immediately** (defensive); weight _increases_ and
  threshold _decreases_ take effect after a **72h delay** (reuse
  `CREDENTIAL_QUARANTINE_MS`), with a notification, so a human sees a weakening
  before it gains power. This moots the live-read attack direction.
- **AAL2 step-up** to edit recovery config (`requireAal`/`StepUpRequiredError`
  exist). Note: `requireAal` checks the session's AAL, **not recency** - a passkey
  session is AAL2 for 24h. Minister has no `auth_time` recency today. Either add a
  small recency check or the spec says "AAL2 session" (not "fresh"); do not claim
  a property the code can't express. **Decision needed** (§12).
- **Audit + broadcast**: `AuditLog` (actor, before/after, ts) **plus email to all
  admins** on any recovery-config change - a lone compromised admin can't weaken
  recovery silently.
- **Fail closed on config read failure** mid-recovery: abort the re-proof, never
  default a weight to 0 or the seed silently.
- **`RECOVERY_ELIGIBLE_TYPES` stays in code**, not the DB (it means "a plugin can
  nonce-bind a live re-proof" - a code property). The editor greys out the
  recovery column for ineligible types (today: oauth-account, email-domain,
  email-exact, tlsn-attestation).
- **Parity test** covers the provenance fallbacks exactly (github/google/reddit/
  hackernews/undefined -> 20, discord/steam -> 10, email 15, tlsn 100, IAL
  fallback for unreachable types) so behavior is byte-identical. Separately flag
  (not part of parity) that reddit/hackernews inheriting 20 is likely
  miscalibrated - the dashboard's first audited edit after seeding.

### 5.5 Statistics view

Per type: global holder count + global %. Expandable to **allowlisted** attribute
distributions (§6). Plus **conditional cohorts**: operator-defined numerator/
denominator distinct-user counts + %. Built-in example: denominator =
`oauth-account{provider=github}` holders; numerator = `account-age{provider=
github, olderThanMonths>=24}` holders; show "N users" and "P% of github-account
holders". Admin view shows exact counts (operator-gated).

## 6. Public stats page (Ministry)

Public, read-only: the **score model** (categories, caps, bucket meaning, the raw
per-badge weights - published deliberately, plus the per-bucket dollar-cost table)
and **badge statistics** (global counts/% and reviewed cohort stats).

Privacy guardrails (k-suppression alone is insufficient):

- **Attribute-value allowlist (mandatory).** Materialize/publish attribute stats
  ONLY for keys whose value space is a closed enum: `provider`, `olderThanMonths`,
  `followersAtLeast`, `chain`, `event`, `threshold`, `kind`, `country`. NEVER
  `email`, `domain`, `fingerprint`, `state`, `city`, `handle` - the _existence_ of
  a row like `email-domain=corp.example.com` leaks that someone at that org uses
  Minister, which suppression cannot fix. The allowlist lives in code by the
  registry; the recompute validates every configured cohort key against it (also
  closing a JSON-key injection hole - keys are never interpolated free-form).
- **k-anonymity suppression**: any public cell with count < k (default 5) shows
  "<k". Admin view may show exact.
- **Count rounding**: public counts rounded (nearest 10, or ~5% for large counts)
  so hourly diffing can't watch single +1 transitions (a differencing
  deanonymization vector). Do not publish time series; exact counts admin-only.
  Residual cross-cohort differencing risk is noted in operator docs, not claimed
  eliminated.

## 7. Statistics recompute job

Stats are **materialized** into `BadgeStat` (+ cohort tables); live cross-badge
`COUNT(DISTINCT userId)` per request is too heavy.

- **Scheduling: an in-process interval**, not host cron. The box is pull-only,
  reachable only briefly over SSH, its compose file already drifts from `infra`,
  and the last outage was unmanaged host state - host cron is one more forgotten
  hand-config that image deploys won't carry. An `instrumentation.ts`-registered
  interval (production-guarded, jittered, taking a Postgres **advisory lock** or
  checking `computedAt` freshness so a second process is a no-op) ships in the
  image, survives redeploys with zero box work; the recompute is a handful of
  aggregate queries. Keep the `stats:recompute` **script** and the admin
  **"recompute now"** button as the escape hatch and test surface. This interval
  is also the seam a future real scheduler (Eligibility auto-issuance) grows from.
- Materialization is delete-and-rewrite (or upsert) in one transaction,
  `@@unique([badgeType, attributeKey, attributeValue])`, single `computedAt`
  surfaced as "as of ...".

## 8. Deforum consumption (first RP)

### 8.1 Bucket persistence + staleness

Deforum gates from the session with no per-call OIDC re-verify; the id_token
lives ~10min, the app session ~30 days, and nothing stores a bucket today. So:
verify `sybil_bucket` from the id_token at the OIDC **callback**, persist it on
`deforum_users` as `sybilBucket Int` + `sybilBucketVerifiedAt` (beside
`cachedBadges`), gate from the session-resolved user, and enforce a **staleness
policy**: a bucket older than **7 days** (or absent) fails the gate and redirects
to re-auth (the user is usually still signed in at Minister - two clicks). This
prevents honoring a 30-day-old bucket after Minister revoked the badges behind it.

### 8.2 Layered dials + effective = max

Three min-bucket dials, each `0` = off: `siteMinBucket`, `discoveryMinBucket`
(home feed + directory), per-sub-forum `viewMinBucket`. Effective bar for a page =
**max** of the applicable dials. Defaults: site 0, discovery 0 (public shopfront),
per-sub-forum 0 (public) - the recommended default from the brainstorm, every
higher wall one toggle away. Clamp all dials to 0-4 server-side.

### 8.3 Enforcement (choke-point, fail-closed, row-filtering)

- One shared helper `requireViewBucket(target, session)` where target is a
  sub-forum id, `'discovery'`, or `'site'`, called from **every gated page load
  AND every content-bearing API GET** - a choke point like the existing
  `authorizeAction`, not per-route copy-paste. Content GETs to cover today:
  `/api/posts/[postId]/poll/results` (enforce the post's sub-forum gate); note
  that any future RSS route must route through the same helper.
- **Home feed + directory must filter ROWS**, not just gate the page: a sub-forum
  whose effective view gate exceeds the viewer's bucket is **excluded** from the
  aggregated feed and directory (mirroring how members-only subs are already
  skipped in `feed/home.ts` and `directory/list.ts`). `discoveryMinBucket` gates
  the aggregation surface itself; per-sub-forum `viewMinBucket` filters which rows
  appear within it - two independent controls.
- **Existence semantics**: the bucket gate's "this space needs a stronger
  account" page **confirms the sub-forum exists** (it is the shopfront). Operators
  who want to hide existence use `defaultVisibility: members-only` (404), not
  `viewMinBucket`. State this in the operator UI.
- **Config fail-closed nuance**: "settings row absent" (never configured) -> dials
  0, site fully public (do NOT brick a fresh post-migration boot); "settings read
  error" -> fail closed on the gated surface only.
- **Declined scope**: Deforum requests `sybil-score` at login; a user who
  declines logs in fine but fails every gate >= 1. Deforum surfaces that state
  explicitly ("you chose not to share account strength"), not a generic wall.

### 8.4 Config storage + ops

- Instance dials live in a new **singleton settings row** (Deforum has no
  instance-config table today; only env + per-sub-forum jsonb).
- `subforums.viewMinBucket Int default 0`.
- Both edited in the operator dashboard, `requireOperator`-gated, audit-logged.
- **Ops step (runbook)**: add `sybil-score` to Deforum's login scopes and to the
  Deforum client's `allowedScopes` in Minister's admin, or every authorize is
  rejected.

## 9. Data model (first draft)

Minister (new; names indicative):

- `BadgeWeight { badgeType, qualifier, sybilWeight Int, recoveryWeight Int, category String, allowSoloRecovery Boolean @default(false), effectiveAt DateTime?, updatedAt }` - PK `(badgeType, qualifier)`. `effectiveAt` carries a delayed weakening (§5.4). Seeded from current constants.
- `SybilCategory { name @id, cap Int }`.
- `SybilBucketConfig` (four cutoffs + breadth floors) and `RecoveryConfig` (`threshold`) as singleton config rows.
- `BadgeStat { id, badgeType, attributeKey, attributeValue, count Int, computedAt, @@unique([badgeType, attributeKey, attributeValue]) }` - allowlisted keys only.
- `CohortStatDef { id, label, numeratorFilter Json, denominatorFilter Json }` + `CohortStat { defId, numerator Int, denominator Int, computedAt }`. A filter side = a Zod-validated conjunction of 1-3 `{ type, where?, whereGte? }` clauses over allowlisted keys; computed via `EXISTS` subqueries (distinct-user counts), scoped to unexpired native badges.
- `OidcAuthorizationCode` gains `sybilScore Boolean @default(false)` + `sybilBucket Int?` (denormalized to the access token).
- Config changes recorded via `AuditLog` + admin email broadcast.

Deforum (new):

- `deforum_users.sybilBucket Int?` + `sybilBucketVerifiedAt DateTime?`.
- `InstanceSettings` singleton: `siteMinBucket Int`, `discoveryMinBucket Int`.
- `subforums.viewMinBucket Int @default(0)`.

## 10. Cohort filter format (v1)

A cohort side is a conjunction of 1-3 badge filters:
`{ type: string, where?: Record<allowlistedKey, string|number|boolean>, whereGte?: Record<allowlistedKey, number> }`, Zod-validated, keys allowlist-checked. Distinct-user count example (built-in "github aged accounts as a fraction of github accounts"):

```sql
SELECT COUNT(DISTINCT b1."userId") FROM "Badge" b1
WHERE b1.type = 'account-age'
  AND b1.attributes->>'provider' = 'github'
  AND (b1.attributes->>'olderThanMonths')::int >= 24
  AND b1."issuer" = <minister-did> AND (b1."expiresAt" IS NULL OR b1."expiresAt" > now())
  AND EXISTS (SELECT 1 FROM "Badge" b2 WHERE b2."userId" = b1."userId"
              AND b2.type = 'oauth-account' AND b2.attributes->>'provider' = 'github');
```

`olderThanMonths` is stored as the highest satisfied tier, so `>=24` correctly
sums the 24/36/60 cells.

## 11. Build plan (phased; domain-floor; auditor pass per phase)

1. **Phase 1 - Minister core**: `BadgeWeight`/category/bucket/recovery config
   tables + seed migration (parity test), the pure scorer (hygiene + boot check),
   the `sybil-score` scope + `sybil_bucket` claim with **consent-snapshot** wiring
   - consent copy + anonymity hint + discovery-doc updates, the admin weights/
     categories/caps/buckets editors with the recovery guardrails (§5.4). Editor
     holder-count column uses `anonymity-sets.ts`.
2. **Phase 2 - Stats**: `BadgeStat`/cohort tables, recompute (in-process interval
   - script + "recompute now"), admin stats view, public transparency page with
     the attribute allowlist, k-suppression, and rounding.
3. **Phase 3 - SDK**: `sybil-score` scope + `sybil_bucket` claim + drift-check in
   the client, and the verified bucket carried on
   `@ministryofmany/minister-verify`'s `VerifiedIdentity`.
4. **Phase 4 - Deforum**: `deforum_users` bucket persistence + staleness, instance
   settings + `viewMinBucket`, request the scope at login (+ the Minister
   allowedScopes ops step), the fail-closed layered gate choke-point with home/
   directory row filtering, operator UI.
5. **Phase 5 (optional, later) - Discreetly**: room min-bucket dial.

Each phase: typecheck + tests + `next build` (the real Next gate) green.

**Auditor must sign off on**: the recovery clamps + delayed-apply +
`allowSoloRecovery` (§5.4); the consent-snapshot disclosure wiring + fail-closed
omission (§4); the stats attribute allowlist + rounding (§6); and the Deforum gate
choke-point + feed/directory row filtering (§8).

## 12. Decisions still needed from the owner

- **AAL freshness**: build a small `auth_time` recency check so recovery-config
  edits require a _fresh_ step-up, or accept "any AAL2 session" and note the gap?
  (Deep-solver leans: build the recency check - it is small and this is
  account-security config.)
- **Default Deforum gate** for opted-in sub-forums: bucket **1** (welcoming: any
  proof) or **2** (one solid proof)? Reserve 3-4 for `siteMinBucket` scrape-wave
  emergencies.
- **Publish raw weights** on the public page (recommended yes, paired with the
  dollar-cost table) vs categories + bucket meaning only?
