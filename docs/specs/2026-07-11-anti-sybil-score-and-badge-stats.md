# Anti-Sybil Quality Score, Badge Statistics, and RP View-Gating

Status: draft for review (deep-solver review pending)
Date: 2026-07-11
Scope: Minister (core), `@minister/client` SDK (mirror), Deforum (first consumer), Discreetly (optional, later)

## 1. Goal

Give every badge a **cost-to-farm weight**, sum a user's held badges into a coarse
**anti-sybil score bucket (0-4)**, and let a relying party gate on that bucket
**without ever learning which badges the user holds**. Ship the operator tooling
to tune it well: an admin dashboard to edit the weights, categories, caps, and
bucket cutoffs, plus badge statistics (global and conditional) so the tuning is
informed rather than guessed. Publish a public stats page. Recompute the stats on
a schedule.

First consumer: Deforum requires a Minister login at or above a configurable
score bucket to view gated surfaces, tunable per sub-forum and instance-wide, to
deter scraping while staying welcoming to real newcomers.

## 2. Non-goals

- Proof of unique personhood. The score is "how expensive is this identity to
  farm", never "this is one distinct human". Copy and docs must say so.
- Changing the per-badge disclosure model. Individual badge VCs still disclose
  exactly as today; the score is an _additional_, opt-in, aggregate claim.
- A global cross-RP reputation. The bucket is disclosed per-RP under the pairwise
  `sub`, so it is not a cross-RP correlator.
- Discreetly integration is documented but deferred past v1.

## 3. The score model

### 3.1 Two independent weight columns per badge type

Every badge type carries **two** operator-editable integer weights, for two
different threat models that must not be conflated:

- **`sybilWeight`** (new) - cost to farm this credential as a fake human.
  Consumed only by the RP-facing score. Higher = harder to farm.
- **`recoveryWeight`** (existing, migrated) - how much this badge counts toward
  the account-recovery threshold. Today these live as hardcoded constants in
  `apps/minister/src/lib/assurance.ts` (`BADGE_ASSURANCE_WEIGHT`,
  `RECOVERY_WEIGHT_BY_TYPE`, the oauth provenance table, `RECOVERY_THRESHOLD`).
  This spec moves them into the same DB config so the admin can edit both columns
  side by side. **Behavior must be identical to today on first migration** (seed
  the table from the current constants; a migration parity test asserts equality).

The existing inert `sybilResistance` label (`none | weak | moderate`) on
`BadgeTypeMeta` is **not** the score. It answers "is a dedup nullifier wired",
a different question. It stays as-is (informational); the new `sybilWeight` is
purpose-built and calibrated fresh.

### 3.2 Provenance sensitivity

`oauth-account` weight already depends on provenance today (github/google worth
more than discord/steam for recovery). The sybil score needs the same nuance.
The weight config is therefore keyed by **(badgeType, provenanceKey)** where
`provenanceKey` is `*` for types with no provenance split and the provider slug
for `oauth-account` (and any future provenance-split type). The resolver falls
back to the `*` row when no specific row exists.

### 3.3 Categories and per-category caps (anti-farming)

A naive sum is farmable: 10 throwaway email badges should not equal 10x the
score. Each badge type belongs to an operator-editable **category**, and each
category has a **cap**. A user's contribution from a category is
`min(categoryCap, sum of sybilWeights of that user's badges in the category)`.
The raw score is the sum of capped category contributions.

First-draft categories (editable in the dashboard):

| Category          | Types                                        | Rationale                                       |
| ----------------- | -------------------------------------------- | ----------------------------------------------- |
| `email`           | email-domain, email-exact                    | cheap, farmable in bulk                         |
| `social-oauth`    | oauth-account, social-following, account-age | one real account is cheapish; many are costlier |
| `wallet`          | wallet-control, wallet-age, onchain-event    | one funded/aged wallet has real cost            |
| `human-attribute` | age-over-_, residency-_                      | proofs about a real person                      |
| `domain`          | domain-control                               | controlling a real domain has cost              |
| `attestation`     | tlsn-attestation, public-key                 | strong, hard to fake                            |
| `invite`          | invite-code                                  | trust delegated by an existing member           |

Dedup already prevents holding two badges with the same anchor (same github,
same email), so within-category farming is bounded further by the cap.

### 3.4 Raw score -> bucket (0-4)

Coarse on purpose: five buckets keep the disclosed value low-entropy (so it is a
negligible fingerprint even before pairwise-`sub`), and coarse is all an
anti-scrape gate needs. Bucket cutoffs are operator-editable. First-draft
meaning (exact cutoffs are for the deep-solver to calibrate against the seeded
weights):

- **0** - no meaningful anti-sybil signal (fresh account, nothing proven).
- **1** - a single weak signal (one email, one throwaway oauth).
- **2** - a couple of independent signals.
- **3** - several independent signals or one strong one.
- **4** - high assurance (a strong attestation, or many independent proofs).

### 3.5 Where it is computed

A pure function `sybilScore(heldBadges, config) -> { raw: number, bucket: 0..4 }`
in a new plain module (e.g. `apps/minister/src/lib/sybil-score.ts`), over the
badges the user **holds** (not only disclosed ones - the whole point is the RP
learns the bucket without the badge set). Unit-tested against fixture badge sets.
It never throws; an unknown badge type contributes 0 and is logged for the admin
to categorize.

## 4. Disclosure (OIDC)

### 4.1 New scope + claim

- New scope: **`sybil-score`** (opt-in, listed in an RP's `allowedScopes` like
  any badge scope). Requesting it means "I want the account-strength bucket".
- New id_token / userinfo claim: **`sybil_bucket`** (integer 0-4), emitted by
  `resolveUserClaims` (`apps/minister/src/lib/oidc-claims.ts`) **only** when the
  `sybil-score` scope was requested and consented, computed via the pure scorer
  over the user's held badges at disclosure time.
- Add `sybilBucket?: number` to `ResolvedUserClaims`. No other pipeline change:
  `minister_badges` is untouched; the bucket is an independent field.

### 4.2 Consent

The consent screen gets one plain, honest line when the scope is present, e.g.:
"Share your account-strength level: **3 of 4**. This shows how hard your account
is to fake. It does not reveal which badges you have." Consent is per the normal
grant flow; declining drops the claim, not the login.

### 4.3 Privacy

- 5 buckets = ~2.3 bits, disclosed under the pairwise `sub`, so not a cross-RP
  correlator and a negligible within-RP fingerprint. Documented in
  `docs/oidc-privacy.md`.
- The RP never sees the components, only the bucket. Confirmed by construction:
  the scorer output is a scalar; the badge set is never in the claim.

### 4.4 SDK mirror

`@minister/client` must gain: the `sybil-score` scope, the `sybil_bucket` claim
in its verified-claims type, and (for RPs that want to display or reason about
it) the canonical bucket meaning. The score **weights/config are server-only** -
the SDK never recomputes the score; it consumes the disclosed bucket. The
existing drift-check gains the scope. (Cross-repo follow-on, gated before any RP
ships a score gate.)

## 5. Admin dashboard (Ministry)

New operator-gated surface (mirroring `/admin` gating). Sections:

### 5.1 Weights editor

A table of every `(badgeType, provenanceKey)` row with **two editable columns**,
`sybilWeight` and `recoveryWeight`, plus the type's `category` (a dropdown) and
a read-only note of its current holder count (from the stats table). Editing is
transactional, validated (non-negative ints, bounded), and **audit-logged** with
before/after values.

### 5.2 Categories + caps editor

Add/rename categories, assign types to categories, edit each category's cap.

### 5.3 Bucket cutoffs editor

Edit the four cutoffs that map raw score -> bucket, with a live preview: "with
the current weights, a user holding {a github oauth + a verified email} would
score raw N -> bucket B".

### 5.4 Recovery guardrails (security-critical)

The recovery weights and `RECOVERY_THRESHOLD` are **account-security** knobs:
lowering them weakens account recovery for everyone. Therefore:

- Editing recovery weights requires a **fresh step-up (AAL2)**, is **audit-logged**,
  and shows an explicit warning.
- Config values are **bounded** (server-side clamps; a recovery weight cannot be
  set absurdly high to trivialize recovery, nor the threshold to 0).
- A change to a recovery weight does not retroactively alter an in-flight
  `RecoveryAttempt` (weights are read at attempt start, not per re-proof - confirm
  against `recovery-threshold.ts` current behavior and preserve it).

### 5.5 Statistics view

Per badge type: global holder count and global % of all users. Expandable to
attribute distributions (e.g. account-age: counts at each of 12/24/36/60 months;
oauth-account: counts per provider). Plus **conditional cohort stats**: for a set
of operator-defined cohorts, numerator/denominator distinct-user counts and the
percentage. Built-in example matching the ask: denominator = holders of
`oauth-account{provider=github}`; numerator = holders of
`account-age{provider=github, olderThanMonths>=24}`; display both "N users
globally" and "P% of github-account holders". Operators can define additional
cohorts (a cohort = a labeled numerator filter + denominator filter, each a
badgeType plus attribute predicates).

## 6. Public stats page (Ministry)

A public, read-only page showing the **score model** (the categories, caps, and
bucket meaning - and, subject to the open question in §12, possibly the raw
per-badge weights) and the **badge statistics** (global counts/percentages and
the configured cohort stats). Transparency is a feature: it lets anyone see how
the score is built and how common each badge is. The tension to resolve is that
publishing the exact weights also hands a farmer the exact recipe.

Privacy guardrail: **k-anonymity suppression**. Any cell whose count is below a
threshold `k` (default 5, configurable) is shown as "<k" rather than an exact
small number, so the public page never deanonymizes a badge held by one or two
users. The admin view may show exact counts (operator-gated); the public view
suppresses.

## 7. Statistics recompute job

Stats are **materialized** into a `BadgeStat` table, not computed live (live
`COUNT(DISTINCT userId)` across cross-badge cohorts is too heavy per request).

- A pure recompute function walks the badge tables and writes: per
  `(badgeType, attributeKey, attributeValue)` distinct-user counts, per-type
  totals, and the configured cohort numerator/denominator counts, all stamped
  `computedAt`.
- **Scheduling**: Minister has no scheduler today. The recompute is exposed as (a)
  a script `pnpm --filter @minister/app stats:recompute` and (b) an
  operator-only "recompute now" button. Production runs it on a **host cron** on
  the Lightsail box (hourly or nightly - operator choice; nightly default),
  invoking the script inside the running container. This avoids adding an
  in-process scheduler and matches how the box already runs scheduled work.
  (Open: whether to add a lightweight in-process interval instead - deep-solver to
  weigh, given the single-instance deployment.)
- The public and admin stats pages read the latest materialized rows and show
  `computedAt` ("as of ...") so staleness is honest.

## 8. Deforum consumption (first RP)

### 8.1 Layered, operator-tunable gate

Three independent **min-bucket dials**, each `0` = off (no gate):

- `siteMinBucket` - the whole site.
- `discoveryMinBucket` - the home feed and the directory.
- per-sub-forum `viewMinBucket` - a specific sub-forum's content.

The **effective** required bucket for any page is the **maximum** of the
applicable dials (site always applies; discovery applies to home/directory; the
sub-forum dial applies to that sub-forum). So the operator can raise the site
floor during a scrape wave and drop it afterward, independently of per-sub-forum
settings.

**Defaults**: `siteMinBucket = 0`, `discoveryMinBucket = 0` (public shopfront),
per-sub-forum `viewMinBucket = 0` (public), operator opts a sub-forum in. This is
the recommended default from the brainstorm (home + directory public, gate per
sub-forum), while every higher wall is one toggle away.

### 8.2 Enforcement

- Deforum requests the `sybil-score` scope at login so the session carries the
  user's bucket (verified from the id_token, fail-closed like badge verification
  today).
- Route loads enforce the effective min-bucket **fail-closed**, mirroring the
  existing `defaultVisibility === 'members-only'` 404 pattern and the
  operator-gate soft/hard split: a logged-out or under-threshold visitor to a
  gated surface is redirected to `sign in with Minister` (carrying `next`), or
  shown an "this space requires a stronger account" page with what would clear it.
- The home feed and directory apply the `discoveryMinBucket` gate at the page
  level; individual gated sub-forums apply their own dial.

### 8.3 Config storage + operator UI

- Instance dials (`siteMinBucket`, `discoveryMinBucket`, the cron cadence if
  surfaced) live in a new **instance-settings** store (a singleton settings row;
  Deforum has no instance-config table today, only env + per-sub-forum jsonb).
- Per-sub-forum `viewMinBucket` is a new field on the `subforums` row (alongside
  `defaultVisibility`).
- Both edited in the existing operator dashboard
  (`/admin`, `/admin/s/[subforumId]`), gated by `requireOperator`, audit-logged.

## 9. Security and privacy considerations

- **Admin-editable recovery weights are the sharp edge.** They are account-security
  config. Guardrails in 5.4 (AAL2 step-up, bounds, audit log, no retroactive
  effect on in-flight attempts) are mandatory, not optional. The auditor must
  sign off on these specifically.
- **Fail-closed everywhere**: an unreadable/absent config, an unverifiable bucket,
  or a missing scope all resolve to "no disclosure / no access", never "open".
- **Bucket entropy**: 5 coarse buckets under pairwise `sub`; documented as a
  negligible correlator. Do not add resolution without re-reviewing this.
- **Stats k-anonymity**: public page suppresses cells below `k` (default 5).
- **Score is over held badges, disclosed as a scalar** - verify by construction
  that no code path can leak the contributing badge set through the score claim.
- **All config edits audit-logged** with actor, before/after, timestamp.

## 10. Data model (first draft)

Minister (new tables; names indicative):

- `BadgeWeight { badgeType, provenanceKey, sybilWeight Int, recoveryWeight Int, category String, updatedAt }` - PK `(badgeType, provenanceKey)`. Seeded from current constants.
- `SybilCategory { name @id, cap Int }`.
- `SybilBucketConfig` - the four cutoffs (a singleton config row or a small table).
- `RecoveryConfig` - `threshold Int` and any other migrated recovery scalars.
- `BadgeStat { id, badgeType, attributeKey, attributeValue, count Int, computedAt, @@index([badgeType]) }` - materialized distinct-user counts.
- `CohortStatDef { id, label, numeratorFilter Json, denominatorFilter Json }` + `CohortStat { defId, numerator Int, denominator Int, computedAt }`.
- Config changes recorded via the existing `AuditLog`.

Deforum (new):

- `InstanceSettings` singleton row: `siteMinBucket Int`, `discoveryMinBucket Int`, `statsCron?`.
- `subforums.viewMinBucket Int default 0`.

## 11. Build plan (phased; domain-floor)

1. **Deep-solver design pass** (this spec's calibration + review): exact sybil
   weights, category caps, bucket cutoffs, the recovery-migration parity, the
   guardrail bounds, the disclosure wiring, and the scheduling choice. Auditor
   reviews the recovery-weight editability and the disclosure privacy.
2. **Phase 1 - Minister core**: config tables + seed migration (parity test),
   the pure scorer, `sybil-score` scope + `sybil_bucket` claim + consent, admin
   weights/categories/caps/buckets editors with the recovery guardrails.
3. **Phase 2 - Stats**: `BadgeStat`/cohort tables, recompute script + "recompute
   now", host cron, admin stats view, public stats page with k-anonymity.
4. **Phase 3 - SDK mirror**: scope + claim + drift-check in `@minister/client`.
5. **Phase 4 - Deforum**: instance settings + `viewMinBucket`, request the scope
   at login, fail-closed layered gate in the loads, operator UI.
6. **Phase 5 (optional, later) - Discreetly**: room min-bucket dial.

Each phase: typecheck + tests + `next build` (the real Next gate) green, and the
domain-floor pieces (scorer, disclosure, recovery config, gate) get an auditor
pass before merge.

## 12. Open questions for the deep-solver

- Exact `sybilWeight` per type and per oauth provenance; the category caps; the
  four bucket cutoffs - calibrated so a real newcomer with one solid proof clears
  a sensible default gate but a zero-cost account does not.
- How to represent provenance-split weights cleanly in the editable table without
  a combinatorial explosion.
- Recovery-weight guardrail bounds (min/max per weight, threshold floor).
- Scheduling: host cron vs a lightweight in-process interval on the single
  instance.
- Cohort-stat definition format (how expressive the operator-defined filters
  should be in v1).
- Whether the public page shows the raw weight numbers or only the categories +
  bucket meaning (full transparency vs giving a farmer the exact recipe).
