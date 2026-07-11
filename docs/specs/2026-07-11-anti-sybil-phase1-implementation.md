# Anti-Sybil Score - Phase 1 Implementation Brief (Minister core)

Companion to `2026-07-11-anti-sybil-score-and-badge-stats.md` (the design spec).
This brief pins the concrete architecture calls, exact seams (file:line from a
full codebase recon), seed values, and the build/verify contract for Phase 1.
Every build agent reads this. Section numbers below reference the design spec.

Branch: `feat/anti-sybil-score`. Package manager: pnpm. Node 20+.
Gate every change on: `pnpm --filter @minister/app typecheck` **and**
`pnpm --filter @minister/app test` **and** `pnpm --filter @minister/app build`
(the real Next gate - a `"use server"` file may export ONLY async functions; a
class/const export passes tsc + vitest but FAILS `next build`).

---

## 0. Architecture decisions (beyond the spec)

1. **Recovery-weight migration = "seed + live DB read", NOT a rewrite of
   `recoveryWeightFor`.** The existing pure sync `recoveryWeightFor(type,
provenance)` in `apps/minister/src/lib/assurance.ts` stays UNCHANGED. It is
   the seed source and the parity oracle. A NEW async
   `recoveryWeightForLive(type, provenance)` reads the `BadgeWeight` DB row
   (honoring the delayed-apply window) and REPLACES the call at
   `recovery-threshold.ts:184`. `assurance.test.ts` stays green untouched.
2. **Delayed-apply lives on the rows**, not a separate schedule table:
   `BadgeWeight.pendingRecoveryWeight Int?` + `recoveryEffectiveAt DateTime?`;
   `RecoveryConfig.pendingThreshold Int?` + `thresholdEffectiveAt DateTime?`.
   Live effective value = `pending != null && effectiveAt <= now ? pending :
live`. No promotion job needed in Phase 1; the read honors `effectiveAt`.
3. **Two admin routes, walled by threat model.** `/admin/sybil-score`
   (sybilWeight + categories + caps + bucket cutoffs; immediate apply; admin
   gate only). `/admin/recovery-config` (recoveryWeight + threshold +
   allowSoloRecovery; delayed-apply; admin + AAL2 + non-recovered + fresh
   `auth_time`; admin-email broadcast). Never let a recovery edit ride the
   low-friction sybil path.
4. **Scorer is pure + context-injected.** `sybilScore(badges, config, ctx)` where
   `ctx = { now: number, nativeIssuerDid: string }`. Filtering (expired /
   non-native) happens INSIDE the scorer over the injected ctx so the rule is
   centralized and unit-tested offline. Never throws.
5. **Parity test is pure/offline.** It asserts the seed rows reproduce
   `recoveryWeightFor` for every (type, provenance); no DB needed.
6. **Deferred to Phase 2:** the _live_ bucket-class-size on the consent anonymity
   hint (needs materialized bucket stats). Phase 1 consent shows the bucket
   number + fixed explanatory copy, no live class size. The per-type
   holder-count column in the weights editor uses the existing 60s-cached
   `holderCountsByType()` (per-type, approximate) in Phase 1.

---

## 1. Data model (Prisma additions)

File: `apps/minister/prisma/schema.prisma`. Generate the migration named
`add_sybil_score_config` via `pnpm --filter @minister/app db:migrate` against a
running compose postgres (`docker compose up -d postgres` from `Minister/` first;
dev `DATABASE_URL` in `.env` points at :5433). Commit the generated
`prisma/migrations/<ts>_add_sybil_score_config/` folder. Naming convention:
`<YYYYMMDDHHMMSS>_snake_case` (auto). Prod applies it via `boot-migrate`
(`prisma migrate deploy`) - do NOT hand-edit applied migrations.

```prisma
model BadgeWeight {
  badgeType             String
  qualifier             String   // "*" or a resolved qualifier token (e.g. "github", "github:24")
  sybilWeight           Int
  recoveryWeight        Int      // live/effective recovery contribution
  category              String   // FK-by-name to SybilCategory.name (validated in app, not DB FK)
  allowSoloRecovery     Boolean  @default(false)
  // Delayed-apply for RECOVERY weakening only (weight INCREASE). null = no pending change.
  pendingRecoveryWeight Int?
  recoveryEffectiveAt   DateTime?
  updatedAt             DateTime @updatedAt

  @@id([badgeType, qualifier])
  @@index([category])
}

model SybilCategory {
  name String @id
  cap  Int
}

// Singleton (single row, id = "singleton"). Four bucket cutoffs + breadth floors.
model SybilBucketConfig {
  id            String @id @default("singleton")
  // raw-score cutoffs
  bucket1Raw    Int    // >= this -> at least bucket 1
  bucket2Raw    Int
  bucket3Raw    Int
  bucket4Raw    Int
  // qualifying-category breadth floors
  bucket3MinCats Int
  bucket4MinCats Int
  updatedAt     DateTime @updatedAt
}

// Singleton (id = "singleton"). Recovery threshold with delayed-apply.
model RecoveryConfig {
  id                 String   @id @default("singleton")
  threshold          Int      // live/effective (seed 100; bounds [100,1000])
  pendingThreshold   Int?     // delayed weakening (threshold DECREASE)
  thresholdEffectiveAt DateTime?
  updatedAt          DateTime @updatedAt
}
```

`OidcAuthorizationCode` (after `profileAvatar`):

```prisma
  // Granular sybil-score disclosure. Snapshotted at consent; the resolver emits
  // `sybil_bucket` strictly from this flag + bucket, never recomputed at token
  // /userinfo time. sybilScore false whenever `sybil-score` not in scopes.
  sybilScore  Boolean @default(false)
  sybilBucket Int?
```

`OidcAccessToken` (after `profileAvatar`, denormalized identically):

```prisma
  sybilScore  Boolean @default(false)
  sybilBucket Int?
```

---

## 2. Seed values

### 2.1 Sybil weights (design spec §3.6) - `BadgeWeight.sybilWeight`

| badgeType              | qualifier              | sybilWeight |
| ---------------------- | ---------------------- | ----------- |
| email-domain           | *                      | 5           |
| email-exact            | *                      | 5           |
| oauth-account          | github                 | 8           |
| oauth-account          | google                 | 12          |
| oauth-account          | discord                | 4           |
| oauth-account          | steam                  | 5           |
| oauth-account          | reddit                 | 4           |
| oauth-account          | hackernews             | 4           |
| oauth-account          | *                      | 4           |
| account-age            | github:12              | 10          |
| account-age            | github:24              | 15          |
| account-age            | github:36              | 18          |
| account-age            | github:60              | 22          |
| account-age            | reddit:12              | 6           |
| account-age            | reddit:24              | 10          |
| account-age            | reddit:36              | 12          |
| account-age            | reddit:60              | 15          |
| account-age            | hackernews:12          | 6           |
| account-age            | hackernews:24          | 10          |
| account-age            | hackernews:36          | 12          |
| account-age            | hackernews:60          | 15          |
| account-age            | *                      | 6           |
| social-following       | github:10              | 4           |
| social-following       | github:50              | 6           |
| social-following       | github:100             | 8           |
| social-following       | github:500             | 10          |
| social-following       | github:1000            | 12          |
| social-following       | *                      | 4           |
| wallet-control         | *                      | 2           |
| wallet-age             | 12                     | 6           |
| wallet-age             | 24                     | 10          |
| wallet-age             | 36                     | 13          |
| wallet-age             | 60                     | 16          |
| onchain-event          | eth2-genesis-depositor | 30          |
| onchain-event          | *                      | 10          |
| age-over-16..65 (each) | *                      | 25          |
| residency-country      | *                      | 10          |
| residency-state        | *                      | 14          |
| residency-city         | *                      | 16          |
| domain-control         | *                      | 10          |
| tlsn-attestation       | *                      | 10          |
| public-key             | *                      | 1           |
| invite-code            | *                      | 12          |

Seed a `*` row for EVERY registry type (`knownBadgeTypes()`), so the boot-check
passes. `age-over-*` is 10 distinct types (16,18,21,25,30,35,40,45,55,65) - seed
each at sybilWeight 25.

### 2.2 Recovery weights - `BadgeWeight.recoveryWeight` (from `recoveryWeightFor`)

Eligible types (the ONLY ones the recovery engine reads) - MUST match exactly:

- oauth-account: github/google/reddit/hackernews -> 20, discord/steam -> 10, `*` -> 20
- email-domain -> 15, email-exact -> 15
- tlsn-attestation -> 100 (allowSoloRecovery = **true**, the deliberate IAL3 solo path)

Non-eligible types (recovery column greyed in editor, never read by engine; seed
for table coherence from the `recoveryWeightFor` oracle = IAL fallback):

- age-over-*, residency-country/state/city -> 60 (IAL2)
- account-age, social-following, wallet-control, wallet-age, onchain-event,
  public-key, domain-control -> 15 (IAL1)
- invite-code -> 0 (IAL0)

allowSoloRecovery seeded `true` ONLY for `tlsn-attestation` (its weight 100 >=
threshold 100). Every other type MUST seed recoveryWeight < 100.

### 2.3 Categories + caps (design spec §3.3) - `SybilCategory`

| name            | cap | member types                                 |
| --------------- | --- | -------------------------------------------- |
| email           | 10  | email-domain, email-exact                    |
| social-oauth    | 30  | oauth-account, account-age, social-following |
| wallet          | 30  | wallet-control, wallet-age, onchain-event    |
| human-attribute | 40  | age-over-_, residency-_                      |
| domain          | 20  | domain-control                               |
| attestation     | 50  | tlsn-attestation, public-key                 |
| invite          | 15  | invite-code                                  |

Category membership is carried on each `BadgeWeight` row's `category` column
(every row for a type gets that type's category). The `SybilCategory` table holds
just name + cap.

### 2.4 Bucket cutoffs (design spec §3.4) - `SybilBucketConfig` singleton

`bucket1Raw=5, bucket2Raw=15, bucket3Raw=28, bucket4Raw=60, bucket3MinCats=2,
bucket4MinCats=3`.

### 2.5 Recovery threshold - `RecoveryConfig` singleton

`threshold=100` (= current `RECOVERY_THRESHOLD`).

Seeding runs from a script `apps/minister/scripts/seed-sybil-config.ts` (Prisma
`upsert` per row, idempotent, mirrors `seed-client.ts`). Call it from
`boot-migrate` AFTER `migrate deploy`, and expose `pnpm --filter @minister/app
sybil:seed`. Seeding is idempotent and must NOT clobber operator edits: upsert
`create`-only for the mutable weight columns (on conflict, leave existing values;
only insert missing rows). Rationale: re-running seed after an operator tuned a
weight must not reset it.

---

## 3. The pure scorer

File: `apps/minister/src/lib/sybil-score.ts`. Pure, no imports of prisma, never
throws.

```ts
export interface ScorableBadge {
  type: string;
  attributes: Record<string, unknown>;
  expiresAt: Date | null;
  issuer: string;
}
export interface SybilScoringConfig {
  weights: Map<string, Map<string, number>>; // type -> qualifier -> sybilWeight
  categoryByType: Map<string, string>; // type -> category name
  caps: Map<string, number>; // category -> cap
  cutoffs: { b1: number; b2: number; b3: number; b4: number; b3Cats: number; b4Cats: number };
}
export interface SybilScoreResult {
  raw: number;
  bucket: 0 | 1 | 2 | 3 | 4;
}
export function sybilScore(
  badges: ScorableBadge[],
  config: SybilScoringConfig,
  ctx: { now: number; nativeIssuerDid: string },
): SybilScoreResult;
```

Rule (design spec §3.2-§3.4):

1. Drop badges where `expiresAt && expiresAt.getTime() < ctx.now`, or
   `issuer !== ctx.nativeIssuerDid`.
2. Resolve each badge to `(type, qualifier)` via the **qualifier chain**, first
   hit wins:
   - `oauth-account`: `[provider, "*"]`
   - `account-age`: `[provider + ":" + olderThanMonths, provider, "*"]`
   - `wallet-age`: `[String(olderThanMonths), "*"]`
   - `social-following`: `[provider + ":" + followersAtLeast, provider, "*"]`
   - all others: `["*"]`
     Missing/unknown type -> weight 0 (contributes nothing; scorer does not throw).
     Attribute keys per type (from recon): oauth-account.provider,
     account-age.{provider,olderThanMonths}, social-following.{provider,followersAtLeast},
     wallet-age.{chain,olderThanMonths}, onchain-event.event, residency-*.{country,state,city},
     age-over-N.threshold, public-key.{kind,fingerprint}, domain-control.domain, tlsn.{domain,claim}.
3. Group resolved weights by category. **Family-collapse** before summing:
   all `age-over-*` collapse to their single max member; residency
   country<state<city collapse to one (max). (Both are auto-laddered / implied,
   so they are one proof.) Other types: each held badge is its own member.
4. **Geometric decay** per category on member weights sorted desc:
   `c = sum(floor(w_i / 2**i))` for i=0,1,2,...; then `c = min(c, cap)`.
5. Category **qualifies** iff `c >= 8`.
6. `raw = sum(c)`. Bucket: 4 if `raw>=b4 && qualifyingCats>=b4Cats`; else 3 if
   `raw>=b3 && qualifyingCats>=b3Cats`; else 2 if `raw>=b2`; else 1 if `raw>=b1`;
   else 0. (Highest bucket fully satisfied.)

Unit tests (`sybil-score.test.ts`) MUST cover every worked example in design spec
§3.7 (fresh->0, one email->1, invited+email->2, dev->2, dev+2nd root->3, free
farmer->2 ceiling, spending farmer->3), plus: expired badge excluded, non-native
issuer excluded, unknown type contributes 0, family-collapse of age-over ladder,
decay halving a second same-kind badge.

Boot-check: in `instrumentation.ts` (Node runtime only), after config load, assert
every `knownBadgeTypes()` has a `BadgeWeight` `*` row and every referenced
category exists. Prod: throw (fail-loud, mirrors the KMS/Signet boot-verify).
Dev: `console.warn`. Use a dynamic import so the edge bundle drops it.

Config loaders (`apps/minister/src/lib/sybil-config.ts`):

- `loadSybilScoringConfig()` -> `SybilScoringConfig`, cached ~60s (mirror
  `anonymity-sets.ts` cache shape). Reads BadgeWeight/SybilCategory/SybilBucketConfig.
- `recoveryWeightForLive(type, provenance)` -> `Promise<number>`, **uncached**
  (defensive edits must reflect instantly), resolves the qualifier chain
  (oauth-account -> `[provenance,"*"]`, else `["*"]`) and honors
  `pendingRecoveryWeight`/`recoveryEffectiveAt`.
- `loadEffectiveThreshold()` -> `Promise<number>`, uncached, honors
  `pendingThreshold`/`thresholdEffectiveAt`.

---

## 4. Disclosure wiring (design spec §4; recon map 2 has exact file:line)

- `oidc-config.ts`: add `"sybil-score"` to `scopes_supported`, `"sybil_bucket"`
  to `claims_supported`. Ensure `sybil-score` is an assignable client scope
  (appears in `allOidcScopes()` used by the client editor).
- `oidc-claims.ts`: add `sybilBucket?: number` to `ResolvedUserClaims`; add
  params `(sybilScoreGrant: boolean, sybilBucket: number | null)` to
  `resolveUserClaims`; emit `resolved.sybilBucket` ONLY when `sybilScoreGrant &&
sybilBucket !== null`. Stays pure/DB-free.
- `oidc-actions.ts` `approveConsent`: add `approveSybilScore: z.boolean()` to
  `ApproveInput`; `const sybilScoreRequested = request.scopes.includes("sybil-score");
const approveSybilScore = sybilScoreRequested && parsed.data.approveSybilScore;`.
  Compute the bucket ONCE before the tx: load the user's badges, score with
  `loadSybilScoringConfig()` + `{ now: Date.now(), nativeIssuerDid: (await
getIssuer()).did }`, set `sybilBucket`. On ANY failure: `sybilBucket = null`,
  audit `oidc.sybil_score_omitted`, login unaffected (fail-closed-omit). Persist
  `sybilScore: approveSybilScore, sybilBucket` on the auth code. Add
  `sybil-score` into `effectiveScopes` granted-scope logic (retain the scope iff
  approveSybilScore, mirroring `approveProfile`). Extend the consent audit
  metadata with `disclosedSybilScore` + `sybilBucket`.
- `oidc/token/route.ts`: pass `stored.sybilScore, stored.sybilBucket` to
  `resolveUserClaims`; add `sybil_bucket: userClaims.sybilBucket` to the
  `mintIdToken` payload (omit when undefined); denormalize `sybilScore` +
  `sybilBucket` onto the created `OidcAccessToken`.
- `mintIdToken` (wherever id-token claims are typed): allow optional
  `sybil_bucket?: number`.
- `oidc/userinfo/route.ts`: pass `row.sybilScore, row.sybilBucket`; add
  `if (resolved.sybilBucket !== undefined) claims.sybil_bucket = resolved.sybilBucket;`.
- `consent-screen.tsx`: add props `wantsSybilScore`, `sybilBucketPreview: number
| null`, `previouslySybilScore`; a checkbox card (mirror the profile card) with
  copy: heading "Account strength", body "Share your account-strength level:
  **{n} of 4**. This shows how hard your account is to fake. It does not reveal
  which badges you have." Default the checkbox to `wantsSybilScore &&
previouslySybilScore`; send `approveSybilScore` in the `approveConsent` call.
  (No live class-size hint in Phase 1 - fixed copy only.)
- `oidc/authorize/page.tsx`: `wantsSybilScore = request.scopes.includes("sybil-score");`
  compute `sybilBucketPreview` via the scorer (fail soft to null on error), pass
  the props + `previouslySybilScore: grant.sybilScore`.
- `docs/oidc-privacy.md`: add the ~2.3-bit note + "do not add resolution without
  re-review" (design spec §4.4).

---

## 5. Recovery migration + auth_time + guardrails (design spec §5.4)

- `recovery-threshold.ts:184`: replace `const weight = recoveryWeightFor(...)`
  with `const weight = await recoveryWeightForLive(badgeType, context.provenance);`.
  **Fail closed** on a config read error mid-recovery: abort the re-proof with a
  clear error, never default the weight to 0 or the seed.
- `startRecoveryAttempt`: default `requiredScore` from `await
loadEffectiveThreshold()` instead of the `RECOVERY_THRESHOLD` constant
  (constant stays as the seed + floor). Snapshot into the attempt as today.
- `auth.config.ts`: in `jwt()`, when `account` is present, set
  `token.auth_time = Math.floor(Date.now() / 1000)`. In `session()`, surface
  `session.auth_time = token.auth_time`. Add `auth_time?: number` to the JWT +
  Session type augmentations. (Refresh without `account` leaves it unchanged -
  intentional.)
- `session.ts`: add `requireAuthRecency(session, maxAgeSecs)` that throws
  `StepUpRequiredError(2, session.aal ?? 0)` when `auth_time` is missing or
  `now - auth_time > maxAgeSecs`. Recovery-config edits use `maxAgeSecs = 600`.
- Recovery guardrails (enforced in the recovery-config server actions, §5.4):
  - bounds: `recoveryWeight in [0,100]`, `threshold in [100,1000]`.
  - hard-block any single type's recoveryWeight `>= threshold` unless that row's
    `allowSoloRecovery` is true (seeded only for tlsn).
  - asymmetric apply: weight DECREASE / threshold INCREASE = immediate; weight
    INCREASE / threshold DECREASE = pending +72h (reuse `CREDENTIAL_QUARANTINE_MS`
    - verify its value is 72h; if not, define `RECOVERY_WEAKEN_DELAY_MS`).
  - `RECOVERY_ELIGIBLE_TYPES` stays in code (unchanged). Editor greys the recovery
    column for ineligible types.
  - every recovery-config change: `audit(...)` with before/after **and** email
    broadcast to all admins (`prisma.user.findMany({ where:{isAdmin:true} })` +
    loop `sendMail`). A weakening email says "takes effect in 72h".
  - parity test (`sybil-recovery-parity.test.ts`, pure): for every (type,
    provenance) in the seed, assert the seeded `recoveryWeight` equals
    `recoveryWeightFor(type, provenance)`; include the eligible set explicitly
    (oauth github/google/reddit/hackernews->20, discord/steam->10, undefined->20;
    email 15; tlsn 100) + non-eligible fallbacks (age/residency->60, IAL1->15,
    invite->0).

---

## 6. Admin editors (design spec §5.1-§5.4)

Follow the OIDC-client editor pattern exactly (recon map 4): a server component
page gated by `requireAdmin()`, a `"use client"` form with local state +
error/saved toast, a server action via the `adminAction(schema, handler)` wrapper
(validates, mutates, `audit`, `revalidatePath`).

- `/admin/sybil-score` (page + `admin-sybil-weights-form.tsx`): grouped-by-type
  weight rows with editable `sybilWeight` + a `category` dropdown + a per-type
  holder-count column (`holderCountsByType()`); a categories/caps sub-editor; a
  bucket-cutoffs sub-editor with a LIVE preview ("a user holding {github oauth +
  verified email} scores raw N -> bucket B" computed via the pure scorer). Server
  actions gate on `adminAction` only (immediate apply). Recovery column shown
  read-only here with a link to `/admin/recovery-config`.
- `/admin/recovery-config` (page + `admin-recovery-form.tsx`): editable
  `recoveryWeight` (greyed for non-`RECOVERY_ELIGIBLE_TYPES`), `allowSoloRecovery`
  toggle, `threshold`. Every server action: `requireAdmin` + `requireAal(session,
2)` + reject `session.recovered` + `requireAuthRecency(session, 600)` +
  bounds/solo checks + asymmetric apply + audit + admin-email broadcast. Surface a
  banner for any pending (delayed) change with its `effectiveAt`. Client uses the
  existing `withStepUp` pattern so a stale session triggers a passkey re-auth and
  retry.
- Add nav entries in `/admin/layout.tsx` / `/admin/page.tsx`.

---

## 7. Build unit decomposition (dependency order)

- **U0 Foundation** (this unit first, solo): schema + migration + seed script +
  `sybil-config.ts` loaders (`loadSybilScoringConfig`, `recoveryWeightForLive`,
  `loadEffectiveThreshold`) + boot-check + the pure parity test. Gate: migrate
  applies, typecheck, test, build all green.
- **U1 Scorer** (after U0 types exist): `sybil-score.ts` + full unit tests.
- **U2 Disclosure** (after U0+U1): §4 wiring end to end.
- **U3 Recovery+auth_time** (after U0): §5 wiring + guardrail primitives +
  parity test.
- **U4 Admin editors** (after U0+U1+U3): §6 two routes.
- **Verify**: multi-lens auditor fan-out on the four security seams (§4 snapshot,
  §5.4 recovery guardrails, auth_time, scorer) + full typecheck/test/build.

U2 and U4 touch mostly disjoint files (oidc-* vs admin-*) and may run
back-to-back; everything is reviewed before merge. Recovery/disclosure/auth code
is domain-floor - built by opus-tier agents, audited before merge.
