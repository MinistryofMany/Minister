// Anti-sybil score + recovery-weight configuration: the pure seed constants,
// the shared scorer types (U1 imports these), and the live config loaders.
//
// Two threat models share these rows but must never be conflated:
//   * `sybilWeight`    — cost to farm a credential as a fake human; feeds ONLY
//                         the RP-facing anti-sybil score.
//   * `recoveryWeight` — contribution to the account-recovery threshold; a live
//                         migration of the constants in `assurance.ts`
//                         (`recoveryWeightFor` stays the pure oracle + parity
//                         source of truth — see sybil-recovery-parity.test.ts).
//
// See docs/specs/2026-07-11-anti-sybil-score-and-badge-stats.md (design) and
// docs/specs/2026-07-11-anti-sybil-phase1-implementation.md (§1-§3, the contract).

import { AGE_THRESHOLDS, knownBadgeTypes } from "@minister/shared";

import { prisma } from "@/lib/prisma";

// ---------------------------------------------------------------------------
// Shared scorer types (design/impl brief §3). Kept here so U0 is self-contained
// and the U1 scorer (`sybil-score.ts`) imports them rather than redeclaring.
// ---------------------------------------------------------------------------

// A held badge as the scorer sees it. `attributes` mirrors `Badge.attributes`
// (denormalized display JSON); `issuer` and `expiresAt` drive input hygiene
// (native-issuer + unexpired) inside the pure scorer.
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

// ---------------------------------------------------------------------------
// Seed constants (impl brief §2). Pure, exported. These are hand-specified
// literals, NOT computed from `recoveryWeightFor`: the parity test asserts the
// two agree, which is only meaningful when they are independent transcriptions.
// ---------------------------------------------------------------------------

export interface BadgeWeightSeedRow {
  badgeType: string;
  qualifier: string; // "*" or a resolved qualifier token (e.g. "github", "github:24")
  sybilWeight: number;
  recoveryWeight: number;
  category: string;
  allowSoloRecovery: boolean;
}

// Category names (impl brief §2.3). Kept as a const map for the seed rows.
const CAT_EMAIL = "email";
const CAT_SOCIAL_OAUTH = "social-oauth";
const CAT_WALLET = "wallet";
const CAT_HUMAN_ATTRIBUTE = "human-attribute";
const CAT_DOMAIN = "domain";
const CAT_ATTESTATION = "attestation";
const CAT_INVITE = "invite";

// The ten `age-over-N` types are fully uniform (sybil 25, recovery 60 = IAL2,
// human-attribute, no solo). Generate from the shared registry's threshold list
// so a new threshold cannot drift the seed away from the boot-check's
// `knownBadgeTypes()`.
const AGE_OVER_SEED_ROWS: BadgeWeightSeedRow[] = AGE_THRESHOLDS.map((t) => ({
  badgeType: `age-over-${t}`,
  qualifier: "*",
  sybilWeight: 25,
  recoveryWeight: 60,
  category: CAT_HUMAN_ATTRIBUTE,
  allowSoloRecovery: false,
}));

// The full BadgeWeight seed. EVERY `knownBadgeTypes()` type carries a `*` row
// (the boot-check asserts this). `allowSoloRecovery` is true ONLY for
// tlsn-attestation (its recovery weight 100 == threshold 100; every other row's
// recovery weight is < 100, so no other single type can solo-recover).
export const SYBIL_BADGE_WEIGHT_SEED: readonly BadgeWeightSeedRow[] = [
  // email (recovery 15 = IAL1 baseline)
  {
    badgeType: "email-domain",
    qualifier: "*",
    sybilWeight: 5,
    recoveryWeight: 15,
    category: CAT_EMAIL,
    allowSoloRecovery: false,
  },
  {
    badgeType: "email-exact",
    qualifier: "*",
    sybilWeight: 5,
    recoveryWeight: 15,
    category: CAT_EMAIL,
    allowSoloRecovery: false,
  },

  // oauth-account (recovery: github/google/reddit/hackernews/* -> 20, discord/steam -> 10)
  {
    badgeType: "oauth-account",
    qualifier: "github",
    sybilWeight: 8,
    recoveryWeight: 20,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "google",
    sybilWeight: 12,
    recoveryWeight: 20,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "discord",
    sybilWeight: 4,
    recoveryWeight: 10,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "steam",
    sybilWeight: 5,
    recoveryWeight: 10,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "reddit",
    sybilWeight: 4,
    recoveryWeight: 20,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "hackernews",
    sybilWeight: 4,
    recoveryWeight: 20,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "oauth-account",
    qualifier: "*",
    sybilWeight: 4,
    recoveryWeight: 20,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },

  // account-age (recovery 15 = IAL1; sybil varies by provider:months)
  {
    badgeType: "account-age",
    qualifier: "github:12",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "github:24",
    sybilWeight: 15,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "github:36",
    sybilWeight: 18,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "github:60",
    sybilWeight: 22,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "reddit:12",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "reddit:24",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "reddit:36",
    sybilWeight: 12,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "reddit:60",
    sybilWeight: 15,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "hackernews:12",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "hackernews:24",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "hackernews:36",
    sybilWeight: 12,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "hackernews:60",
    sybilWeight: 15,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "account-age",
    qualifier: "*",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },

  // social-following (recovery 15 = IAL1)
  {
    badgeType: "social-following",
    qualifier: "github:10",
    sybilWeight: 4,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "social-following",
    qualifier: "github:50",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "social-following",
    qualifier: "github:100",
    sybilWeight: 8,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "social-following",
    qualifier: "github:500",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "social-following",
    qualifier: "github:1000",
    sybilWeight: 12,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },
  {
    badgeType: "social-following",
    qualifier: "*",
    sybilWeight: 4,
    recoveryWeight: 15,
    category: CAT_SOCIAL_OAUTH,
    allowSoloRecovery: false,
  },

  // wallet (recovery 15 = IAL1)
  {
    badgeType: "wallet-control",
    qualifier: "*",
    sybilWeight: 2,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "wallet-age",
    qualifier: "12",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "wallet-age",
    qualifier: "24",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "wallet-age",
    qualifier: "36",
    sybilWeight: 13,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "wallet-age",
    qualifier: "60",
    sybilWeight: 16,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  // wallet-age `*`: the brief's §2.1 table lists only 12/24/36/60, but the
  // boot-check requires a `*` row for every registry type and the scorer chain
  // is [months, "*"]. Seed the conservative floor (the 12-month value).
  {
    badgeType: "wallet-age",
    qualifier: "*",
    sybilWeight: 6,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "onchain-event",
    qualifier: "eth2-genesis-depositor",
    sybilWeight: 30,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },
  {
    badgeType: "onchain-event",
    qualifier: "*",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_WALLET,
    allowSoloRecovery: false,
  },

  // human-attribute residency (recovery 60 = IAL2). age-over-* appended below.
  {
    badgeType: "residency-country",
    qualifier: "*",
    sybilWeight: 10,
    recoveryWeight: 60,
    category: CAT_HUMAN_ATTRIBUTE,
    allowSoloRecovery: false,
  },
  {
    badgeType: "residency-state",
    qualifier: "*",
    sybilWeight: 14,
    recoveryWeight: 60,
    category: CAT_HUMAN_ATTRIBUTE,
    allowSoloRecovery: false,
  },
  {
    badgeType: "residency-city",
    qualifier: "*",
    sybilWeight: 16,
    recoveryWeight: 60,
    category: CAT_HUMAN_ATTRIBUTE,
    allowSoloRecovery: false,
  },

  // domain (recovery 15 = IAL1)
  {
    badgeType: "domain-control",
    qualifier: "*",
    sybilWeight: 10,
    recoveryWeight: 15,
    category: CAT_DOMAIN,
    allowSoloRecovery: false,
  },

  // attestation. tlsn-attestation carries the deliberate IAL3 solo-recovery path.
  {
    badgeType: "tlsn-attestation",
    qualifier: "*",
    sybilWeight: 10,
    recoveryWeight: 100,
    category: CAT_ATTESTATION,
    allowSoloRecovery: true,
  },
  {
    badgeType: "public-key",
    qualifier: "*",
    sybilWeight: 1,
    recoveryWeight: 15,
    category: CAT_ATTESTATION,
    allowSoloRecovery: false,
  },

  // invite (recovery 0 = IAL0; proves nothing about a person)
  {
    badgeType: "invite-code",
    qualifier: "*",
    sybilWeight: 12,
    recoveryWeight: 0,
    category: CAT_INVITE,
    allowSoloRecovery: false,
  },

  ...AGE_OVER_SEED_ROWS,
];

export interface SybilCategorySeedRow {
  name: string;
  cap: number;
}

// Category caps (impl brief §2.3).
export const SYBIL_CATEGORY_SEED: readonly SybilCategorySeedRow[] = [
  { name: CAT_EMAIL, cap: 10 },
  { name: CAT_SOCIAL_OAUTH, cap: 30 },
  { name: CAT_WALLET, cap: 30 },
  { name: CAT_HUMAN_ATTRIBUTE, cap: 40 },
  { name: CAT_DOMAIN, cap: 20 },
  { name: CAT_ATTESTATION, cap: 50 },
  { name: CAT_INVITE, cap: 15 },
];

// Bucket cutoffs singleton (impl brief §2.4).
export const SYBIL_BUCKET_CONFIG_SEED = {
  id: "singleton",
  bucket1Raw: 5,
  bucket2Raw: 15,
  bucket3Raw: 28,
  bucket4Raw: 60,
  bucket3MinCats: 2,
  bucket4MinCats: 3,
} as const;

// Recovery threshold singleton (impl brief §2.5) — equals the current
// `RECOVERY_THRESHOLD` constant; the seed keeps behavior identical.
export const RECOVERY_CONFIG_SEED = {
  id: "singleton",
  threshold: 100,
} as const;

// ---------------------------------------------------------------------------
// Typed errors. A missing config row mid-recovery must fail closed (throw), not
// silently return 0 — see impl brief §3, §5. The caller in U3 catches these to
// abort the re-proof rather than under-weighting recovery.
// ---------------------------------------------------------------------------

export class MissingRecoveryWeightError extends Error {
  constructor(
    readonly badgeType: string,
    readonly provenance?: string,
  ) {
    super(
      `No BadgeWeight recovery row for type=${badgeType} provenance=${provenance ?? "(none)"}: ` +
        "sybil config is incomplete (not even a `*` row). Refusing to under-weight recovery.",
    );
    this.name = "MissingRecoveryWeightError";
  }
}

export class MissingRecoveryConfigError extends Error {
  constructor() {
    super("RecoveryConfig singleton row is absent: sybil config is not seeded. Failing closed.");
    this.name = "MissingRecoveryConfigError";
  }
}

export class MissingSybilBucketConfigError extends Error {
  constructor() {
    super("SybilBucketConfig singleton row is absent: sybil config is not seeded. Failing closed.");
    this.name = "MissingSybilBucketConfigError";
  }
}

// ---------------------------------------------------------------------------
// loadSybilScoringConfig — module-scoped ~60s cache (mirrors anonymity-sets.ts).
// ---------------------------------------------------------------------------

const CONFIG_CACHE_TTL_MS = 60_000;

interface ConfigCacheEntry {
  value: SybilScoringConfig;
  expiresAt: number;
}

// Module-scoped, process-local (mirrors anonymity-sets.ts). Staleness never
// affects correctness — the scorer re-reads within one TTL and disclosure is
// snapshotted at consent regardless.
let configCache: ConfigCacheEntry | null = null;

/**
 * Load the scorer config (BadgeWeight + SybilCategory + SybilBucketConfig),
 * cached in-process for ~60s. The returned object is treated as read-only by
 * the pure scorer; it is not deep-copied per call.
 *
 * @param now injectable clock (unix ms) for deterministic tests.
 */
export async function loadSybilScoringConfig(
  now: number = Date.now(),
): Promise<SybilScoringConfig> {
  if (configCache && now < configCache.expiresAt) return configCache.value;

  const [weightRows, categoryRows, bucket] = await Promise.all([
    prisma.badgeWeight.findMany(),
    prisma.sybilCategory.findMany(),
    prisma.sybilBucketConfig.findUnique({ where: { id: "singleton" } }),
  ]);

  if (!bucket) throw new MissingSybilBucketConfigError();

  const weights = new Map<string, Map<string, number>>();
  const categoryByType = new Map<string, string>();
  for (const row of weightRows) {
    let byQual = weights.get(row.badgeType);
    if (!byQual) {
      byQual = new Map<string, number>();
      weights.set(row.badgeType, byQual);
    }
    byQual.set(row.qualifier, row.sybilWeight);
    // Every row of a type shares its category; last write wins (all equal).
    categoryByType.set(row.badgeType, row.category);
  }

  const caps = new Map<string, number>();
  for (const cat of categoryRows) caps.set(cat.name, cat.cap);

  const value: SybilScoringConfig = {
    weights,
    categoryByType,
    caps,
    cutoffs: {
      b1: bucket.bucket1Raw,
      b2: bucket.bucket2Raw,
      b3: bucket.bucket3Raw,
      b4: bucket.bucket4Raw,
      b3Cats: bucket.bucket3MinCats,
      b4Cats: bucket.bucket4MinCats,
    },
  };

  configCache = { value, expiresAt: now + CONFIG_CACHE_TTL_MS };
  return value;
}

/** Drop the cached scorer config. Test-only; production relies on TTL expiry. */
export function __clearSybilConfigCache(): void {
  configCache = null;
}

// ---------------------------------------------------------------------------
// recoveryWeightForLive — UNCACHED. A defensive weight cut (an emergency
// weakening's inverse) must reflect on the very next re-proof, so this always
// reads the live row. Honors the delayed-apply window on the row.
// ---------------------------------------------------------------------------

// Qualifier candidate chain for RECOVERY resolution (impl brief §3). Recovery
// only distinguishes oauth-account by provenance; every other type resolves to
// its single `*` row.
function recoveryQualifierChain(type: string, provenance?: string): string[] {
  if (type === "oauth-account") return provenance ? [provenance, "*"] : ["*"];
  return ["*"];
}

interface RecoveryWeightRow {
  recoveryWeight: number;
  pendingRecoveryWeight: number | null;
  recoveryEffectiveAt: Date | null;
}

// Effective recovery weight honoring delayed-apply: a pending (weakening)
// weight only takes effect once its effectiveAt has passed.
function effectiveRecoveryWeight(row: RecoveryWeightRow, now: number): number {
  if (
    row.pendingRecoveryWeight != null &&
    row.recoveryEffectiveAt != null &&
    row.recoveryEffectiveAt.getTime() <= now
  ) {
    return row.pendingRecoveryWeight;
  }
  return row.recoveryWeight;
}

/**
 * Live effective recovery weight for a (type, provenance), read fresh (never
 * cached). Resolves the qualifier chain and honors the row's delayed-apply
 * window. Fails CLOSED: if not even a `*` row exists, throws
 * `MissingRecoveryWeightError` rather than returning 0 — U3 catches it to abort
 * the re-proof, never under-counting recovery.
 *
 * @param now injectable clock (unix ms) for deterministic tests.
 */
export async function recoveryWeightForLive(
  type: string,
  provenance?: string,
  now: number = Date.now(),
): Promise<number> {
  const rows = await prisma.badgeWeight.findMany({
    where: { badgeType: type },
    select: {
      qualifier: true,
      recoveryWeight: true,
      pendingRecoveryWeight: true,
      recoveryEffectiveAt: true,
    },
  });
  const byQual = new Map(rows.map((r) => [r.qualifier, r]));

  // The chain always ends in "*", so this both resolves the specific qualifier
  // and falls back to the `*` row before giving up.
  for (const qualifier of recoveryQualifierChain(type, provenance)) {
    const row = byQual.get(qualifier);
    if (row) return effectiveRecoveryWeight(row, now);
  }
  throw new MissingRecoveryWeightError(type, provenance);
}

// ---------------------------------------------------------------------------
// loadEffectiveThreshold — UNCACHED. Honors the RecoveryConfig singleton's
// delayed-apply (a threshold DECREASE is a weakening; it only takes effect once
// its effectiveAt has passed).
// ---------------------------------------------------------------------------

/**
 * Live effective recovery threshold, read fresh (never cached). Fails CLOSED if
 * the singleton is absent (throws `MissingRecoveryConfigError`).
 *
 * @param now injectable clock (unix ms) for deterministic tests.
 */
export async function loadEffectiveThreshold(now: number = Date.now()): Promise<number> {
  const cfg = await prisma.recoveryConfig.findUnique({ where: { id: "singleton" } });
  if (!cfg) throw new MissingRecoveryConfigError();
  if (
    cfg.pendingThreshold != null &&
    cfg.thresholdEffectiveAt != null &&
    cfg.thresholdEffectiveAt.getTime() <= now
  ) {
    return cfg.pendingThreshold;
  }
  return cfg.threshold;
}

// ---------------------------------------------------------------------------
// Boot-time integrity check (impl brief §3, §5). Queries the live config and
// reports drift; DB errors PROPAGATE so the caller (instrumentation.ts) can
// treat a transient outage differently from genuine drift (fail-closed on drift
// in prod, tolerate an outage — mirroring the Signet boot-verify).
// ---------------------------------------------------------------------------

export interface SybilConfigDrift {
  // Registry types with no `*` BadgeWeight row (the scorer would silently
  // contribute 0 for them; recovery would fail closed).
  missingStarRows: string[];
  // BadgeWeight rows whose `category` has no matching SybilCategory.
  danglingCategories: string[];
  // Absent singleton config rows. A partial seed can insert weights + categories
  // while the SybilBucketConfig / RecoveryConfig singleton upserts never land;
  // loadSybilScoringConfig / loadEffectiveThreshold then throw deep inside a
  // request (disclosure omitted, recovery aborted) with no boot signal. Names:
  // "SybilBucketConfig" and/or "RecoveryConfig".
  missingSingletons: string[];
}

/**
 * Assert every `knownBadgeTypes()` has a `*` BadgeWeight row, every referenced
 * category exists, and both singleton config rows (SybilBucketConfig,
 * RecoveryConfig) are present. Returns the drift found (empty = clean). DB/query
 * errors are NOT caught here — they propagate to the caller (a MISSING config
 * table surfaces as a Prisma schema error, which instrumentation.ts fails closed
 * on in prod; a transient connection error it defers).
 */
export async function checkSybilConfigDrift(): Promise<SybilConfigDrift> {
  const [weightRows, categoryRows, bucketSingleton, recoverySingleton] = await Promise.all([
    prisma.badgeWeight.findMany({ select: { badgeType: true, qualifier: true, category: true } }),
    prisma.sybilCategory.findMany({ select: { name: true } }),
    prisma.sybilBucketConfig.findUnique({ where: { id: "singleton" }, select: { id: true } }),
    prisma.recoveryConfig.findUnique({ where: { id: "singleton" }, select: { id: true } }),
  ]);

  const starTypes = new Set<string>();
  const referencedCategories = new Set<string>();
  for (const row of weightRows) {
    if (row.qualifier === "*") starTypes.add(row.badgeType);
    referencedCategories.add(row.category);
  }
  const categoryNames = new Set(categoryRows.map((c) => c.name));

  const missingStarRows = knownBadgeTypes()
    .filter((t) => !starTypes.has(t))
    .sort();
  const danglingCategories = [...referencedCategories].filter((c) => !categoryNames.has(c)).sort();

  const missingSingletons: string[] = [];
  if (!bucketSingleton) missingSingletons.push("SybilBucketConfig");
  if (!recoverySingleton) missingSingletons.push("RecoveryConfig");

  return { missingStarRows, danglingCategories, missingSingletons };
}
