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
import {
  effectiveRecoveryThreshold,
  effectiveRecoveryWeight,
} from "@/lib/recovery-config-guardrails";

import { buildSybilScoringConfig } from "./sybil-score";

// Re-exported so the seed/config consumers (the loader here, the parity test)
// can import the pure builder from this module. It is defined in the prisma-free
// `sybil-score.ts` so the "use client" admin form can import it too, without
// pulling the DB client into the browser bundle.
export { buildSybilScoringConfig };

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
// Group membership is self-asserted and MUST NOT buy anti-sybil score; its own
// category exists (so the boot drift-check's category reference resolves) but
// caps at 0 and every row weighs 0 — a farmed roster earns nothing.
const CAT_GROUP = "group";

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

// Compact seed table: [badgeType, qualifier, sybilWeight, recoveryWeight,
// category]. Mapped once into BadgeWeightSeedRow below. Preserve every value
// EXACTLY — this feeds the DB seed and the sybil-score parity test.
type WeightTuple = readonly [
  badgeType: string,
  qualifier: string,
  sybilWeight: number,
  recoveryWeight: number,
  category: string,
];

const WEIGHT_TABLE: readonly WeightTuple[] = [
  // email (recovery 15 = IAL1 baseline)
  ["email-domain", "*", 5, 15, CAT_EMAIL],
  ["email-exact", "*", 5, 15, CAT_EMAIL],

  // oauth-account (recovery: github/google/reddit/hackernews/* -> 20, discord/steam -> 10)
  ["oauth-account", "github", 8, 20, CAT_SOCIAL_OAUTH],
  ["oauth-account", "google", 12, 20, CAT_SOCIAL_OAUTH],
  ["oauth-account", "discord", 4, 10, CAT_SOCIAL_OAUTH],
  ["oauth-account", "steam", 5, 10, CAT_SOCIAL_OAUTH],
  ["oauth-account", "reddit", 4, 20, CAT_SOCIAL_OAUTH],
  ["oauth-account", "hackernews", 4, 20, CAT_SOCIAL_OAUTH],
  ["oauth-account", "*", 4, 20, CAT_SOCIAL_OAUTH],

  // account-age (recovery 15 = IAL1; sybil varies by provider:months)
  ["account-age", "github:12", 10, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "github:24", 15, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "github:36", 18, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "github:60", 22, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "reddit:12", 6, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "reddit:24", 10, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "reddit:36", 12, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "reddit:60", 15, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "hackernews:12", 6, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "hackernews:24", 10, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "hackernews:36", 12, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "hackernews:60", 15, 15, CAT_SOCIAL_OAUTH],
  ["account-age", "*", 6, 15, CAT_SOCIAL_OAUTH],

  // social-following (recovery 15 = IAL1)
  ["social-following", "github:10", 4, 15, CAT_SOCIAL_OAUTH],
  ["social-following", "github:50", 6, 15, CAT_SOCIAL_OAUTH],
  ["social-following", "github:100", 8, 15, CAT_SOCIAL_OAUTH],
  ["social-following", "github:500", 10, 15, CAT_SOCIAL_OAUTH],
  ["social-following", "github:1000", 12, 15, CAT_SOCIAL_OAUTH],
  ["social-following", "*", 4, 15, CAT_SOCIAL_OAUTH],

  // wallet (recovery 15 = IAL1)
  ["wallet-control", "*", 2, 15, CAT_WALLET],
  ["wallet-age", "12", 6, 15, CAT_WALLET],
  ["wallet-age", "24", 10, 15, CAT_WALLET],
  ["wallet-age", "36", 13, 15, CAT_WALLET],
  ["wallet-age", "60", 16, 15, CAT_WALLET],
  // wallet-age `*`: the brief's §2.1 table lists only 12/24/36/60, but the
  // boot-check requires a `*` row for every registry type and the scorer chain
  // is [months, "*"]. Seed the conservative floor (the 12-month value).
  ["wallet-age", "*", 6, 15, CAT_WALLET],
  ["onchain-event", "eth2-genesis-depositor", 30, 15, CAT_WALLET],
  ["onchain-event", "*", 10, 15, CAT_WALLET],

  // human-attribute residency (recovery 60 = IAL2). age-over-* appended below.
  ["residency-country", "*", 10, 60, CAT_HUMAN_ATTRIBUTE],
  ["residency-state", "*", 14, 60, CAT_HUMAN_ATTRIBUTE],
  ["residency-city", "*", 16, 60, CAT_HUMAN_ATTRIBUTE],

  // domain (recovery 15 = IAL1)
  ["domain-control", "*", 10, 15, CAT_DOMAIN],

  // attestation. tlsn-attestation carries the deliberate IAL3 solo-recovery path.
  ["tlsn-attestation", "*", 10, 100, CAT_ATTESTATION],
  ["public-key", "*", 1, 15, CAT_ATTESTATION],

  // invite (recovery 0 = IAL0; proves nothing about a person)
  ["invite-code", "*", 12, 0, CAT_INVITE],

  // group membership: HARD sybilWeight 0 (self-asserted; a founder must not farm
  // score by adding sock-puppet members). recovery 0 too — proves nothing about
  // a person, and it is not recovery-eligible. Mirrors invite-code's IAL0 stance.
  ["group-membership", "*", 0, 0, CAT_GROUP],
];

// `allowSoloRecovery` is true ONLY for tlsn-attestation (its recovery weight
// 100 == threshold 100; every other row's recovery weight is < 100, so no other
// single type can solo-recover).
const SOLO_RECOVERY_TYPES = new Set<string>(["tlsn-attestation"]);

// The full BadgeWeight seed. EVERY `knownBadgeTypes()` type carries a `*` row
// (the boot-check asserts this).
export const SYBIL_BADGE_WEIGHT_SEED: readonly BadgeWeightSeedRow[] = [
  ...WEIGHT_TABLE.map(
    ([badgeType, qualifier, sybilWeight, recoveryWeight, category]): BadgeWeightSeedRow => ({
      badgeType,
      qualifier,
      sybilWeight,
      recoveryWeight,
      category,
      allowSoloRecovery: SOLO_RECOVERY_TYPES.has(badgeType),
    }),
  ),
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
  // Caps at 0: the group category can never contribute to the sybil score,
  // whatever weight rows land in it.
  { name: CAT_GROUP, cap: 0 },
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

// Group founding knobs singleton (docs/groups-design.md). Seeded like the other
// singletons; the founding action reads them via `loadGroupConfig` rather than
// hardcoding, so an operator can retune the gate without a deploy.
export const GROUP_CONFIG_SEED = {
  id: "singleton",
  foundingMinBucket: 2,
  maxOwnedGroups: 3,
} as const;

export interface GroupConfigValues {
  foundingMinBucket: number;
  maxOwnedGroups: number;
}

// Live group config, read fresh (the gate is coarse and infrequent — no cache
// needed). Fails CLOSED: an absent singleton throws so the founding action can
// block rather than silently fall back to a default bucket floor.
export async function loadGroupConfig(): Promise<GroupConfigValues> {
  const cfg = await prisma.groupConfig.findUnique({ where: { id: "singleton" } });
  if (!cfg)
    throw new Error(
      "GroupConfig singleton row is absent: group config is not seeded. Failing closed.",
    );
  return { foundingMinBucket: cfg.foundingMinBucket, maxOwnedGroups: cfg.maxOwnedGroups };
}

// A missing config row mid-recovery must fail closed (throw), not silently
// return 0 — see impl brief §3, §5. The caller in U3 catches the throw
// generically to abort the re-proof rather than under-weighting recovery.

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

  if (!bucket)
    throw new Error(
      "SybilBucketConfig singleton row is absent: sybil config is not seeded. Failing closed.",
    );

  const value = buildSybilScoringConfig(weightRows, categoryRows, bucket);

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

/**
 * Live effective recovery weight for a (type, provenance), read fresh (never
 * cached). Resolves the qualifier chain and honors the row's delayed-apply
 * window (through the SAME `effectiveRecoveryWeight` helper the recovery-config
 * editor uses). Fails CLOSED: if not even a `*` row exists, throws rather than
 * returning 0 — U3 catches it to abort the re-proof, never under-counting
 * recovery.
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
  throw new Error(
    `No BadgeWeight recovery row for type=${type} provenance=${provenance ?? "(none)"}: ` +
      "sybil config is incomplete (not even a `*` row). Refusing to under-weight recovery.",
  );
}

// ---------------------------------------------------------------------------
// loadEffectiveThreshold — UNCACHED. Honors the RecoveryConfig singleton's
// delayed-apply (a threshold DECREASE is a weakening; it only takes effect once
// its effectiveAt has passed).
// ---------------------------------------------------------------------------

/**
 * Live effective recovery threshold, read fresh (never cached). Resolves the
 * delayed-apply window through the SAME `effectiveRecoveryThreshold` helper the
 * recovery-config editor uses. Fails CLOSED if the singleton is absent (throws).
 *
 * @param now injectable clock (unix ms) for deterministic tests.
 */
export async function loadEffectiveThreshold(now: number = Date.now()): Promise<number> {
  const cfg = await prisma.recoveryConfig.findUnique({ where: { id: "singleton" } });
  if (!cfg)
    throw new Error(
      "RecoveryConfig singleton row is absent: sybil config is not seeded. Failing closed.",
    );
  return effectiveRecoveryThreshold(cfg, now);
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
