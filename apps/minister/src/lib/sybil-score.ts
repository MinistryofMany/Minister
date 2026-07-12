// The pure anti-sybil scorer (design spec §3.2-§3.4, impl brief §3). Given the
// badges a user HOLDS, a scoring config, and an injected context (clock + the
// native issuer DID), it produces a raw score and a coarse bucket (0-4).
//
// Contract: PURE (no prisma/network/date reads — `now` is injected), and it
// NEVER throws. An unknown type, a missing attribute, a missing config row, or a
// dangling category all degrade to a 0 contribution rather than an exception, so
// a partially-seeded config can only under-count, never crash the consent flow.
//
// The types (`ScorableBadge`, `SybilScoringConfig`, `SybilScoreResult`) live in
// `sybil-config.ts` (U0) so the loader and the scorer share one definition.

import type { ScorableBadge, SybilScoringConfig, SybilScoreResult } from "./sybil-config";

// The minimal row/cutoff shapes `buildSybilScoringConfig` folds. Every producer
// (the live BadgeWeight rows, the seed constants, the admin form's edited rows)
// is a structural superset of these.
interface WeightRowInput {
  badgeType: string;
  qualifier: string;
  sybilWeight: number;
  category: string;
}
interface CutoffInput {
  bucket1Raw: number;
  bucket2Raw: number;
  bucket3Raw: number;
  bucket4Raw: number;
  bucket3MinCats: number;
  bucket4MinCats: number;
}

/**
 * Fold weight rows + category caps + bucket cutoffs into the `SybilScoringConfig`
 * the pure scorer consumes. The single builder shared by `loadSybilScoringConfig`
 * (live DB rows), the sybil-score parity test (the seed constants), and the admin form's
 * live preview (edited rows) — so all three produce byte-identical config shapes.
 * Lives here (a prisma-free module) so the "use client" admin form can import it
 * without dragging the DB client into the browser bundle.
 */
export function buildSybilScoringConfig(
  weightRows: readonly WeightRowInput[],
  categories: readonly { name: string; cap: number }[],
  cutoffs: CutoffInput,
): SybilScoringConfig {
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
  for (const cat of categories) caps.set(cat.name, cat.cap);

  return {
    weights,
    categoryByType,
    caps,
    cutoffs: {
      b1: cutoffs.bucket1Raw,
      b2: cutoffs.bucket2Raw,
      b3: cutoffs.bucket3Raw,
      b4: cutoffs.bucket4Raw,
      b3Cats: cutoffs.bucket3MinCats,
      b4Cats: cutoffs.bucket4MinCats,
    },
  };
}

// A category qualifies (counts toward the breadth floor for buckets 3/4) once its
// decayed contribution reaches this floor. Design spec §3.4.
const CATEGORY_QUALIFY_THRESHOLD = 8;

// Resolve a held badge to its qualifier candidate chain (impl brief §3, design
// spec §3.2), most-specific first, always ending in "*". Attribute reads are
// defensive: a missing/ill-typed attribute simply drops that candidate so the
// chain falls back toward "*" (or, if even "*" is absent, weight 0) — never a
// throw. `attributes` mirrors `Badge.attributes` (denormalized display JSON),
// but at runtime it is unconstrained JSON: a null / non-object container is
// coerced to `{}` here so property access can never throw (the "never throws"
// contract) — such a badge just resolves to "*".
function qualifierChain(type: string, attributes: unknown): string[] {
  const attrs: Record<string, unknown> =
    attributes !== null && typeof attributes === "object"
      ? (attributes as Record<string, unknown>)
      : {};
  switch (type) {
    case "oauth-account": {
      const provider = attrs.provider;
      return typeof provider === "string" ? [provider, "*"] : ["*"];
    }
    case "account-age": {
      const provider = attrs.provider;
      const months = attrs.olderThanMonths;
      const chain: string[] = [];
      if (typeof provider === "string") {
        if (typeof months === "number" || typeof months === "string") {
          chain.push(`${provider}:${months}`);
        }
        chain.push(provider);
      }
      chain.push("*");
      return chain;
    }
    case "wallet-age": {
      const months = attrs.olderThanMonths;
      return typeof months === "number" || typeof months === "string"
        ? [String(months), "*"]
        : ["*"];
    }
    case "social-following": {
      const provider = attrs.provider;
      const followers = attrs.followersAtLeast;
      const chain: string[] = [];
      if (typeof provider === "string") {
        if (typeof followers === "number" || typeof followers === "string") {
          chain.push(`${provider}:${followers}`);
        }
        chain.push(provider);
      }
      chain.push("*");
      return chain;
    }
    default:
      return ["*"];
  }
}

// Resolve a badge's sybil weight: walk its qualifier chain, first configured row
// wins. Unknown type or no matching qualifier (not even "*") -> 0.
function weightFor(config: SybilScoringConfig, badge: ScorableBadge): number {
  const byQualifier = config.weights.get(badge.type);
  if (!byQualifier) return 0;
  for (const qualifier of qualifierChain(badge.type, badge.attributes)) {
    const weight = byQualifier.get(qualifier);
    if (weight !== undefined) return weight;
  }
  return 0;
}

// Family key for the pre-sum collapse (design spec §3.4 step 1). Fully-correlated
// ladders are one proof and collapse to their single max member: every `age-over-*`
// shares one key, every `residency-*` shares one key. Any other type is its own
// member, so `seq` makes each held badge distinct.
function familyKey(type: string, seq: number): string {
  if (type.startsWith("age-over-")) return "family:age-over";
  if (type.startsWith("residency-")) return "family:residency";
  return `single:${seq}`;
}

/**
 * Score the badges a user holds into a raw score + coarse bucket. Pure, offline,
 * never throws.
 *
 * @param badges the user's held badges (as denormalized `ScorableBadge`s).
 * @param config the scoring config (weights, categories, caps, bucket cutoffs).
 * @param ctx    injected context: `now` (unix ms, the expiry clock) and
 *               `nativeIssuerDid` (Minister's own DID — non-native VCs never buy
 *               bucket, mirroring the OIDC issuer scoping).
 */
export function sybilScore(
  badges: ScorableBadge[],
  config: SybilScoringConfig,
  ctx: { now: number; nativeIssuerDid: string },
): SybilScoreResult {
  // 1. Input hygiene (design spec §3.5): drop non-native-issuer and expired
  //    badges. An imported VC or a lapsed badge must never contribute.
  // 2 + 3. Group by category and family-collapse to per-family max BEFORE summing.
  //    perCategory: category -> (familyKey -> max member weight).
  const perCategory = new Map<string, Map<string, number>>();
  let memberSeq = 0;

  for (const badge of badges) {
    if (badge.issuer !== ctx.nativeIssuerDid) continue;
    if (badge.expiresAt && badge.expiresAt.getTime() < ctx.now) continue;

    const weight = weightFor(config, badge);
    if (weight <= 0) continue; // unknown type / unconfigured qualifier -> 0, contributes nothing

    const category = config.categoryByType.get(badge.type);
    if (category === undefined) continue; // dangling category -> no contribution (fail-closed)

    let families = perCategory.get(category);
    if (!families) {
      families = new Map<string, number>();
      perCategory.set(category, families);
    }
    const key = familyKey(badge.type, memberSeq);
    if (key.startsWith("single:")) memberSeq++;
    const prev = families.get(key);
    if (prev === undefined || weight > prev) families.set(key, weight);
  }

  // 4 + 5 + 6. Geometric decay per category, cap, qualify test, sum -> raw.
  let raw = 0;
  let qualifyingCats = 0;
  for (const [category, families] of perCategory) {
    const memberWeights = [...families.values()].sort((a, b) => b - a);
    let contribution = 0;
    memberWeights.forEach((w, i) => {
      contribution += Math.floor(w / 2 ** i);
    });
    // A missing cap is a seed bug the boot-check catches; treat it as uncapped
    // here so the scorer stays pure and never throws.
    const cap = config.caps.get(category) ?? Number.POSITIVE_INFINITY;
    contribution = Math.min(contribution, cap);
    raw += contribution;
    if (contribution >= CATEGORY_QUALIFY_THRESHOLD) qualifyingCats++;
  }

  const { b1, b2, b3, b4, b3Cats, b4Cats } = config.cutoffs;
  let bucket: 0 | 1 | 2 | 3 | 4;
  if (raw >= b4 && qualifyingCats >= b4Cats) bucket = 4;
  else if (raw >= b3 && qualifyingCats >= b3Cats) bucket = 3;
  else if (raw >= b2) bucket = 2;
  else if (raw >= b1) bucket = 1;
  else bucket = 0;

  return { raw, bucket };
}
