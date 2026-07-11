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

// A category qualifies (counts toward the breadth floor for buckets 3/4) once its
// decayed contribution reaches this floor. Design spec §3.4.
const CATEGORY_QUALIFY_THRESHOLD = 8;

// Resolve a held badge to its qualifier candidate chain (impl brief §3, design
// spec §3.2), most-specific first, always ending in "*". Attribute reads are
// defensive: a missing/ill-typed attribute simply drops that candidate so the
// chain falls back toward "*" (or, if even "*" is absent, weight 0) — never a
// throw. `attributes` mirrors `Badge.attributes` (denormalized display JSON).
function qualifierChain(type: string, attributes: Record<string, unknown>): string[] {
  switch (type) {
    case "oauth-account": {
      const provider = attributes.provider;
      return typeof provider === "string" ? [provider, "*"] : ["*"];
    }
    case "account-age": {
      const provider = attributes.provider;
      const months = attributes.olderThanMonths;
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
      const months = attributes.olderThanMonths;
      return typeof months === "number" || typeof months === "string"
        ? [String(months), "*"]
        : ["*"];
    }
    case "social-following": {
      const provider = attributes.provider;
      const followers = attributes.followersAtLeast;
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
