import { prisma } from "@/lib/prisma";

// Per-badge-type anonymity-set size: how many DISTINCT Minister users
// hold a badge of a given type. A larger holder count means disclosing
// that type is less identifying. This datum drives Phase-2 OR/threshold
// badge selection (pick the satisfying subset with the largest anonymity
// sets) and is used SERVER-SIDE ONLY to rank choices — never per-user,
// never exposed as a raw integer to the relying party or the id_token.
//
// A user can hold multiple badges of one type (the Badge table has no
// per-type uniqueness — see prisma/schema.prisma model Badge), so the
// holder count is COUNT(DISTINCT userId), not a row count. Prisma's
// groupBy cannot express COUNT(DISTINCT col), so this is a raw query.

// How long a computed snapshot is reused before recompute. The count
// only moves as badges are issued/deleted (slow), and staleness never
// affects correctness — the admission gate re-evaluates the full policy
// downstream regardless — so a short TTL keeps the consent path cheap
// without any per-user cost. Mirrors the in-process cache pattern used
// elsewhere (rate-limit sliding window, SDK discovery/JWKS caches).
const CACHE_TTL_MS = 60_000;

interface CacheEntry {
  value: Map<string, number>;
  expiresAt: number;
}

// Module-scoped, process-local. Survives between requests within one
// server process; not shared across processes (which is fine — each
// process converges to the same aggregate within one TTL).
let cache: CacheEntry | null = null;

interface HolderCountRow {
  type: string;
  // Postgres COUNT() returns bigint, which the pg driver surfaces as a
  // JS bigint through Prisma's $queryRaw. Normalize to number below.
  holders: bigint;
}

async function queryHolderCounts(): Promise<Map<string, number>> {
  const rows = await prisma.$queryRaw<HolderCountRow[]>`
    SELECT "type", COUNT(DISTINCT "userId") AS holders
    FROM "Badge"
    GROUP BY "type"
  `;
  const map = new Map<string, number>();
  for (const row of rows) {
    map.set(row.type, Number(row.holders));
  }
  return map;
}

/**
 * Distinct-holder count per badge type, cached in-process for ~60s.
 * The returned map is the live cached instance — callers must treat it
 * as read-only.
 *
 * @param now injectable clock (unix ms) for deterministic tests.
 */
export async function holderCountsByType(now: number = Date.now()): Promise<Map<string, number>> {
  if (cache && now < cache.expiresAt) {
    return cache.value;
  }
  const value = await queryHolderCounts();
  cache = { value, expiresAt: now + CACHE_TTL_MS };
  return value;
}

/** Drop the cached snapshot. Test-only; production relies on TTL expiry. */
export function __clearHolderCountCache(): void {
  cache = null;
}
