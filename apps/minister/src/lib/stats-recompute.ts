// Badge-statistics recompute (design spec §7, phase-2 impl brief §4). Rebuilds
// the materialized stats tables the admin + public pages read: `BadgeStat`
// (per-type totals + allowlisted attribute distributions), `CohortStat`
// (operator-defined numerator/denominator counts), and `BucketStat` (the
// distribution of users across the 0-4 anti-sybil buckets), then stamps the
// `StatsRun` singleton.
//
// All counts are DISTINCT NATIVE, UNEXPIRED holders (issuer = Minister's own
// DID; expiry honored) — the exact hygiene the scorer applies (design spec §1).
//
// Runs inside ONE interactive transaction for a consistent snapshot. The
// scheduled entry point (`runScheduledStatsRecompute`) additionally takes a
// Postgres advisory lock under a key DISTINCT from the recovery-config lock, so a
// second app instance no-ops; the script + admin action call `recomputeAllStats`
// directly (the escape hatch, no lock).

import { knownBadgeTypes } from "@minister/shared";

import { Prisma } from "@/generated/prisma";
import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";
import { countCohortSide, safeParseCohortFilter } from "@/lib/cohort-filter";
import { allowlistedTypeKeyPairs, isAllowlistedValue } from "@/lib/stats-allowlist";
import type { ScorableBadge } from "@/lib/sybil-config";
import { loadSybilScoringConfig } from "@/lib/sybil-config";
import { sybilScore } from "@/lib/sybil-score";

// Fixed 64-bit key for the stats advisory lock. DISTINCT from the recovery-config
// lock (4823710192837n, recovery-config-actions.ts): the two subsystems must
// never contend, and a shared key would let a stats run block a recovery-config
// edit (and vice versa). Any distinct constant works.
export const STATS_ADVISORY_LOCK_KEY = 8273451906123n;

// The interactive-transaction budget for a full recompute. Scoring every user is
// the heavy step; a generous ceiling keeps a large instance's scheduled run from
// tripping Prisma's default 5s interactive-tx timeout. maxWait bounds only the
// time spent acquiring a pooled connection.
const STATS_TX_TIMEOUT_MS = 5 * 60_000;
const STATS_TX_MAX_WAIT_MS = 10_000;

// Users are scored in batches to bound memory on a large instance.
const USER_BATCH_SIZE = 500;

// The five buckets (0-4) always materialize a row, even at count 0, so the
// consumers see a complete distribution.
const BUCKETS = [0, 1, 2, 3, 4] as const;

type Tx = Prisma.TransactionClient;

interface AttrCountRow {
  value: string | null;
  count: bigint;
}
interface TypeCountRow {
  type: string;
  count: bigint;
}

// ---------------------------------------------------------------------------
// BadgeStat: per-type totals + allowlisted attribute distributions
// ---------------------------------------------------------------------------

async function recomputeBadgeStats(tx: Tx, native: string, now: Date): Promise<void> {
  const known = new Set(knownBadgeTypes());
  const rows: Prisma.BadgeStatCreateManyInput[] = [];

  // Per-type totals (attributeKey/Value = ""), one grouped query. Only registry
  // types are published — an unknown slug lingering in the table is skipped.
  const typeTotals = await tx.$queryRaw<TypeCountRow[]>(Prisma.sql`
    SELECT "type", COUNT(DISTINCT "userId")::bigint AS count
    FROM "Badge"
    WHERE "issuer" = ${native} AND ("expiresAt" IS NULL OR "expiresAt" > ${now})
    GROUP BY "type"
  `);
  for (const row of typeTotals) {
    if (!known.has(row.type)) continue;
    rows.push({
      badgeType: row.type,
      attributeKey: "",
      attributeValue: "",
      count: Number(row.count),
      computedAt: now,
    });
  }

  // Per allowlisted (type, key): distinct-holder count grouped by value. The key
  // is a bound parameter (jsonb ->> text), never interpolated; the (type, key)
  // pairs come only from the code-owned allowlist.
  for (const { type, key } of allowlistedTypeKeyPairs()) {
    // GROUP BY 1 (the first SELECT column) rather than repeating the
    // `"attributes"->>$key` expression: a parameterized key yields a DIFFERENT
    // placeholder in the GROUP BY than in the SELECT, so Postgres would not
    // recognize them as the same grouped expression (error 42803). The ordinal
    // reference sidesteps that while keeping the key a bound parameter.
    const dist = await tx.$queryRaw<AttrCountRow[]>(Prisma.sql`
      SELECT "attributes"->>${key} AS value, COUNT(DISTINCT "userId")::bigint AS count
      FROM "Badge"
      WHERE "type" = ${type}
        AND "issuer" = ${native} AND ("expiresAt" IS NULL OR "expiresAt" > ${now})
        AND "attributes"->>${key} IS NOT NULL
      GROUP BY 1
    `);
    for (const row of dist) {
      if (row.value === null) continue;
      // Close the VALUE space, not just the key: Badge.attributes is stored
      // verbatim (unvalidated), so an out-of-domain value (e.g. a free-text
      // provider) is DROPPED here and never materialized.
      if (!isAllowlistedValue(type, key, row.value)) continue;
      rows.push({
        badgeType: type,
        attributeKey: key,
        attributeValue: row.value,
        count: Number(row.count),
        computedAt: now,
      });
    }
  }

  await tx.badgeStat.deleteMany({});
  if (rows.length > 0) await tx.badgeStat.createMany({ data: rows });
}

// ---------------------------------------------------------------------------
// CohortStat: per-def numerator/denominator distinct-user counts
// ---------------------------------------------------------------------------

async function recomputeCohortStats(tx: Tx, native: string, now: Date): Promise<void> {
  const defs = await tx.cohortStatDef.findMany();
  for (const def of defs) {
    // A stored def is re-validated against the live allowlist before counting; a
    // malformed one is skipped (never silently miscounted), logged for the admin.
    const numerator = safeParseCohortFilter(def.numeratorFilter);
    const denominator = safeParseCohortFilter(def.denominatorFilter);
    if (!numerator || !denominator) {
      console.warn(
        `[stats-recompute] cohort def ${def.id} (${def.label}) has an invalid filter; skipping.`,
      );
      continue;
    }
    const [num, den] = await Promise.all([
      countCohortSide(numerator, native, now, tx),
      countCohortSide(denominator, native, now, tx),
    ]);
    await tx.cohortStat.upsert({
      where: { defId: def.id },
      create: { defId: def.id, numerator: num, denominator: den, computedAt: now },
      update: { numerator: num, denominator: den, computedAt: now },
    });
  }
}

// ---------------------------------------------------------------------------
// BucketStat: the distribution of users across the 0-4 anti-sybil buckets
// ---------------------------------------------------------------------------

async function recomputeBucketStats(tx: Tx, native: string, now: Date): Promise<void> {
  const config = await loadSybilScoringConfig(now.getTime());
  const nowMs = now.getTime();
  const counts = [0, 0, 0, 0, 0];

  let cursor: string | undefined;
  for (;;) {
    const users = await tx.user.findMany({
      take: USER_BATCH_SIZE,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      orderBy: { id: "asc" },
      select: { id: true },
    });
    if (users.length === 0) break;

    const ids = users.map((u) => u.id);
    const badges = await tx.badge.findMany({
      where: {
        userId: { in: ids },
        issuer: native,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: { userId: true, type: true, attributes: true, expiresAt: true, issuer: true },
    });

    const byUser = new Map<string, ScorableBadge[]>();
    for (const id of ids) byUser.set(id, []);
    for (const b of badges) {
      const attrs =
        b.attributes !== null && typeof b.attributes === "object" && !Array.isArray(b.attributes)
          ? (b.attributes as Record<string, unknown>)
          : {};
      byUser.get(b.userId)?.push({
        type: b.type,
        attributes: attrs,
        expiresAt: b.expiresAt,
        issuer: b.issuer,
      });
    }

    for (const id of ids) {
      const { bucket } = sybilScore(byUser.get(id) ?? [], config, {
        now: nowMs,
        nativeIssuerDid: native,
      });
      counts[bucket] = (counts[bucket] ?? 0) + 1;
    }

    if (users.length < USER_BATCH_SIZE) break;
    cursor = ids[ids.length - 1];
  }

  await tx.bucketStat.deleteMany({});
  await tx.bucketStat.createMany({
    data: BUCKETS.map((bucket) => ({ bucket, count: counts[bucket] ?? 0, computedAt: now })),
  });
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// The core recompute body, run on one (transaction) client for a consistent
// snapshot. `native` is Minister's own issuer DID, resolved before the tx opens.
async function recomputeWithin(tx: Tx, native: string, now: Date): Promise<void> {
  await recomputeBadgeStats(tx, native, now);
  await recomputeCohortStats(tx, native, now);
  await recomputeBucketStats(tx, native, now);
}

export interface RecomputeResult {
  durationMs: number;
}

/**
 * Recompute all badge statistics in one transaction and stamp `StatsRun`. Used
 * by the `stats:recompute` script and the admin "Recompute now" action — no
 * advisory lock (the deliberate escape hatch). The scheduled interval uses
 * `runScheduledStatsRecompute` instead.
 *
 * @param now injectable clock for deterministic tests.
 */
export async function recomputeAllStats(now: Date = new Date()): Promise<RecomputeResult> {
  const issuer = await getIssuer();
  const native = issuer.did;
  const start = Date.now();

  await prisma.$transaction(
    async (tx) => {
      await recomputeWithin(tx, native, now);
    },
    { timeout: STATS_TX_TIMEOUT_MS, maxWait: STATS_TX_MAX_WAIT_MS },
  );

  const durationMs = Date.now() - start;
  await prisma.statsRun.upsert({
    where: { id: "singleton" },
    create: { id: "singleton", computedAt: now, durationMs },
    update: { computedAt: now, durationMs },
  });
  return { durationMs };
}

export type ScheduledStatsOutcome = "recomputed" | "skipped-locked" | "skipped-fresh";

interface AdvisoryLockRow {
  locked: boolean;
}

/**
 * The scheduled entry point (instrumentation.ts interval). In one transaction:
 * take the stats advisory lock (a second instance's `pg_try_advisory_xact_lock`
 * returns false -> `skipped-locked`); skip if `StatsRun.computedAt` is fresher
 * than `intervalMs` (`skipped-fresh`); otherwise recompute. The transaction-level
 * lock auto-releases at commit. Stamps `StatsRun` only on an actual recompute.
 *
 * @param intervalMs the freshness window (a run newer than this is skipped).
 * @param now        injectable clock for deterministic tests.
 */
export async function runScheduledStatsRecompute(
  intervalMs: number,
  now: Date = new Date(),
): Promise<ScheduledStatsOutcome> {
  const issuer = await getIssuer();
  const native = issuer.did;
  const start = Date.now();

  const outcome = await prisma.$transaction(
    async (tx): Promise<ScheduledStatsOutcome> => {
      const lock = await tx.$queryRaw<AdvisoryLockRow[]>(
        Prisma.sql`SELECT pg_try_advisory_xact_lock(${STATS_ADVISORY_LOCK_KEY}) AS locked`,
      );
      if (!lock[0]?.locked) return "skipped-locked";

      const run = await tx.statsRun.findUnique({ where: { id: "singleton" } });
      if (run && now.getTime() - run.computedAt.getTime() < intervalMs) return "skipped-fresh";

      await recomputeWithin(tx, native, now);
      await tx.statsRun.upsert({
        where: { id: "singleton" },
        create: { id: "singleton", computedAt: now, durationMs: Date.now() - start },
        update: { computedAt: now, durationMs: Date.now() - start },
      });
      return "recomputed";
    },
    { timeout: STATS_TX_TIMEOUT_MS, maxWait: STATS_TX_MAX_WAIT_MS },
  );

  return outcome;
}
