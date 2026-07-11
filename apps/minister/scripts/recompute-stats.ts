#!/usr/bin/env tsx
// Recompute the materialized badge statistics (BadgeStat / CohortStat /
// BucketStat / StatsRun) on demand — the escape hatch + test surface for the
// in-process interval (anti-sybil phase 2, §4). Exposed as `stats:recompute`.
//
// Runs the real `recomputeAllStats` (no advisory lock; a manual run always
// executes). Set DATABASE_URL the same way the app does.

import { recomputeAllStats } from "../src/lib/stats-recompute.js";
import { prisma } from "../src/lib/prisma.js";

async function main(): Promise<void> {
  const { durationMs } = await recomputeAllStats();
  console.log(`[recompute-stats] done in ${durationMs}ms.`);
}

main()
  .catch((err: unknown) => {
    console.error("[recompute-stats] failed:", err);
    process.exit(1);
  })
  .finally(() => {
    void prisma.$disconnect();
  });
