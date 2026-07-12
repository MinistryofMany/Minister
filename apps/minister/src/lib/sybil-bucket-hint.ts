// Phase-2 §7: wires the materialized BucketStat (P2-U0's stats recompute)
// into the consent screen's account-strength card. Reuses the same coarse
// anonymity-hint bucketing anonymity-sets.ts uses for per-badge-type holder
// counts, applied instead to "how many users currently score this bucket" —
// so a user about to disclose a rare bucket 4 on a small instance sees "very
// small group" before consenting.

import { anonymityHint, type AnonymityHint } from "@/lib/anonymity-hint";
import { prisma } from "@/lib/prisma";

/**
 * Look up the bucket-class size for `bucket` (0-4) and map it through
 * `anonymityHint`. FAIL SOFT: `BucketStat` may not exist yet (the recompute
 * job hasn't run) or the read may error — either way this returns `null` so
 * the consent card renders without a hint rather than blocking login. Cheap:
 * a single-row lookup against a 5-row table, no caching needed.
 */
export async function loadBucketAnonymityHint(bucket: number): Promise<AnonymityHint | null> {
  try {
    const stat = await prisma.bucketStat.findUnique({ where: { bucket } });
    if (!stat) return null;
    return anonymityHint(stat.count);
  } catch (err) {
    console.error("[sybil-bucket-hint] failed to load BucketStat:", err);
    return null;
  }
}
