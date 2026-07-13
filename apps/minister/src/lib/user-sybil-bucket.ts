// Compute a user's coarse anti-sybil bucket (0-4) from the badges they hold.
// A thin wrapper over the same pieces the OIDC consent path uses
// (loadScorableBadges shape + loadSybilScoringConfig + the pure scorer), pulled
// into its own module so non-OIDC callers (the group founding gate) can reuse it
// without importing the OIDC server actions.
//
// NOT fail-safe on its own: an unseeded config makes `loadSybilScoringConfig`
// throw, and getIssuer/prisma can throw — the caller (createGroup) treats any
// throw as "cannot verify, block founding" (fail-closed), never as bucket 0.

import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";
import { loadSybilScoringConfig, type ScorableBadge } from "@/lib/sybil-config";
import { sybilScore } from "@/lib/sybil-score";

export async function computeUserSybilBucket(
  userId: string,
  now: number = Date.now(),
): Promise<number> {
  const [rows, config, issuer] = await Promise.all([
    prisma.badge.findMany({
      where: { userId },
      select: { type: true, attributes: true, expiresAt: true, issuer: true },
    }),
    loadSybilScoringConfig(now),
    getIssuer(),
  ]);
  const badges: ScorableBadge[] = rows.map((row) => ({
    type: row.type,
    attributes: row.attributes as Record<string, unknown>,
    expiresAt: row.expiresAt,
    issuer: row.issuer,
  }));
  return sybilScore(badges, config, { now, nativeIssuerDid: issuer.did }).bucket;
}
