import { derivePairwiseSub } from "@/lib/pairwise-backend";
import { prisma } from "@/lib/prisma";

// Subject resolution with the merge override seam (slice 5). The pairwise
// `sub` an RP sees for (userId, clientId) is normally derived by the pairwise
// HMAC. After an account merge, the survivor carries a SubjectOverride row per
// client the donor had token history with, so it can keep presenting the
// donor's historical pairwise identity to every RP the donor used — lossless
// for RPs only one account touched.
//
// resolveSub is the DB-touching wrapper the OIDC token + userinfo endpoints
// call. With no overrides present (the default) it is exactly the pairwise
// derivation, so behaviour is unchanged until a merge populates the table.
//
// The derivation routes through the Phase 7 seam (lib/pairwise-backend.ts) so
// it can be staged local → shadow → signet-fallback → signet; in the default
// `local` mode it is byte-identical to the synchronous pairwiseSub. §2.6: this
// is the only place that consults the override table, and it holds no open
// prisma.$transaction across the (async) derivation.
export async function resolveSub(userId: string, clientId: string): Promise<string> {
  const override = await prisma.subjectOverride.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { sub: true },
  });
  if (override) return override.sub;
  return derivePairwiseSub(userId, clientId);
}
