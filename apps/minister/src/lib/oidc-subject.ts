import { pairwiseSub } from "@/lib/oidc-tokens";
import { prisma } from "@/lib/prisma";

// Subject resolution with the merge override seam (slice 5). The pairwise
// `sub` an RP sees for (userId, clientId) is normally derived by the pure
// HMAC in pairwiseSub. After an account merge, the survivor carries a
// SubjectOverride row per client the donor had token history with, so it
// can keep presenting the donor's historical pairwise identity to every RP
// the donor used — lossless for RPs only one account touched.
//
// resolveSub is the DB-touching wrapper the OIDC token + userinfo endpoints
// call. With no overrides present (the default) it is exactly pairwiseSub,
// so behaviour is unchanged until a merge populates the table.
//
// pairwiseSub itself stays pure and synchronous (its tests assert that);
// this is the only place that consults the override table.
export async function resolveSub(userId: string, clientId: string): Promise<string> {
  const override = await prisma.subjectOverride.findUnique({
    where: { userId_clientId: { userId, clientId } },
    select: { sub: true },
  });
  if (override) return override.sub;
  return pairwiseSub(userId, clientId);
}
