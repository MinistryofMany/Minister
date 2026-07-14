import { resolveSub } from "@/lib/oidc-subject";
import { prisma } from "@/lib/prisma";

// A plain-object view of one connected app's per-app pseudonymous identity, safe
// to cross the RSC server→client boundary (JSON-only, no class instances).
export interface PerAppIdView {
  appName: string;
  // The pairwise `sub` Minister stamps into this client's tokens. Server-only to
  // compute (derived from OIDC_PAIRWISE_SECRET or a SubjectOverride), but the sub
  // itself is what the app already sees, so surfacing it to the user leaks nothing.
  sub: string;
}

// The transparency read behind Settings → "Your IDs per app": for every app the
// user has a durable OIDC grant with, the app's display name and the pairwise
// `sub` that app receives. Resolved server-side via resolveSub (the same
// override-aware derivation the token/userinfo endpoints use), so each app's ID
// here is byte-identical to what it actually gets.
export async function loadPerAppIds(userId: string): Promise<PerAppIdView[]> {
  const grants = await prisma.oidcGrant.findMany({
    where: { userId },
    select: { clientId: true },
    orderBy: { createdAt: "asc" },
  });

  const clients = await prisma.oidcClient.findMany({
    where: { clientId: { in: grants.map((g) => g.clientId) } },
    select: { clientId: true, name: true },
  });
  const nameByClientId = new Map(clients.map((c) => [c.clientId, c.name]));

  return Promise.all(
    grants.map(async (g) => ({
      // A deleted client leaves the grant orphaned; fall back to the raw id.
      appName: nameByClientId.get(g.clientId) ?? g.clientId,
      sub: await resolveSub(userId, g.clientId),
    })),
  );
}
