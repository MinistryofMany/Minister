"use server";

import { signOut } from "@/auth";
import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

// Revoke every outstanding session for the current user — including
// this one. Bumps User.sessionGeneration so any JWT carrying the
// previous value fails the staleness check in getCurrentSession() on
// its next protected request.
//
// We can't selectively revoke a single JWT (it's stateless by design),
// so this is necessarily "all devices, including this one." After bump
// we sign the current device out cleanly so they're not left with a
// JWT cookie that's about to fail on every page load.
export async function revokeAllSessions(): Promise<never> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }

  // The sessionGeneration bump only kills Minister login sessions; the
  // user's outstanding OIDC access tokens stay valid until their ≤1h TTL,
  // so "all devices" wouldn't really cut OIDC grants. In the same
  // transaction, revoke them (mark revokedAt so the row survives for the
  // "revoked" 401 at /oidc/userinfo), mirroring updateOidcClient but keyed
  // by userId. NOTE: this does NOT terminate sessions the user already
  // holds inside relying-party apps; that needs OIDC back-channel logout
  // (deferred — Stage 9+).
  const userId = session.user.id;
  const [updated] = await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { sessionGeneration: { increment: 1 } },
      select: { sessionGeneration: true },
    }),
    prisma.oidcAccessToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);

  await audit(session.user.id, "session.revoked_all", {
    newGeneration: updated.sessionGeneration,
  });

  // signOut redirects, so this function never returns. Type as `never`
  // to keep callers honest.
  await signOut({ redirectTo: "/" });
  throw new Error("unreachable");
}
