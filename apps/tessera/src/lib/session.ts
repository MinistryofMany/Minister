import { cache } from "react";
import type { Session } from "next-auth";

import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

// Server-side session getter with revocation enforcement.
//
// Why this exists: with JWT-strategy sessions, `auth()` alone trusts the
// JWT until it naturally expires. To support "sign out everywhere"
// (bumping User.sessionGeneration on the database), we compare the
// JWT's captured generation against the current value before treating
// the user as signed in.
//
// Wrapped in React.cache so multiple call sites in the same render
// (e.g. header + page body, /profile + redirect-from-/) share a single
// DB query. Per-request cost: one indexed findUnique.
//
// Middleware in src/middleware.ts still does the cheap JWT-only check
// at the Edge — that catches no-cookie / bad-signature before this
// helper ever runs. This is the second layer: stale-but-valid JWTs.
export const getCurrentSession = cache(
  async (): Promise<Session | null> => {
    const session = await auth();
    if (!session?.user?.id) return null;

    const expectedGen = session.sessionGeneration ?? 0;
    const fresh = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { sessionGeneration: true },
    });
    if (!fresh) return null;
    if (fresh.sessionGeneration !== expectedGen) return null;

    return session;
  },
);

// Convenience wrapper for the very common "I need the userId or I bail"
// pattern in server actions. Throws on revoked / missing — callers turn
// that into a redirect or an error response.
export async function requireSession(): Promise<Session> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  return session;
}
