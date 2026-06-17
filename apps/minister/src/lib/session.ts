import { cache } from "react";
import type { Session } from "next-auth";

import { auth } from "@/auth";
import type { Aal } from "@/lib/assurance";
import { prisma } from "@/lib/prisma";

export interface SessionFlags {
  session: Session;
  isAdmin: boolean;
}

// Server-side session getter with revocation + ban enforcement.
//
// Why this exists: with JWT-strategy sessions, `auth()` alone trusts the
// JWT until it naturally expires. To support "sign out everywhere"
// (bumping User.sessionGeneration) and admin bans, we check the user
// row before treating the user as signed in. A banned user's JWT keeps
// verifying at the Edge; this is the layer that rejects it.
//
// Wrapped in React.cache so multiple call sites in the same render
// (e.g. header + page body, /profile + redirect-from-/) share a single
// DB query. Per-request cost: one indexed findUnique.
//
// Middleware in src/middleware.ts still does the cheap JWT-only check
// at the Edge — that catches no-cookie / bad-signature before this
// helper ever runs.
const loadSessionFlags = cache(async (): Promise<SessionFlags | null> => {
  const session = await auth();
  if (!session?.user?.id) return null;

  const expectedGen = session.sessionGeneration ?? 0;
  const fresh = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: {
      sessionGeneration: true,
      isAdmin: true,
      isBanned: true,
      mergedIntoUserId: true,
    },
  });
  if (!fresh) return null;
  if (fresh.sessionGeneration !== expectedGen) return null;
  if (fresh.isBanned) return null;
  // A merged (tombstoned) account is treated as signed out, same as a ban:
  // the JWT keeps verifying at the Edge, but this layer rejects it. The
  // user now lives under the survivor account and must sign in there.
  if (fresh.mergedIntoUserId !== null) return null;

  return { session, isAdmin: fresh.isAdmin };
});

export async function getCurrentSession(): Promise<Session | null> {
  return (await loadSessionFlags())?.session ?? null;
}

// For call sites that branch on admin-ness (header nav, /admin layout).
// Same single cached query as getCurrentSession.
export async function getSessionFlags(): Promise<SessionFlags | null> {
  return loadSessionFlags();
}

// Convenience wrapper for the very common "I need the userId or I bail"
// pattern in server actions. Throws on revoked / banned / missing —
// callers turn that into a redirect or an error response.
export async function requireSession(): Promise<Session> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  return session;
}

// Admin gate for /admin pages and admin server actions. Admin-ness is
// a DB flag (granted via scripts/make-admin.ts), never something a
// user can reach from the UI.
export async function requireAdmin(): Promise<Session> {
  const flags = await loadSessionFlags();
  if (!flags?.session.user?.id || !flags.isAdmin) {
    throw new Error("Not an admin");
  }
  return flags.session;
}

// Thrown when a sensitive operation requires a higher authentication
// assurance level than the current session carries. Distinct from a plain
// "Not signed in": the UI catches this specifically to route the user into
// a step-up re-auth (enroll/use a passkey) rather than a full sign-in, and
// carries the floor that was required for messaging.
export class StepUpRequiredError extends Error {
  readonly requiredAal: Aal;
  readonly currentAal: Aal;

  constructor(requiredAal: Aal, currentAal: Aal) {
    super(`Step-up required: this action needs AAL${requiredAal} (session is AAL${currentAal})`);
    this.name = "StepUpRequiredError";
    this.requiredAal = requiredAal;
    this.currentAal = currentAal;
  }
}

// AAL floor guard for sensitive server actions (credential mutation,
// primary-email promotion, starting recovery/merge — all AAL2 per
// DESIGNDECISIONS #4). Throws StepUpRequiredError when the session is below
// the floor (or has no AAL, e.g. a pre-AAL JWT), which the caller turns
// into a step-up prompt. A missing session is a StepUpRequiredError from
// AAL0 — callers that want a hard "not signed in" should gate on
// requireSession() first.
//
// Note: this checks ONLY the AAL claim on the passed session. It does not
// re-validate the session against the DB; pair it with requireSession()/
// getCurrentSession() (which enforce gen/ban/merge) to get a fully-checked,
// AAL-floored principal.
export function requireAal(session: Session | null, floor: Aal): void {
  const current: Aal = session?.aal ?? 0;
  if (current < floor) {
    throw new StepUpRequiredError(floor, current);
  }
}
