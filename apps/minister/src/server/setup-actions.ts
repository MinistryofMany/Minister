"use server";

import { audit } from "@/lib/audit";
import { prisma } from "@/lib/prisma";
import { requireSession } from "@/lib/session";

// Onboarding completion. The final step of the forced /welcome setup guide
// stamps `setupCompletedAt`, which flips the session loader's setup gate and
// stops redirecting the user back to /welcome. Idempotent: a second call on an
// already-completed account is a no-op (never re-stamps the timestamp).
export async function completeSetup(): Promise<{ ok: true }> {
  const session = await requireSession();
  const userId = session.user.id;

  const res = await prisma.user.updateMany({
    where: { id: userId, setupCompletedAt: null },
    data: { setupCompletedAt: new Date() },
  });
  if (res.count > 0) {
    await audit(userId, "account.setup_completed", {});
  }
  return { ok: true };
}
