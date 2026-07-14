import { env } from "@/env";
import { prisma } from "@/lib/prisma";

// True when the anon-identity flag is on AND the user's enrollment is stuck in
// PENDING_BACKUP (seed generated, backup not yet confirmed). One source of truth
// for both the badge-wizard gate (spec §6.4) and the persistent reminder banner.
// Returns false for `none` (never enrolled) and `active` — those users are
// unaffected, so the gate never bites someone without an in-progress enrollment.
export async function isAnonBackupPending(userId: string): Promise<boolean> {
  if (!env.ANON_IDENTITY_ENABLED) return false;
  const enrollment = await prisma.anonSeedEnrollment.findUnique({
    where: { userId },
    select: { seedGeneratedAt: true, backupConfirmedAt: true },
  });
  return (
    enrollment !== null &&
    enrollment.seedGeneratedAt !== null &&
    enrollment.backupConfirmedAt === null
  );
}
