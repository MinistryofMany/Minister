import Link from "next/link";
import { ShieldAlert } from "lucide-react";

import { isAnonBackupPending } from "@/lib/anon-seed/backup-gate";

// Persistent reminder (spec §6.4) shown on the profile and badge pages while a
// user's Private Identity enrollment is PENDING_BACKUP: badges are blocked until
// the backup is confirmed, so nudge them to finish. Renders nothing when the
// flag is off or the user isn't mid-enrollment (isAnonBackupPending is false).
export async function BackupPendingBanner({ userId }: { userId: string }) {
  if (!(await isAnonBackupPending(userId))) return null;

  return (
    <div
      role="region"
      aria-label="Finish backing up your Private Identity"
      className="flex flex-col gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900 sm:flex-row sm:items-center sm:justify-between dark:border-amber-900/50 dark:bg-amber-900/20 dark:text-amber-200"
    >
      <div className="flex items-start gap-3">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
        <div className="space-y-0.5">
          <p className="text-sm font-semibold">Finish backing up your Private Identity</p>
          <p className="text-sm text-amber-800 dark:text-amber-300/90">
            You can&apos;t add badges until you back up your Private Identity key. Ministry never
            sees it and can&apos;t recover it, so this step protects your anonymous identity in
            every connected app.
          </p>
        </div>
      </div>
      <Link
        href="/settings/private-identity"
        className="inline-flex shrink-0 items-center justify-center rounded-md bg-amber-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600"
      >
        Finish backup
      </Link>
    </div>
  );
}
