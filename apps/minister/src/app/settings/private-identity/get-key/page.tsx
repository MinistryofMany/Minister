import { notFound, redirect } from "next/navigation";

import { env } from "@/env";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

import { GetKeyClient } from "./get-key-client";

// DISPLAY side of QR pairing: this device NEEDS the root. It mints a relay
// session and an ephemeral X25519 key pair (private half memory-only), renders
// the QR, and polls for the sealed payload. The root-holding device scans and
// seals. `userId`/`epoch` come from THIS device's own server session (C2) — the
// received root is loaded at the account's current enrollment epoch.
export default async function GetKeyPage() {
  if (!env.ANON_IDENTITY_ENABLED) notFound();

  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  const enrollment = await prisma.anonSeedEnrollment.findUnique({
    where: { userId: session.user.id },
  });
  const epoch = enrollment?.enrollmentEpoch ?? 1;

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Get your key from another device</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Show this code to a device that already has your Private Identity, and point that
          device&apos;s camera at it. Your key is sent end-to-end encrypted — Ministry never sees
          it.
        </p>
      </header>

      <GetKeyClient userId={session.user.id} epoch={epoch} />
    </div>
  );
}
