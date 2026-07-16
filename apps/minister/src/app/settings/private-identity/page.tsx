import { notFound, redirect } from "next/navigation";

import { env } from "@/env";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

import { AnonymousKeyManager } from "./anonymous-key-manager";

// Proactive enrollment + lifecycle management for the Private Identity key
// (anon-identity master spec §6.2). Flag-gated: a disabled deployment 404s.
// Also the navigation target the L2 save flow references (spec §7.2).

export default async function PrivateIdentityPage() {
  if (!env.ANON_IDENTITY_ENABLED) notFound();

  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const [enrollment, blobs] = await Promise.all([
    prisma.anonSeedEnrollment.findUnique({ where: { userId: session.user.id } }),
    prisma.anonSeedBlob.findMany({
      where: { userId: session.user.id },
      orderBy: { createdAt: "asc" },
      select: { credentialId: true, createdAt: true },
    }),
  ]);
  const status =
    !enrollment || enrollment.seedGeneratedAt === null
      ? ("none" as const)
      : enrollment.backupConfirmedAt === null
        ? ("pending_backup" as const)
        : ("active" as const);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Private Identity</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Your Private Identity, generated and kept in your browser, gives you a separate anonymous
          identity in every connected app. Ministry never sees it and cannot recover it.
        </p>
      </header>

      <AnonymousKeyManager
        userId={session.user.id}
        initialStatus={status}
        epoch={enrollment?.enrollmentEpoch ?? 1}
        passkeyBlobs={blobs.map((b) => ({
          credentialId: b.credentialId,
          createdAt: b.createdAt.toISOString(),
        }))}
      />
    </div>
  );
}
