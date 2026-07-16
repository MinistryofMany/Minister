import { redirect } from "next/navigation";

import { env } from "@/env";
import { gravatarUrl } from "@/lib/gravatar";
import { prisma } from "@/lib/prisma";
import { getSessionFlags } from "@/lib/session";
import type { AnonSeedStatus } from "@/server/anon-seed-actions";

import { WelcomeWizard } from "./welcome-wizard";

// Forced onboarding guide, reached AFTER sign-in (email + magic link are the
// sign-in itself). The gated sections' layouts redirect a not-yet-set-up user
// here; once completeSetup stamps setupCompletedAt this page sends them on.
export default async function WelcomePage() {
  const flags = await getSessionFlags();
  if (!flags?.session.user?.id) redirect("/");
  if (flags.setupComplete) redirect("/profile");

  const userId = flags.session.user.id;

  const anonEnabled = env.ANON_IDENTITY_ENABLED;

  const [passkeyCount, user, provenEmails, enrollment] = await Promise.all([
    prisma.authenticator.count({ where: { userId } }),
    prisma.user.findUnique({
      where: { id: userId },
      select: { displayName: true, avatarUrl: true },
    }),
    prisma.userEmail.findMany({
      where: { userId, verifiedAt: { not: null } },
      orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
      select: { email: true },
    }),
    anonEnabled
      ? prisma.anonSeedEnrollment.findUnique({ where: { userId } })
      : Promise.resolve(null),
  ]);

  const anonStatus: AnonSeedStatus =
    !enrollment || enrollment.seedGeneratedAt === null
      ? "none"
      : enrollment.backupConfirmedAt === null
        ? "pending_backup"
        : "active";

  const gravatarOptions = provenEmails.map((e) => ({
    email: e.email,
    url: gravatarUrl(e.email),
  }));

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Welcome to Ministry</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          A quick setup so your account is secure and ready. It takes about a minute.
        </p>
      </header>

      <WelcomeWizard
        userId={userId}
        initialPasskeyCount={passkeyCount}
        anonEnabled={anonEnabled}
        initialAnonStatus={anonStatus}
        initialDisplayName={user?.displayName ?? null}
        initialAvatarUrl={user?.avatarUrl ?? null}
        gravatarOptions={gravatarOptions}
      />
    </div>
  );
}
