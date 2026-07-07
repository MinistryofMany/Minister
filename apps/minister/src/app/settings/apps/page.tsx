import { redirect } from "next/navigation";

import { RpProfileForm } from "@/app/settings/apps/rp-profile-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

// Settings → Connected apps. Manage the per-relying-party profile persona
// (name + avatar) each app you've signed into sees. These are snapshotted at
// first consent and stay fixed until edited here; they are separate from the
// global default in Settings → Profile. Under the snapshot-per-app model an
// existing persona is authoritative: clearing a field means "share nothing for
// that field with this app", NOT a fall-back to the global default. This is
// the "editable after" surface for the feature.
export default async function ConnectedAppsPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");
  const userId = session.user.id;

  // Every app the user has a durable grant with (a real prior consent),
  // including which profile fields were disclosed, the global curated profile
  // (the legacy fallback for an app with no persona row), and any existing
  // per-RP personas.
  const [user, grants] = await Promise.all([
    prisma.user.findUnique({
      where: { id: userId },
      select: { displayName: true, avatarUrl: true },
    }),
    prisma.oidcGrant.findMany({
      where: { userId },
      select: { clientId: true, profileName: true, profileAvatar: true },
      orderBy: { createdAt: "asc" },
    }),
  ]);

  const clientIds = grants.map((g) => g.clientId);
  const [clients, overrides] = await Promise.all([
    prisma.oidcClient.findMany({
      where: { clientId: { in: clientIds } },
      select: { clientId: true, name: true },
    }),
    prisma.oidcProfileOverride.findMany({
      where: { userId, clientId: { in: clientIds } },
      select: { clientId: true, displayName: true, avatarUrl: true },
    }),
  ]);

  const nameByClientId = new Map(clients.map((c) => [c.clientId, c.name]));
  const overrideByClientId = new Map(overrides.map((o) => [o.clientId, o]));

  const globalName = user?.displayName ?? null;
  const globalAvatar = user?.avatarUrl ?? null;

  const apps = grants.map((g) => {
    const override = overrideByClientId.get(g.clientId) ?? null;
    // AUTHORITATIVE current value, mirroring the disclosure resolver: a present
    // persona row wins verbatim (null field => nothing shared for that field);
    // no row falls back to the global default (the seed for a first persona).
    const currentDisplayName = override ? override.displayName : globalName;
    const currentAvatarUrl = override ? override.avatarUrl : globalAvatar;
    return {
      clientId: g.clientId,
      // A deleted client leaves the grant orphaned; fall back to the raw id.
      clientName: nameByClientId.get(g.clientId) ?? g.clientId,
      // Whether the app actually RECEIVES each field right now: it was granted
      // (grant boolean) AND the authoritative current value is non-null. A
      // cleared persona field reads as "not shared" even though it was granted.
      nameShared: g.profileName && currentDisplayName !== null,
      avatarShared: g.profileAvatar && currentAvatarUrl !== null,
      currentDisplayName,
      currentAvatarUrl,
    };
  });

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Connected apps</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          The name and avatar each app sees when you share your profile. These are per-app and
          separate from your global default in Settings → Profile. Clearing a field stops sharing it
          with that app.
        </p>
      </header>

      {apps.length === 0 ? (
        <Card>
          <CardContent className="py-6 text-sm text-neutral-600 dark:text-neutral-400">
            You haven&apos;t connected any apps yet. Once you sign into an app with Minister and
            share your profile, it will appear here.
          </CardContent>
        </Card>
      ) : (
        apps.map((app) => (
          <Card key={app.clientId}>
            <CardHeader>
              <CardTitle>{app.clientName}</CardTitle>
              <CardDescription>
                What {app.clientName} currently receives — Name:{" "}
                {app.nameShared ? "shared" : "not shared"}, Avatar:{" "}
                {app.avatarShared ? "shared" : "not shared"}.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RpProfileForm
                clientId={app.clientId}
                clientName={app.clientName}
                initialDisplayName={app.currentDisplayName}
                initialAvatarUrl={app.currentAvatarUrl}
              />
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}
