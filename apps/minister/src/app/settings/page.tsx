import Link from "next/link";
import { redirect } from "next/navigation";

import { ProfileForm } from "@/app/settings/profile-form";
import { RevokeAllButton } from "@/components/revoke-all-button";
import { SignOutButton } from "@/components/sign-out-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

// Links into the account-security surfaces (multi-credential, recovery,
// merge). Each destination enforces its own AAL floor; these are just nav.
const SECURITY_LINKS = [
  {
    href: "/settings/credentials",
    title: "Credentials",
    description: "Manage your sign-in emails and passkeys, and choose a primary email.",
  },
  {
    href: "/settings/recovery-codes",
    title: "Recovery codes",
    description: "Generate single-use codes to recover access if you lose your passkey.",
  },
  {
    href: "/settings/merge",
    title: "Combine accounts",
    description: "Merge a second account (e.g. work + school) into this one.",
  },
];

export default async function SettingsPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { displayName: true, avatarUrl: true },
  });

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Manage your profile, credentials, and sessions.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>
            Your display name and avatar. Shared with apps only when you choose to disclose your
            profile.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ProfileForm
            initialDisplayName={user?.displayName ?? null}
            initialAvatarUrl={user?.avatarUrl ?? null}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Connected apps</CardTitle>
          <CardDescription>
            Manage the name and avatar each app you&apos;ve signed into sees. Per-app and separate
            from your global default above.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            href="/settings/apps"
            className="block rounded-lg border border-neutral-200 p-3 transition hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-900"
          >
            <div className="text-sm font-medium">Connected apps</div>
            <div className="text-sm text-neutral-600 dark:text-neutral-400">
              Set a per-app display name and avatar, or clear one to stop sharing it with that app.
            </div>
          </Link>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security</CardTitle>
          <CardDescription>
            Your credentials, account recovery, and merging accounts.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {SECURITY_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="rounded-lg border border-neutral-200 p-3 transition hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-900"
            >
              <div className="text-sm font-medium">{link.title}</div>
              <div className="text-sm text-neutral-600 dark:text-neutral-400">
                {link.description}
              </div>
            </Link>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Session</CardTitle>
          <CardDescription>
            End your current session on this device, or revoke all sessions across every device.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <SignOutButton />
          <RevokeAllButton />
        </CardContent>
      </Card>
    </div>
  );
}
