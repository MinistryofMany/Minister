import Link from "next/link";
import { redirect } from "next/navigation";

import { RevokeAllButton } from "@/components/revoke-all-button";
import { SignOutButton } from "@/components/sign-out-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { env } from "@/env";
import { getCurrentSession } from "@/lib/session";

// Links into the account-security surfaces (multi-credential, recovery). Each
// destination enforces its own AAL floor; these are just nav. Combining
// accounts is deliberately NOT a standing entry here: it is offered only when
// you try to add an email that already belongs to another account, after you
// prove you control it (see the credentials page).
const SECURITY_LINKS = [
  {
    href: "/settings/credentials",
    title: "Credentials",
    description: "Manage your sign-in emails and passkeys, and choose a primary email.",
  },
  {
    href: "/settings/security",
    title: "Account recovery",
    description:
      "Recover your account with your badges or single-use codes if you lose your passkey.",
  },
];

export default async function SettingsPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const securityLinks = env.ANON_IDENTITY_ENABLED
    ? [
        ...SECURITY_LINKS,
        {
          href: "/settings/private-identity",
          title: "Private Identity",
          description:
            "Set up, unlock, and manage your Private Identity. Unlike your account, it can't be recovered — only replaced.",
        },
      ]
    : SECURITY_LINKS;

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
          <CardDescription>Edit your username and photo on your profile page.</CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            href="/profile"
            className="block rounded-lg border border-neutral-200 p-3 transition hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-900"
          >
            <div className="text-sm font-medium">Edit your profile</div>
            <div className="text-sm text-neutral-600 dark:text-neutral-400">
              Change your username and photo. Shared with an app only when you choose to disclose
              your profile.
            </div>
          </Link>
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
          <CardDescription>Your credentials and account recovery.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {securityLinks.map((link) => (
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
