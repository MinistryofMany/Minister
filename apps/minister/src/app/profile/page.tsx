import Link from "next/link";
import { redirect } from "next/navigation";
import { KeyRound, Plus } from "lucide-react";

import { ProfileForm } from "@/app/settings/profile-form";
import { BadgeGrid } from "@/components/badge-grid";
import { RegisterPasskeyButton } from "@/components/register-passkey-button";
import { RelyingParties } from "@/components/relying-parties";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loadUserBadges } from "@/lib/badges";
import { gravatarUrl } from "@/lib/gravatar";
import { prisma } from "@/lib/prisma";
import { getCurrentSession } from "@/lib/session";

export default async function ProfilePage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const [badges, passkeyCount, user, provenEmails] = await Promise.all([
    loadUserBadges(session.user.id),
    // Passkeys are the Auth.js Authenticator rows. Zero means the account
    // only has the magic-link fallback, so we surface the add-a-passkey CTA;
    // once the user has at least one, the banner disappears.
    prisma.authenticator.count({ where: { userId: session.user.id } }),
    // The user-curated display name and avatar the owner edits below. These
    // are independent of the upstream auth identity and only ever shared with
    // an app when the owner discloses their profile.
    prisma.user.findUnique({
      where: { id: session.user.id },
      select: { displayName: true, avatarUrl: true },
    }),
    // Verified emails only — the Gravatar option is offered strictly for an
    // address the user has already PROVEN they control (never an unverified
    // one). The action re-checks this on save; passing it here is just to
    // populate the picker.
    prisma.userEmail.findMany({
      where: { userId: session.user.id, verifiedAt: { not: null } },
      orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
      select: { email: true },
    }),
  ]);

  // Precompute each proven email's Gravatar URL server-side so the editor can
  // preview the choice without shipping the SHA-256 hashing (node:crypto) to
  // the browser. These hashes only ever reach the user's own page.
  const gravatarOptions = provenEmails.map((e) => ({
    email: e.email,
    url: gravatarUrl(e.email),
  }));
  const name = session.user.name ?? session.user.email ?? "Anonymous user";
  const hasPublic = badges.some((b) => b.isPublic);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      {passkeyCount === 0 ? (
        <div
          role="region"
          aria-label="Add a passkey"
          className="flex flex-col gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900 sm:flex-row sm:items-center sm:justify-between dark:border-amber-900/50 dark:bg-amber-900/20 dark:text-amber-200"
        >
          <div className="flex items-start gap-3">
            <KeyRound className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
            <div className="space-y-0.5">
              <p className="text-sm font-semibold">Add a passkey</p>
              <p className="text-sm text-amber-800 dark:text-amber-300/90">
                Your account has no passkey yet. Add one for faster, phishing-resistant sign-in
                instead of waiting on a magic-link email.
              </p>
            </div>
          </div>
          <RegisterPasskeyButton className="shrink-0" />
        </div>
      ) : null}

      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Signed in as <span className="font-medium">{name}</span>.{" "}
          {hasPublic ? (
            <>
              Public profile:{" "}
              <Link
                href={`/u/${session.user.id}`}
                className="underline underline-offset-2 hover:no-underline"
              >
                /u/{session.user.id.slice(0, 10)}…
              </Link>
            </>
          ) : (
            <span className="text-neutral-500">All badges private — public profile is empty.</span>
          )}
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Edit your profile</CardTitle>
          <CardDescription>
            Your username and photo. Shared with an app only when you choose to disclose your
            profile to it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ProfileForm
            userId={session.user.id}
            initialDisplayName={user?.displayName ?? null}
            initialAvatarUrl={user?.avatarUrl ?? null}
            gravatarOptions={gravatarOptions}
          />
        </CardContent>
      </Card>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Badges <span className="text-sm font-normal text-neutral-500">({badges.length})</span>
        </h2>
        <Button asChild size="sm">
          <Link href="/badges/new">
            <Plus className="h-4 w-4" />
            Add badge
          </Link>
        </Button>
      </div>

      {badges.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>No badges yet</CardTitle>
            <CardDescription>
              Pick a plugin and walk through its wizard to claim your first badge.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild>
              <Link href="/badges/new">Add a badge</Link>
            </Button>
          </CardContent>
        </Card>
      ) : (
        <BadgeGrid badges={badges} />
      )}

      <RelyingParties />
    </div>
  );
}
