import Link from "next/link";
import { redirect } from "next/navigation";
import { Plus } from "lucide-react";

import { auth } from "@/auth";
import { BadgeGrid } from "@/components/badge-grid";
import { RegisterPasskeyButton } from "@/components/register-passkey-button";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { loadUserBadges } from "@/lib/badges";

export default async function ProfilePage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const badges = await loadUserBadges(session.user.id);
  const name = session.user.name ?? session.user.email ?? "Anonymous user";
  const hasPublic = badges.some((b) => b.isPublic);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
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
            <span className="text-neutral-500">
              All badges private — public profile is empty.
            </span>
          )}
        </p>
      </header>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Badges{" "}
          <span className="text-sm font-normal text-neutral-500">
            ({badges.length})
          </span>
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
              Pick a plugin and walk through its wizard to claim your first
              badge.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex gap-2">
            <Button asChild>
              <Link href="/badges/new">Add a badge</Link>
            </Button>
            <RegisterPasskeyButton />
          </CardContent>
        </Card>
      ) : (
        <BadgeGrid badges={badges} />
      )}
    </div>
  );
}
