import { redirect } from "next/navigation";

import { RevokeAllButton } from "@/components/revoke-all-button";
import { SignOutButton } from "@/components/sign-out-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getCurrentSession } from "@/lib/session";

export default async function SettingsPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Account controls. Display name, avatar, and privacy settings arrive in Stage 1.
        </p>
      </header>

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
