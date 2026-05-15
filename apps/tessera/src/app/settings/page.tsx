import { redirect } from "next/navigation";

import { auth } from "@/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SignOutButton } from "@/components/sign-out-button";

export default async function SettingsPage() {
  const session = await auth();
  if (!session?.user) redirect("/");
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Account controls. Display name, avatar, and privacy settings
          arrive in Stage 1.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Session</CardTitle>
          <CardDescription>End your current session on this device.</CardDescription>
        </CardHeader>
        <CardContent>
          <SignOutButton />
        </CardContent>
      </Card>
    </div>
  );
}
