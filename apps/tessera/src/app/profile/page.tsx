import { redirect } from "next/navigation";

import { auth } from "@/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { RegisterPasskeyButton } from "@/components/register-passkey-button";

export default async function ProfilePage() {
  const session = await auth();
  if (!session?.user) redirect("/");
  const name = session.user.name ?? session.user.email ?? "Anonymous user";

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Signed in as <span className="font-medium">{name}</span>.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>No badges yet</CardTitle>
          <CardDescription>
            You haven&apos;t earned any badges. Badge plugins land in Stage 2 —
            for now this is an intentional empty state.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RegisterPasskeyButton />
        </CardContent>
      </Card>
    </div>
  );
}
