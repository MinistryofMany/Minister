import { redirect } from "next/navigation";

import { auth } from "@/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SignInForm } from "@/components/sign-in-form";

export default async function HomePage() {
  const session = await auth();
  if (session?.user) redirect("/profile");

  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Tessera</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Your verifiable identity, your terms. Sign in to start collecting
          badges.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            Use a passkey if you have one, or get a magic link by email.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SignInForm />
        </CardContent>
      </Card>
    </div>
  );
}
