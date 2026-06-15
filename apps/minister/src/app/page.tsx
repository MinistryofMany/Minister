import { redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SignInForm } from "@/components/sign-in-form";
import { getCurrentSession } from "@/lib/session";

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ from?: string }>;
}) {
  // Use getCurrentSession (not raw auth()) so a stale-but-cryptographically-
  // valid JWT — i.e. the user whose sessionGeneration was bumped server-side
  // — sees the sign-in form here instead of being redirected to /profile,
  // where they'd be redirected back to / by the staleness check, looping.
  const session = await getCurrentSession();
  if (session?.user) redirect("/profile");

  // Middleware bounces here with ?from=<path> when an unauthenticated
  // request hits a protected route — tell the user why they're seeing this.
  const { from } = await searchParams;
  const bounced = typeof from === "string" && from.startsWith("/");

  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Minister</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Your verifiable identity, your terms. Sign in to start collecting badges.
        </p>
      </header>

      {bounced ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
          Please sign in to continue.
        </p>
      ) : null}

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
