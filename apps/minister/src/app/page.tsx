import { redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SignInForm } from "@/components/sign-in-form";
import { mailTransportConfigured } from "@/lib/mailer";
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
          {/* mailConfigured drives the "check your inbox" vs "check the
              server logs" copy — the email is really delivered whenever a
              transport is set (SMTP_URL or Resend). */}
          <SignInForm mailConfigured={mailTransportConfigured()} />
        </CardContent>
      </Card>

      <section className="space-y-3">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold tracking-tight">Sign in with Minister</h2>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Apps that let you sign in with your Minister identity.
          </p>
        </div>
        <ul className="space-y-3">
          {relyingParties.map((app) => (
            <li key={app.url}>
              <a
                href={app.url}
                target="_blank"
                rel="noopener noreferrer"
                className="block rounded-lg border border-neutral-200 bg-white p-4 shadow-sm transition-colors hover:border-neutral-300 hover:bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950 dark:hover:border-neutral-700 dark:hover:bg-neutral-900"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-neutral-900 dark:text-neutral-100">
                    {app.name}
                  </span>
                  <span aria-hidden className="text-neutral-400 dark:text-neutral-500">
                    ↗
                  </span>
                </div>
                <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                  {app.description}
                </p>
              </a>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

const relyingParties = [
  {
    name: "FreedInk",
    url: "https://freed.ink",
    description: "Anonymous collective blogging, gated by zero-knowledge group-membership proofs.",
  },
  {
    name: "Discreetly",
    url: "https://discreetly.chat",
    description: "Anonymous federated zero-knowledge group chat.",
  },
  {
    name: "Deforum",
    url: "https://deforum.space",
    description: "Anonymous forums and discussion.",
  },
] as const;
