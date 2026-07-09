import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getCurrentSession } from "@/lib/session";
import { resumeViaPendingToken } from "@/server/wizard";

interface PageProps {
  searchParams: Promise<{
    code?: string;
    state?: string;
    error?: string;
    error_description?: string;
  }>;
}

// X redirects the user here after authorize. We resolve the in-flight wizard
// session via ?state (matching the value the plugin generated and the runtime
// persisted as pendingToken), then hand ?code back to the plugin.
export default async function XCallbackPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const session = await getCurrentSession();

  if (!session?.user) {
    return (
      <Shell title="Sign in to finish">
        <CardDescription>
          You came back from X but aren&apos;t signed in to Minister here. Sign in (same browser)
          and then re-run the X flow.
        </CardDescription>
        <Button asChild className="mt-4 self-start">
          <Link href="/">Go to sign-in</Link>
        </Button>
      </Shell>
    );
  }

  if (params.error) {
    return (
      <Shell title="X declined">
        <CardDescription>{params.error_description ?? params.error}</CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/badges/new/x">Try again</Link>
        </Button>
      </Shell>
    );
  }

  if (!params.code || !params.state) {
    return (
      <Shell title="Malformed callback">
        <CardDescription>
          X redirected without a code or state. The flow may have expired — restart it.
        </CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/badges/new/x">Restart</Link>
        </Button>
      </Shell>
    );
  }

  const h = await headers();
  const origin = `${h.get("x-forwarded-proto") ?? "http"}://${h.get("host") ?? "localhost:3000"}`;

  const result = await resumeViaPendingToken({
    token: params.state,
    userId: session.user.id,
    origin,
    input: { code: params.code },
  });

  if (result.kind === "complete") {
    redirect("/profile?issued=x");
  }

  if (result.kind === "continue") {
    redirect(`/badges/new/${result.pluginId}?wsid=${encodeURIComponent(result.sessionId)}`);
  }

  return (
    <Shell title="X flow failed">
      <CardDescription>{result.message}</CardDescription>
      <Button asChild variant="outline" className="mt-4 self-start">
        <Link href="/badges/new/x">Restart</Link>
      </Button>
    </Shell>
  );
}

function Shell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col">{children}</CardContent>
      </Card>
    </div>
  );
}
