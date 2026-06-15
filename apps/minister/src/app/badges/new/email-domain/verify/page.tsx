import Link from "next/link";
import { redirect } from "next/navigation";
import { headers } from "next/headers";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { getCurrentSession } from "@/lib/session";
import { resumeViaPendingToken } from "@/server/wizard";

interface PageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function EmailDomainVerifyPage({ searchParams }: PageProps) {
  const { token } = await searchParams;
  const session = await getCurrentSession();

  if (!session?.user) {
    return (
      <ResultShell title="Sign in to finish verifying">
        <CardDescription>
          You opened a Minister verification link, but aren&apos;t signed in here. Sign in (in this
          browser) and click the link from your email again.
        </CardDescription>
        <Button asChild className="mt-4 self-start">
          <Link href="/">Go to sign-in</Link>
        </Button>
      </ResultShell>
    );
  }

  if (!token) {
    return (
      <ResultShell title="Missing token">
        <CardDescription>
          This link is malformed — it has no token attached. Restart the wizard if you need to.
        </CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/badges/new/email-domain">Restart</Link>
        </Button>
      </ResultShell>
    );
  }

  const h = await headers();
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host") ?? "localhost:3000";
  const origin = `${proto}://${host}`;

  const result = await resumeViaPendingToken({
    token,
    userId: session.user.id,
    origin,
    input: { token },
  });

  if (result.kind === "complete") {
    redirect("/profile?issued=email-domain");
  }

  if (result.kind === "continue") {
    redirect(`/badges/new/${result.pluginId}?wsid=${encodeURIComponent(result.sessionId)}`);
  }

  return (
    <ResultShell title="That didn't work">
      <CardDescription>{result.message}</CardDescription>
      <Button asChild variant="outline" className="mt-4 self-start">
        <Link href="/badges/new/email-domain">Restart</Link>
      </Button>
    </ResultShell>
  );
}

function ResultShell({ title, children }: { title: string; children: React.ReactNode }) {
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
