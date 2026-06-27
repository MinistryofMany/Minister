import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { verifyEmail } from "@/server/credential-actions";

interface PageProps {
  searchParams: Promise<{ token?: string }>;
}

// Email-verify landing. Intentionally NOT gated on a signed-in session: the
// magic-link token is the proof of control, and the owner may click it from an
// inbox that isn't signed into Minister in this browser. verifyEmail() consumes
// the single-use token and stamps the row verified; it scopes the token to the
// one UserEmail it was minted for, so it can only verify that address.
export default async function VerifyEmailPage({ searchParams }: PageProps) {
  const { token } = await searchParams;

  if (!token) {
    return (
      <ResultShell title="Missing token">
        <CardDescription>
          This verification link is malformed — it has no token attached.
        </CardDescription>
        <BackButton />
      </ResultShell>
    );
  }

  let verifiedEmail: string;
  try {
    const result = await verifyEmail(token);
    verifiedEmail = result.email;
  } catch (err) {
    const message = err instanceof Error ? err.message : "This verification link didn't work.";
    return (
      <ResultShell title="Couldn't verify that email">
        <CardDescription>{message}</CardDescription>
        <BackButton />
      </ResultShell>
    );
  }

  return (
    <ResultShell title="Email verified">
      <CardDescription>
        <span className="font-medium text-neutral-900 dark:text-neutral-100">{verifiedEmail}</span>{" "}
        is now verified on your account. You can make it your primary address from your credentials.
      </CardDescription>
      <BackButton />
    </ResultShell>
  );
}

function BackButton() {
  return (
    <Button asChild variant="outline" className="mt-4 self-start">
      <Link href="/settings/credentials">Back to credentials</Link>
    </Button>
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
