import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { completeEmailDomainReProof } from "@/server/recovery-threshold-actions";

interface PageProps {
  searchParams: Promise<{ token?: string }>;
}

// Landing page for the nonce-bound email-domain re-proof link (slice 4). The
// link was sent by requestEmailDomainReProof. Clicking it completes the LIVE
// re-proof: completeEmailDomainReProof verifies the token (authentic, single-
// use, nonce-bound) and records the proof against the attempt. This page is
// intentionally UNAUTHENTICATED — the whole flow is for a user who has lost
// their factors. The token itself is the capability; no session is consulted.
export default async function RecoverEmailVerifyPage({ searchParams }: PageProps) {
  const { token } = await searchParams;

  if (!token) {
    return (
      <Shell title="Missing token">
        <CardDescription>
          This link is malformed — it has no token attached. Restart badge recovery.
        </CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/recover/badges">Back to recovery</Link>
        </Button>
      </Shell>
    );
  }

  const result = await completeEmailDomainReProof(token);

  if (!result.ok) {
    return (
      <Shell title="That didn't work">
        <CardDescription>{result.error}</CardDescription>
        <Button asChild variant="outline" className="mt-4 self-start">
          <Link href="/recover/badges">Back to recovery</Link>
        </Button>
      </Shell>
    );
  }

  return (
    <Shell title="Email confirmed">
      <CardDescription>
        That proof was recorded
        {typeof result.accumulatedScore === "number" && typeof result.requiredScore === "number"
          ? ` — your recovery score is now ${result.accumulatedScore} of ${result.requiredScore}.`
          : "."}{" "}
        {result.satisfied
          ? "You've reached the threshold. Go back to recovery and finish to sign in."
          : "Go back to recovery, refresh your score, and re-prove more badges if you need to."}
      </CardDescription>
      <Button asChild className="mt-4 self-start">
        <Link href="/recover/badges">Back to recovery</Link>
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
