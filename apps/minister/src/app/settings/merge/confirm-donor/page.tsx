import Link from "next/link";

import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { completeDonorLink } from "@/server/merge-actions";

interface PageProps {
  searchParams: Promise<{ token?: string; s?: string; d?: string }>;
}

// Donor-side landing for the merge ceremony. The survivor asked to merge this
// account in; this page is reached by clicking the one-time link emailed to a
// verified donor address. It is intentionally NOT gated on a signed-in session:
// clicking the link IS the donor's authentication (it proves control of the
// donor inbox), exactly like the email-verify landing.
//
// completeDonorLink consumes the single-use link marker (bound to the survivor↔
// donor pair) and, only on success, mints a single-use donor-proof CODE. We show
// that code plus the donor account id for the human to bring back to the
// survivor's merge page (Step 2), where confirmMerge runs in the survivor's
// AAL2 session. The code is short-lived and single-use, so showing it here is
// the secure hand-off, not a standing secret.
export default async function ConfirmDonorPage({ searchParams }: PageProps) {
  const { token, s, d } = await searchParams;

  if (!token || !s || !d) {
    return (
      <ResultShell title="This link is incomplete">
        <CardDescription>
          The confirmation link is missing information. Ask whoever started the merge to send it
          again.
        </CardDescription>
        <BackButton />
      </ResultShell>
    );
  }

  const result = await completeDonorLink(token, s, d);

  if (!result.ok || !result.donorProof || !result.donorUserId) {
    return (
      <ResultShell title="Couldn't confirm this account">
        <CardDescription>
          {result.error ?? "This confirmation link is invalid, expired, or already used."}
        </CardDescription>
        <BackButton />
      </ResultShell>
    );
  }

  return (
    <ResultShell title="Confirmed — finish on the other account">
      <CardDescription>
        You&apos;ve confirmed you control this account. To complete the merge, go back to the
        account that started it and enter the two values below on its merge page. They expire in a
        few minutes and work only once.
      </CardDescription>

      <div className="mt-2 flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
            Account id
          </span>
          <div className="flex items-center gap-2">
            <code className="break-all rounded-md border border-neutral-200 bg-neutral-50 px-2 py-1 font-mono text-xs dark:border-neutral-800 dark:bg-neutral-900">
              {result.donorUserId}
            </code>
            <CopyButton value={result.donorUserId} label="Copy" />
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
            Confirmation code
          </span>
          <div className="flex flex-col gap-2">
            <code className="break-all rounded-md border border-neutral-200 bg-neutral-50 px-2 py-1 font-mono text-[11px] leading-relaxed dark:border-neutral-800 dark:bg-neutral-900">
              {result.donorProof}
            </code>
            <div>
              <CopyButton value={result.donorProof} label="Copy code" />
            </div>
          </div>
        </div>
      </div>

      <p className="mt-3 text-xs text-neutral-500 dark:text-neutral-400">
        After the merge completes, this account becomes part of the other one and can no longer be
        signed into on its own. If you didn&apos;t intend this, simply don&apos;t use the code above
        — nothing is merged until it&apos;s entered.
      </p>
    </ResultShell>
  );
}

function ResultShell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">{children}</CardContent>
      </Card>
    </div>
  );
}

function BackButton() {
  return (
    <Button asChild variant="outline" size="sm">
      <Link href="/settings">Back to settings</Link>
    </Button>
  );
}
