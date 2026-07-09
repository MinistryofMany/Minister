import { redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getCurrentSession } from "@/lib/session";

import { MergeClient } from "./merge-client";

interface PageProps {
  // `donor` is prefilled when the user arrives here from the credentials page,
  // after trying to add an email that already belongs to another account. It is
  // only a convenience prefill; the merge still emails that address a prove-it
  // link, so control of it is proven before anything is merged.
  searchParams: Promise<{ donor?: string }>;
}

// Account-merge ceremony entry (slice 5). The signed-in account is the SURVIVOR
// (DESIGNDECISIONS #12): it keeps its id and its RP identities, and absorbs the
// donor. The page renders for any signed-in user; the AAL2 floor + not-recovered
// checks are enforced inside the server actions (startMerge / confirmMerge),
// which surface a step-up prompt the client catches.
//
// There is no standing link to this page: it is reached only from the
// credential-collision offer (adding an email already on another account) or a
// donor confirmation link. That keeps merge out of the way until it's relevant.
export default async function MergePage({ searchParams }: PageProps) {
  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  const { donor } = await searchParams;
  const prefillDonor = typeof donor === "string" ? donor.trim().slice(0, 320) : "";

  // The client shows a clear warning when the session is below AAL2 or is a
  // recovered session, before the user even tries — the action is the real gate.
  const belowAal2 = (session.aal ?? 0) < 2;
  const recovered = session.recovered === true;

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Merge another account in</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Combine a second Minister account into this one. This account stays the one you sign in
          to; the other becomes part of it and can no longer be used on its own.
        </p>
      </header>

      {prefillDonor ? (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
          <p>
            <span className="font-medium">{prefillDonor}</span> already belongs to another Minister
            account. If that account is also yours, confirm you control that address below to
            combine it into this one.
          </p>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>What a merge does</CardTitle>
          <CardDescription>Read this before you start — a merge is far-reaching.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-neutral-700 dark:text-neutral-300">
          <ul className="list-disc space-y-2 pl-5">
            <li>
              <strong>This account is kept.</strong> Its sign-in id, your linked apps, and your
              settings stay exactly as they are.
            </li>
            <li>
              <strong>The other account&apos;s data moves here:</strong> its emails, passkeys,
              linked logins, badges, share links, and recovery codes all become part of this
              account.
            </li>
            <li>
              <strong>Apps you signed into stay connected.</strong> For any app the other account
              used that this one didn&apos;t, this account keeps presenting that app the same
              identity, so you stay signed in there.
            </li>
            <li>
              <strong>One thing can&apos;t be carried over:</strong> if BOTH accounts signed into
              the same app, that app can only ever see one of you. This account&apos;s identity wins
              there, and the other account&apos;s identity for that one app is left behind.
              You&apos;ll see the exact list after the merge.
            </li>
            <li>
              <strong>The other account is closed</strong> and can be restored for a limited time if
              this was a mistake.
            </li>
          </ul>
          {recovered ? (
            <p className="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
              You&apos;re in a recovered session. Add a passkey and sign in with it before you can
              merge accounts.
            </p>
          ) : belowAal2 ? (
            <p className="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
              Merging requires a passkey. Sign in with your passkey first, then come back here.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <MergeClient blocked={recovered || belowAal2} initialDonorEmail={prefillDonor} />
    </div>
  );
}
