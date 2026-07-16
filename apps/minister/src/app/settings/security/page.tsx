import Link from "next/link";
import { redirect } from "next/navigation";

import { RecoveryCodesClient } from "@/app/settings/recovery-codes/recovery-codes-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loadPrivilegedGate } from "@/lib/credential-gate";
import { countUnusedCodes } from "@/lib/recovery-codes";
import { getCurrentSession } from "@/lib/session";

// Account recovery, consolidated: the two recovery paths that cover different
// failure modes (threshold badge re-proving as the primary, single-use recovery
// codes as the universal fallback) live under ONE section. Deliberately kept
// visually separate from the Private Identity page, because the two are opposite
// promises: the account CAN be recovered; the Private Identity canNOT — it can
// only be replaced (a new key, a new anonymous identity everywhere). See
// docs/identity-secrets-problem.md, O-3.
export default async function SecurityPage() {
  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  const [unused, gate] = await Promise.all([
    countUnusedCodes(session.user.id),
    loadPrivilegedGate(session.user.id, session.cred),
  ]);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Account recovery</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Two ways back into your account if you lose your passkey: re-prove enough of your badges,
          or use a recovery code. Either restores your account, badges, and app memberships.
        </p>
      </header>

      <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-200">
        Your <span className="font-medium">account</span> can be recovered — with badges or a
        recovery code. Your <span className="font-medium">Private Identity</span> is different: it
        lives only in your browser, so it{" "}
        <span className="font-medium">cannot be recovered, only replaced</span>. Manage it under{" "}
        <Link
          href="/settings/private-identity"
          className="underline underline-offset-2 hover:no-underline"
        >
          Private Identity
        </Link>
        .
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recover with your badges</CardTitle>
          <CardDescription>
            Re-prove a weighted set of the badges you already hold to regain access. Nothing to back
            up in advance — but it needs badges you can prove again right now.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            href="/recover/badges"
            className="block rounded-lg border border-neutral-200 p-3 transition hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-900"
          >
            <div className="text-sm font-medium">Start badge recovery</div>
            <div className="text-sm text-neutral-600 dark:text-neutral-400">
              Use this if you&apos;re locked out and can still prove your badges.
            </div>
          </Link>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recovery codes</CardTitle>
          <CardDescription>
            Single-use codes that work with no badges and no other account — the universal fallback.
            Generating them requires a passkey; store them somewhere safe.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RecoveryCodesClient initialUnused={unused} gate={gate} />
        </CardContent>
      </Card>
    </div>
  );
}
