import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

import { RecoverBadgesClient } from "./recover-badges-client";

// Unauthenticated entry: recover an account by LIVE-re-proving badges you hold
// until the accumulated recovery weight crosses the threshold (slice 4). Each
// re-proof re-runs the real plugin verification bound to a fresh attempt nonce
// — a stored credential is never accepted (DESIGNDECISIONS #8). Crossing the
// threshold lands a reduced-capability (quarantined, AAL1 `recovered`) session
// whose only meaningful power is enrolling a new passkey (DESIGNDECISIONS #9).
//
// Today only the email-domain re-proof is wired end-to-end; oauth-account and
// tlsn-attestation re-proofs are scaffolded but not yet live.
export default function RecoverWithBadgesPage() {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Recover with your badges</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Re-prove enough of the badges on your account to recover access. The harder a badge is to
          forge, the more it counts.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Badge-threshold recovery</CardTitle>
          <CardDescription>
            Enter the email on the account. We&apos;ll show which badges you can re-prove and how
            much each is worth. Reaching the threshold signs you in with reduced access — add a
            passkey right away to restore full access.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RecoverBadgesClient />
        </CardContent>
      </Card>

      <p className="text-center text-xs text-neutral-500 dark:text-neutral-400">
        Recovering this way notifies every email on the account.
      </p>
    </div>
  );
}
