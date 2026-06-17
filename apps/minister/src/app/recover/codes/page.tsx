import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

import { RecoverCodesClient } from "./recover-codes-client";

// Unauthenticated entry: redeem a recovery code to regain access. This is the
// cold-start backstop for a user who lost their passkey and email access but
// kept their printed/stored codes. Redeeming lands a reduced-capability
// (quarantined, AAL1 `recovered`) session whose only meaningful power is
// enrolling a new passkey — it can't evict other credentials, change the
// primary email, start a merge, or disclose badges (DESIGNDECISIONS #9).
export default function RecoverWithCodesPage() {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Recover with a code</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Enter your email and one of your recovery codes. Each code works once.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Use a recovery code</CardTitle>
          <CardDescription>
            This signs you in with reduced access. You&apos;ll be asked to add a new passkey right
            away — until you do, your session can&apos;t change other credentials or disclose
            badges.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RecoverCodesClient />
        </CardContent>
      </Card>

      <p className="text-center text-xs text-neutral-500 dark:text-neutral-400">
        Recovering with a code notifies every email on the account.
      </p>
    </div>
  );
}
