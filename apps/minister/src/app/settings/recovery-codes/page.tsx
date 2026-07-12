import { redirect } from "next/navigation";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loadPrivilegedGate } from "@/lib/credential-gate";
import { countUnusedCodes } from "@/lib/recovery-codes";
import { getCurrentSession } from "@/lib/session";

import { RecoveryCodesClient } from "./recovery-codes-client";

// Authenticated page to generate / regenerate recovery codes and view them
// once. The action itself (generateMyRecoveryCodes) enforces the AAL2 floor
// and the H-1 quarantine gate; we only require a signed-in session to render.
// The gate verdict is precomputed here so the page can explain a hold BEFORE
// the user tries (kind copy up front, the action stays the real gate).
export default async function RecoveryCodesPage() {
  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  const [unused, gate] = await Promise.all([
    countUnusedCodes(session.user.id),
    loadPrivilegedGate(session.user.id, session.cred),
  ]);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Recovery codes</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          One-time codes that let you sign in if you lose your passkey and email. Store them
          somewhere safe.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Your recovery codes</CardTitle>
          <CardDescription>
            Generating recovery codes requires a passkey. A recovered session is reduced-capability
            until you enroll a new passkey, so keep at least one strong factor when you can.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RecoveryCodesClient initialUnused={unused} gate={gate} />
        </CardContent>
      </Card>
    </div>
  );
}
