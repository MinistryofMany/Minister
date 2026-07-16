"use client";

import { useState } from "react";

import { Card, CardContent } from "@/components/ui/card";
import { isVaultReady } from "@/lib/anon-seed/vault";
import type { AnonSeedStatus } from "@/server/anon-seed-actions";

import { EnrollmentFlow } from "./enrollment-flow";
import { UnlockPanel } from "./unlock-panel";

// Inline anonymous-identity section on the consent page (spec §6.2): rendered
// only for anon-enabled clients when the feature flag is on (the server
// withholds the prop otherwise). Drives enrollment (status none/pending) or
// unlock (active, vault locked) and reports readiness. Approval never blocks
// on this: an un-ready state just means the redirect carries no fragment
// (fail-open for login, fail-closed for identity, spec §8.3).

export interface AnonConsentView {
  appId: string;
  status: AnonSeedStatus;
  passkeyBlobCount: number;
  userId: string;
}

export function AnonConsentSection({
  anon,
  clientName,
  clearRef,
}: {
  anon: AnonConsentView;
  clientName: string;
  clearRef: React.MutableRefObject<(() => void) | null>;
}) {
  // "ready" = ACTIVE enrollment and this user's seed unlocked in the vault —
  // the fragment will be delivered after approve.
  const [ready, setReady] = useState(() => anon.status === "active" && isVaultReady(anon.userId));
  const [status, setStatus] = useState<AnonSeedStatus>(anon.status);

  return (
    <Card>
      <CardContent className="space-y-3 py-4">
        <div>
          <h3 className="text-sm font-semibold">Private Identity</h3>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            {clientName} supports anonymous writing. Your Private Identity stays in your browser —
            Ministry never sees it and never sends it anywhere.
          </p>
        </div>

        {ready ? (
          <p
            className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800 dark:border-green-900/40 dark:bg-green-950/30 dark:text-green-300"
            data-anon-ready="true"
          >
            Ready — your anonymous identity will be handed to {clientName} in your browser after you
            approve.
          </p>
        ) : status === "active" ? (
          <>
            <UnlockPanel
              userId={anon.userId}
              hasPasskeyBlobs={anon.passkeyBlobCount > 0}
              clearRef={clearRef}
              onUnlocked={() => setReady(true)}
            />
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              You can approve without unlocking — {clientName} then gets no anonymous identity until
              you connect it later.
            </p>
          </>
        ) : (
          <EnrollmentFlow
            userId={anon.userId}
            needsRestart={status === "pending_backup"}
            onComplete={() => {
              setStatus("active");
              setReady(isVaultReady(anon.userId));
            }}
          />
        )}
      </CardContent>
    </Card>
  );
}
