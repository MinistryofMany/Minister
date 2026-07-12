"use client";

import { useState } from "react";
import { signIn as signInWebAuthn } from "next-auth/webauthn";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  confirmMerge,
  startMerge,
  type ConfirmMergeResult,
  type StartMergeResult,
} from "@/server/merge-actions";

// Client island driving the survivor side of the merge ceremony. Three phases:
//   1. "start"   — the survivor enters the donor email; startMerge mails a
//      prove-it link to it. We always advance to "await-proof" (anti-enumeration:
//      a hit and a miss look identical to the survivor).
//   2. "confirm" — the donor clicked the emailed link in (their copy of) the
//      browser, got a one-time confirmation code, and the survivor pastes it +
//      the donor id here. confirmMerge verifies it and runs the merge.
//   3. "done"    — show what moved and, crucially, the stranded-app list.
//
// The donor-proof code and the donor id both come from the confirm-donor page
// the magic link lands on. Pasting them here keeps confirmMerge running in the
// SURVIVOR session, which is where the AAL2 + not-recovered + quarantine gates
// live. Refusals arrive as TYPED results (stepUp / quarantine), never as
// thrown errors (a thrown server-action error is an opaque digest in prod):
// when a passkey ceremony can clear the refusal we run it and retry once.

type Phase = "start" | "await-proof" | "done";

interface DoneState {
  moved: Record<string, number>;
  overridesCreated: number;
  strandedClients: string[];
}

// True when a passkey ceremony (step-up or re-auth with an established
// passkey) can clear this refusal right now.
function ceremonyCanClear(result: StartMergeResult | ConfirmMergeResult): boolean {
  if (result.ok) return false;
  return result.stepUp === true || result.quarantine?.canStepUp === true;
}

// Run the passkey ceremony in place; true on success.
async function passkeyCeremony(): Promise<boolean> {
  try {
    const res = await signInWebAuthn("passkey", { redirect: false });
    return !(res && "error" in res && res.error);
  } catch {
    return false;
  }
}

export function MergeClient({
  blocked,
  initialDonorEmail = "",
}: {
  blocked: boolean;
  initialDonorEmail?: string;
}) {
  const [phase, setPhase] = useState<Phase>("start");
  const [donorEmail, setDonorEmail] = useState(initialDonorEmail);
  const [donorProof, setDonorProof] = useState("");
  const [donorUserId, setDonorUserId] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<DoneState | null>(null);

  // Run a merge action; when a passkey ceremony can clear its refusal, run
  // the ceremony and retry exactly once. Returns the final result, or null if
  // the ceremony was abandoned/failed.
  async function withPasskeyRetry<T extends StartMergeResult | ConfirmMergeResult>(
    call: () => Promise<T>,
  ): Promise<T | null> {
    const first = await call();
    if (!ceremonyCanClear(first)) return first;
    if (!(await passkeyCeremony())) return null;
    return call();
  }

  async function handleStart() {
    setPending(true);
    setError(null);
    try {
      const result = await withPasskeyRetry(() => startMerge(donorEmail));
      if (result === null) {
        setError("Confirming with a passkey is required and was not completed.");
        return;
      }
      if (!result.ok) {
        setError(result.error ?? "Could not start the merge.");
        return;
      }
      setPhase("await-proof");
    } catch {
      setError("Could not start the merge. Please try again.");
    } finally {
      setPending(false);
    }
  }

  async function handleConfirm() {
    setPending(true);
    setError(null);
    try {
      const result = await withPasskeyRetry(() =>
        confirmMerge(donorProof.trim(), donorUserId.trim()),
      );
      if (result === null) {
        setError("Confirming with a passkey is required and was not completed.");
        return;
      }
      if (!result.ok) {
        setError(result.error ?? "Could not complete the merge.");
        return;
      }
      setDone({
        moved: result.moved ?? {},
        overridesCreated: result.overridesCreated ?? 0,
        strandedClients: result.strandedClients ?? [],
      });
      setPhase("done");
    } catch {
      setError("Could not complete the merge. Please try again.");
    } finally {
      setPending(false);
    }
  }

  if (phase === "done" && done) {
    return <MergeDone done={done} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col gap-3 rounded-md border border-neutral-200 p-4 dark:border-neutral-800">
        <h2 className="text-sm font-semibold">Step 1 — Send a confirmation to the other account</h2>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Enter a verified email on the account you want to merge in. We&apos;ll email it a one-time
          link to confirm you control it too.
        </p>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            type="email"
            inputMode="email"
            autoComplete="off"
            placeholder="other-account@example.com"
            value={donorEmail}
            onChange={(e) => setDonorEmail(e.target.value)}
            disabled={blocked || pending || phase !== "start"}
          />
          <Button onClick={handleStart} disabled={blocked || pending || phase !== "start"}>
            {pending && phase === "start" ? "Sending…" : "Send confirmation"}
          </Button>
        </div>
        {phase === "await-proof" ? (
          <p className="text-sm text-green-700 dark:text-green-400">
            If that account exists, a confirmation link is on its way. Open it, then bring back the
            confirmation code and account id it shows.
          </p>
        ) : null}
      </section>

      <section className="flex flex-col gap-3 rounded-md border border-neutral-200 p-4 dark:border-neutral-800">
        <h2 className="text-sm font-semibold">Step 2 — Finish the merge</h2>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          After opening the link from the other account, paste the confirmation code and account id
          it gave you here. This is the point of no easy return — the merge runs immediately.
        </p>
        <label className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
          Account id (from the confirmation page)
        </label>
        <Input
          autoComplete="off"
          placeholder="user_…"
          value={donorUserId}
          onChange={(e) => setDonorUserId(e.target.value)}
          disabled={blocked || pending}
        />
        <label className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
          Confirmation code
        </label>
        <Input
          autoComplete="off"
          placeholder="Paste the confirmation code"
          value={donorProof}
          onChange={(e) => setDonorProof(e.target.value)}
          disabled={blocked || pending}
        />
        <div>
          <Button
            onClick={handleConfirm}
            disabled={blocked || pending || !donorProof.trim() || !donorUserId.trim()}
          >
            {pending && phase !== "start" ? "Merging…" : "Merge the accounts"}
          </Button>
        </div>
      </section>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
    </div>
  );
}

function MergeDone({ done }: { done: DoneState }) {
  const movedEntries = Object.entries(done.moved).filter(([, n]) => n > 0);

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md border border-green-300 bg-green-50 p-4 text-sm dark:border-green-900 dark:bg-green-950/40">
        <p className="font-medium text-green-800 dark:text-green-200">
          The accounts were merged. The other account is now part of this one.
        </p>
      </div>

      {movedEntries.length > 0 ? (
        <div className="rounded-md border border-neutral-200 p-4 dark:border-neutral-800">
          <h3 className="mb-2 text-sm font-semibold">What moved over</h3>
          <ul className="grid grid-cols-2 gap-1 text-sm text-neutral-700 dark:text-neutral-300">
            {movedEntries.map(([k, n]) => (
              <li key={k}>
                {k}: {n}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {done.strandedClients.length > 0 ? (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm dark:border-amber-900 dark:bg-amber-950/40">
          <h3 className="mb-1 font-semibold text-amber-800 dark:text-amber-200">
            Left behind ({done.strandedClients.length})
          </h3>
          <p className="text-amber-800 dark:text-amber-200">
            Both accounts had signed into the apps below. Each app can only see one of you, so this
            account&apos;s identity is what they keep. The other account&apos;s identity for these
            apps could not be carried over:
          </p>
          <ul className="mt-2 list-disc pl-5 font-mono text-xs text-amber-900 dark:text-amber-100">
            {done.strandedClients.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          No app identities were left behind — every app the other account used is now carried by
          this one.
        </p>
      )}
    </div>
  );
}
