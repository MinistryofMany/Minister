"use client";

import { useState } from "react";

import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { generateMyRecoveryCodes } from "@/server/recovery-code-actions";

// Client island for the recovery-codes settings page. Generating codes is a
// destructive, view-once operation: we make the user confirm, render the
// plaintext exactly once (never re-fetchable), and offer copy + download. The
// plaintext lives only in this component's state and is gone on navigation.

type Phase = "idle" | "confirm" | "shown";

export function RecoveryCodesClient({ initialUnused }: { initialUnused: number }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [unused, setUnused] = useState(initialUnused);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasCodes = unused > 0;

  async function handleGenerate() {
    setPending(true);
    setError(null);
    try {
      const result = await generateMyRecoveryCodes();
      setCodes(result.codes);
      setUnused(result.codes.length);
      setPhase("shown");
    } catch (e) {
      // requireAal throws StepUpRequiredError when the session is below AAL2.
      const message = e instanceof Error ? e.message : "Could not generate recovery codes.";
      setError(
        message.startsWith("Step-up required")
          ? "You need to sign in with a passkey before you can generate recovery codes."
          : message,
      );
    } finally {
      setPending(false);
    }
  }

  if (phase === "shown" && codes) {
    return <ViewOnce codes={codes} onDone={() => setPhase("idle")} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        {hasCodes
          ? `You have ${unused} unused recovery ${unused === 1 ? "code" : "codes"}. Generating a new set invalidates the unused ones.`
          : "You don't have any recovery codes yet. Generate a set and store them somewhere safe."}
      </p>

      {phase === "confirm" ? (
        <div className="flex flex-col gap-3 rounded-md border border-amber-300 bg-amber-50 p-4 text-sm dark:border-amber-900 dark:bg-amber-950/40">
          <p className="font-medium">
            {hasCodes
              ? "Regenerating will invalidate your existing unused codes. Continue?"
              : "Generate recovery codes? You'll see them only once."}
          </p>
          <div className="flex flex-wrap gap-3">
            <Button onClick={handleGenerate} disabled={pending}>
              {pending ? "Generating…" : hasCodes ? "Regenerate codes" : "Generate codes"}
            </Button>
            <Button variant="ghost" onClick={() => setPhase("idle")} disabled={pending}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div>
          <Button onClick={() => setPhase("confirm")}>
            {hasCodes ? "Regenerate recovery codes" : "Generate recovery codes"}
          </Button>
        </div>
      )}

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
    </div>
  );
}

function ViewOnce({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const blob = codes.join("\n");
  const downloadHref = `data:text/plain;charset=utf-8,${encodeURIComponent(`${blob}\n`)}`;

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md border border-amber-300 bg-amber-50 p-4 text-sm dark:border-amber-900 dark:bg-amber-950/40">
        <p className="font-medium">Save these now - this is the only time they&apos;re shown.</p>
        <p className="mt-1 text-neutral-600 dark:text-neutral-400">
          Each code works once. Store them in a password manager or print them. Anyone with a code
          can start account recovery, so keep them private.
        </p>
      </div>

      <ul className="grid grid-cols-1 gap-2 rounded-md border border-neutral-200 bg-neutral-50 p-4 font-mono text-sm dark:border-neutral-800 dark:bg-neutral-900 sm:grid-cols-2">
        {codes.map((code) => (
          <li key={code} className="tracking-widest">
            {code}
          </li>
        ))}
      </ul>

      <div className="flex flex-wrap gap-3">
        <CopyButton value={blob} label="Copy all" />
        <Button asChild variant="outline" size="sm">
          <a href={downloadHref} download="minister-recovery-codes.txt">
            Download .txt
          </a>
        </Button>
        <Button variant="ghost" size="sm" onClick={onDone}>
          I&apos;ve saved them
        </Button>
      </div>
    </div>
  );
}
