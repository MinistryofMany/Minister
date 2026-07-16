"use client";

import { useState, useTransition } from "react";

import { encodeSeedToString, generateRootSeed } from "@minister/shared";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getMemoryOnlyPref, markVaultActive, unlockVault } from "@/lib/anon-seed/vault";
import {
  beginAnonSeedEnrollment,
  confirmSeedBackup,
  resetAnonSeed,
} from "@/server/anon-seed-actions";

import { PasskeyProtectButton } from "./passkey-protect-button";
import { PmSave } from "./pm-save";

// Enrollment: generate → forced backup → retype-to-confirm → storage offers
// (anon identity master spec §6.3, §7). A vault-OWNED component (I4): the seed is
// generated here with crypto.getRandomValues, loaded straight into the vault,
// and rendered ONLY as the canonical 28-character backup string (the single
// permitted backup format, decision O-2; the 12-word codec was retired).
// Nothing here sends any codec form anywhere: no form elements, no fetch; the
// only server calls are the metadata-only enrollment actions. Backup is
// download + write-down; email is deliberately not offered (spec §2).

interface Props {
  userId: string;
  // True when a previous enrollment stalled in PENDING_BACKUP: generating
  // fresh runs the free reset first (spec §6.1 — nothing derived, nothing
  // lost; the epoch bump invalidates any stray blobs).
  needsRestart: boolean;
  onComplete: () => void;
}

type Step =
  | { step: "intro" }
  | { step: "backup"; seedString: string }
  | { step: "confirm"; seedString: string }
  | { step: "store" };

export function EnrollmentFlow({ userId, needsRestart, onComplete }: Props) {
  const [state, setState] = useState<Step>({ step: "intro" });
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function generate() {
    setError(null);
    startTransition(async () => {
      if (needsRestart) {
        // Free PENDING reset; ignore "nothing to reset" (already none).
        await resetAnonSeed({});
      }
      const begun = await beginAnonSeedEnrollment();
      if (!begun.ok) {
        setError(begun.error);
        return;
      }
      const seed = generateRootSeed();
      const seedString = encodeSeedToString(seed);
      // Into the vault immediately (not yet ACTIVE — no derivation until the
      // backup is confirmed, I3), bound to the epoch the server just stamped on
      // the enrollment row so a later derivation is epoch-consistent (Lane C).
      // The local copy is zeroized; the string remains for the backup screen only.
      await unlockVault(userId, seed, { active: false, epoch: begun.state.enrollmentEpoch });
      seed.fill(0);
      setState({ step: "backup", seedString });
    });
  }

  function submitConfirm(seedString: string, typed: string) {
    // Retype-to-confirm is a UX forcing function (spec §6.3), never a security
    // control: an exact match against the string just shown proves the user
    // captured it. Compare verbatim (the string is case-sensitive base58check).
    if (typed.trim() !== seedString) {
      setError("That doesn't match your Private Identity. Check your backup and try again.");
      return;
    }
    setError(null);
    startTransition(async () => {
      const confirmed = await confirmSeedBackup();
      if (!confirmed.ok) {
        setError(confirmed.error);
        return;
      }
      await markVaultActive(userId);
      // Drop the string from component state before the storage step — the
      // backup surface is done (best-effort scrubbing; spec check 14).
      setState({ step: "store" });
    });
  }

  switch (state.step) {
    case "intro":
      return (
        <div className="space-y-3">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Your Private Identity, generated in your browser, gives you a separate anonymous
            identity in every connected app. Ministry never sees it and can never recover it — you
            must back it up yourself.
          </p>
          {error ? <ErrorNote message={error} /> : null}
          <Button type="button" onClick={generate} disabled={pending}>
            {pending
              ? "Working…"
              : needsRestart
                ? "Start over with a fresh Private Identity"
                : "Generate my Private Identity"}
          </Button>
          {needsRestart ? (
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              You started setting up earlier but never finished the backup, so that Private Identity
              was never used. Starting over is safe.
            </p>
          ) : null}
        </div>
      );
    case "backup":
      return (
        <BackupScreen
          seedString={state.seedString}
          onContinue={() => {
            setError(null);
            setState({ step: "confirm", seedString: state.seedString });
          }}
        />
      );
    case "confirm":
      return (
        <ConfirmScreen
          pending={pending}
          error={error}
          onBack={() => {
            setError(null);
            setState({ step: "backup", seedString: state.seedString });
          }}
          onSubmit={(typed) => submitConfirm(state.seedString, typed)}
        />
      );
    case "store":
      return <StoreStep userId={userId} onDone={onComplete} />;
  }
}

function ErrorNote({ message }: { message: string }) {
  return (
    <p className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
      {message}
    </p>
  );
}

function BackupScreen({ seedString, onContinue }: { seedString: string; onContinue: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-sm font-semibold">
          Back up your Private Identity — this is the only copy
        </h4>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Save the file or write down this key. Ministry cannot recover this Private Identity;
          losing it means losing your anonymous identities for good.
        </p>
      </div>

      <div className="rounded-md border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-neutral-900/40">
        <div className="flex items-center justify-between gap-2">
          <code className="break-all font-mono text-sm">{seedString}</code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(seedString);
                setCopied(true);
              } catch {
                setCopied(false);
              }
            }}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" onClick={() => downloadBackupFile(seedString)}>
          Download backup file
        </Button>
        <Button type="button" onClick={onContinue}>
          I&apos;ve saved it — continue
        </Button>
      </div>
    </div>
  );
}

function ConfirmScreen({
  pending,
  error,
  onBack,
  onSubmit,
}: {
  pending: boolean;
  error: string | null;
  onBack: () => void;
  onSubmit: (typed: string) => void;
}) {
  const [typed, setTyped] = useState("");
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-sm font-semibold">Prove you saved it</h4>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Type or paste your Private Identity key from your backup to continue.
        </p>
      </div>
      {error ? <ErrorNote message={error} /> : null}
      <Input
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        aria-label="Your Private Identity key"
        className="font-mono"
      />
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={onBack} disabled={pending}>
          Back to my Private Identity
        </Button>
        <Button
          type="button"
          onClick={() => onSubmit(typed)}
          disabled={pending || typed.trim().length === 0}
        >
          {pending ? "Working…" : "Confirm"}
        </Button>
      </div>
    </div>
  );
}

function StoreStep({ userId, onDone }: { userId: string; onDone: () => void }) {
  const memoryOnly = getMemoryOnlyPref(userId);
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-sm font-semibold">Backed up. Keep it handy on this device?</h4>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          {memoryOnly
            ? "You've chosen never to store your Private Identity. It stays in memory for this page only."
            : "Optional — either option saves you retyping your Private Identity next time. Skipping keeps it in memory for this page only."}
        </p>
      </div>
      {memoryOnly ? null : (
        <div className="flex flex-col gap-3">
          <PasskeyProtectButton userId={userId} />
          <PmSave userId={userId} />
        </div>
      )}
      <Button type="button" onClick={onDone}>
        {memoryOnly ? "Continue" : "Done"}
      </Button>
    </div>
  );
}

// The backup file (spec §6.3 step 1): built and downloaded entirely
// client-side via a Blob object URL — no request carries it anywhere.
function downloadBackupFile(seedString: string): void {
  const content = [
    "Ministry Private Identity — backup",
    `Saved: ${new Date().toISOString().slice(0, 10)}`,
    "",
    `Key: ${seedString}`,
    "",
    "Ministry cannot recover this Private Identity. Anyone who has it can write as your",
    "anonymous identity in every connected app. Keep it private.",
    "",
  ].join("\n");
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "ministry-private-identity.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
