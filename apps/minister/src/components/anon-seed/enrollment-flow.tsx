"use client";

import { useState, useTransition } from "react";

import {
  checkWordChallenge,
  encodeSeedToString,
  encodeSeedToWords,
  generateRootSeed,
  sampleWordChallengeIndices,
} from "@minister/shared";

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

// Enrollment: generate → forced backup → 3-word quiz → storage offers (anon
// identity master spec §6.3, §7). A vault-OWNED component (I4): the seed is
// generated here with crypto.getRandomValues, loaded straight into the vault,
// and rendered ONLY as the two backup forms (string + words) — the two
// permitted string surfaces (spec §12 check 14). Nothing here sends any codec
// form anywhere: no form elements, no fetch; the only server calls are the
// metadata-only enrollment actions. Backup is download + write-down; email is
// deliberately not offered (spec §2).

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
  | { step: "backup"; seedString: string; words: string[] }
  | { step: "quiz"; seedString: string; words: string[]; indices: number[] }
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
      const words = encodeSeedToWords(seed);
      // Into the vault immediately (not yet ACTIVE — no derivation until the
      // backup is confirmed, I3). The local copy is zeroized; the string and
      // words remain for the backup screen only.
      unlockVault(userId, seed, { active: false });
      seed.fill(0);
      setState({ step: "backup", seedString, words });
    });
  }

  function startQuiz(seedString: string, words: string[]) {
    setError(null);
    setState({ step: "quiz", seedString, words, indices: sampleWordChallengeIndices(3) });
  }

  function submitQuiz(words: string[], indices: number[], answers: string[]) {
    const responses = indices.map((index, i) => ({ index, answer: answers[i] ?? "" }));
    if (!checkWordChallenge(words, responses)) {
      // Fresh indices on every failure (spec §6.3 step 2).
      setError("That doesn't match. Check your backup and try the new words below.");
      setState((s) => (s.step === "quiz" ? { ...s, indices: sampleWordChallengeIndices(3) } : s));
      return;
    }
    setError(null);
    startTransition(async () => {
      const confirmed = await confirmSeedBackup();
      if (!confirmed.ok) {
        setError(confirmed.error);
        return;
      }
      markVaultActive(userId);
      // Drop the words/string from component state before the storage step —
      // the backup surfaces are done (best-effort scrubbing; spec check 14).
      setState({ step: "store" });
    });
  }

  switch (state.step) {
    case "intro":
      return (
        <div className="space-y-3">
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            One key, generated in your browser, gives you a separate anonymous identity in every
            connected app. Ministry never sees it and can never recover it — you must back it up
            yourself.
          </p>
          {error ? <ErrorNote message={error} /> : null}
          <Button type="button" onClick={generate} disabled={pending}>
            {pending
              ? "Working…"
              : needsRestart
                ? "Start over with a fresh key"
                : "Generate my key"}
          </Button>
          {needsRestart ? (
            <p className="text-xs text-neutral-500 dark:text-neutral-400">
              You started setting up earlier but never finished the backup, so that key was never
              used. Starting over is safe.
            </p>
          ) : null}
        </div>
      );
    case "backup":
      return (
        <BackupScreen
          seedString={state.seedString}
          words={state.words}
          onContinue={() => startQuiz(state.seedString, state.words)}
        />
      );
    case "quiz":
      return (
        <QuizScreen
          // Remount on every fresh index set so stale answers are cleared.
          key={state.indices.join("-")}
          indices={state.indices}
          pending={pending}
          error={error}
          onBack={() => {
            setError(null);
            setState({ step: "backup", seedString: state.seedString, words: state.words });
          }}
          onSubmit={(answers) => submitQuiz(state.words, state.indices, answers)}
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

function BackupScreen({
  seedString,
  words,
  onContinue,
}: {
  seedString: string;
  words: string[];
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-sm font-semibold">Back up your key — this is the only copy</h4>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Save the file or write down the 12 words. Ministry cannot recover this key; losing it
          means losing your anonymous identities for good.
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

      <ol className="grid grid-cols-3 gap-x-4 gap-y-1 rounded-md border border-neutral-200 p-3 text-sm dark:border-neutral-800 sm:grid-cols-4">
        {words.map((w, i) => (
          <li key={i} className="flex items-baseline gap-1.5">
            <span className="w-5 text-right text-xs tabular-nums text-neutral-400">{i + 1}.</span>
            <span className="font-mono">{w}</span>
          </li>
        ))}
      </ol>

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => downloadBackupFile(seedString, words)}
        >
          Download backup file
        </Button>
        <Button type="button" onClick={onContinue}>
          I&apos;ve saved it — continue
        </Button>
      </div>
    </div>
  );
}

function QuizScreen({
  indices,
  pending,
  error,
  onBack,
  onSubmit,
}: {
  indices: number[];
  pending: boolean;
  error: string | null;
  onBack: () => void;
  onSubmit: (answers: string[]) => void;
}) {
  // The parent remounts this component (keyed on the index set) after a
  // failure, so answers always start clean for fresh indices.
  const [answers, setAnswers] = useState<string[]>(() => indices.map(() => ""));
  return (
    <div className="space-y-3">
      <div>
        <h4 className="text-sm font-semibold">Prove you saved it</h4>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Type these words from your backup to continue.
        </p>
      </div>
      {error ? <ErrorNote message={error} /> : null}
      <div className="flex flex-col gap-2">
        {indices.map((idx, i) => (
          <label key={idx} className="flex items-center gap-3 text-sm">
            <span className="w-20 shrink-0 text-neutral-600 dark:text-neutral-400">
              Word #{idx}
            </span>
            <Input
              value={answers[i] ?? ""}
              onChange={(e) => setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              aria-label={`Word number ${idx}`}
            />
          </label>
        ))}
      </div>
      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={onBack} disabled={pending}>
          Back to my key
        </Button>
        <Button
          type="button"
          onClick={() => onSubmit(answers)}
          disabled={pending || answers.some((a) => a.trim().length === 0)}
        >
          {pending ? "Working…" : "Check words"}
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
            ? "You've chosen never to store your key. It stays in memory for this page only."
            : "Optional — either option saves you retyping the key next time. Skipping keeps it in memory for this page only."}
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
function downloadBackupFile(seedString: string, words: string[]): void {
  const content = [
    "Ministry anonymous writing key — backup",
    `Saved: ${new Date().toISOString().slice(0, 10)}`,
    "",
    `Key: ${seedString}`,
    "",
    "Words:",
    ...words.map((w, i) => `${String(i + 1).padStart(2, " ")}. ${w}`),
    "",
    "Ministry cannot recover this key. Anyone who has it can write as your",
    "anonymous identity in every connected app. Keep it private.",
    "",
  ].join("\n");
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "ministry-anonymous-key.txt";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
