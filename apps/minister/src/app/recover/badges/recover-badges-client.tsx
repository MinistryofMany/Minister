"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  finishBadgeRecovery,
  getRecoveryStatus,
  requestEmailDomainReProof,
  startBadgeRecovery,
} from "@/server/recovery-threshold-actions";

// Unauthenticated badge-threshold recovery flow. Three phases:
//   1. enter the account email -> startBadgeRecovery -> get attemptId +
//      required score + the recovery-eligible badge types this account holds.
//   2. drive a LIVE re-proof per type. Only email-domain is wired: the user
//      enters an address at a held domain, we send a nonce-bound link; clicking
//      it (a separate page) records the proof. The user returns here and we
//      re-poll the score.
//   3. once satisfied, finishBadgeRecovery consumes the attempt + signs in;
//      we route to passkey enrollment.
//
// Where to land after recovery — the recovered session's main power is adding a
// passkey to climb back to AAL2.
const POST_RECOVERY_PATH = "/settings/credentials";

interface AttemptView {
  attemptId: string;
  requiredScore: number;
  provableTypes: string[];
  domains: string[];
}

interface ScoreView {
  accumulatedScore: number;
  requiredScore: number;
  satisfied: boolean;
  provenTypes: string[];
}

const TYPE_LABELS: Record<string, string> = {
  "email-domain": "Email domain",
  "email-exact": "Email address",
  "oauth-account": "Linked account (GitHub/Google/…)",
  "tlsn-attestation": "TLSNotary attestation",
};

const WIRED_TYPES = new Set(["email-domain"]);

export function RecoverBadgesClient() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [attempt, setAttempt] = useState<AttemptView | null>(null);
  const [score, setScore] = useState<ScoreView | null>(null);
  const [reproofEmail, setReproofEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function handleStart(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      const result = await startBadgeRecovery(email);
      if (!result.ok) {
        setError(result.error ?? "Could not start recovery.");
        return;
      }
      if (!result.attemptId || (result.provableTypes?.length ?? 0) === 0) {
        // Anti-enumeration: identical message whether the account is missing or
        // simply has no re-provable badges.
        setNotice(
          "If an account with that email exists and has re-provable badges, its recovery options are shown above. This account has none we can use, so badge recovery isn't available — try a recovery code instead.",
        );
        return;
      }
      setAttempt({
        attemptId: result.attemptId,
        requiredScore: result.requiredScore ?? 0,
        provableTypes: result.provableTypes ?? [],
        domains: result.domains ?? [],
      });
      setScore({
        accumulatedScore: 0,
        requiredScore: result.requiredScore ?? 0,
        satisfied: false,
        provenTypes: [],
      });
    } catch {
      setError("Something went wrong. Try again.");
    } finally {
      setPending(false);
    }
  }

  async function handleSendEmailReProof(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!attempt) return;
    setPending(true);
    setError(null);
    setNotice(null);
    try {
      const result = await requestEmailDomainReProof(attempt.attemptId, reproofEmail);
      if (!result.ok) {
        setError(result.error ?? "Could not send the verification email.");
        return;
      }
      setSent(true);
      setNotice(
        "Check that inbox for a verification link. Open it (it confirms your control of the address), then come back here and refresh your score.",
      );
    } catch {
      setError("Something went wrong. Try again.");
    } finally {
      setPending(false);
    }
  }

  async function handleRefreshScore() {
    if (!attempt) return;
    setPending(true);
    setError(null);
    try {
      const status = await getRecoveryStatus(attempt.attemptId);
      if (!status) {
        setError("This recovery attempt is no longer available. Start over.");
        return;
      }
      setScore({
        accumulatedScore: status.accumulatedScore,
        requiredScore: status.requiredScore,
        satisfied: status.satisfied,
        provenTypes: status.provenTypes,
      });
    } catch {
      setError("Could not refresh. Try again.");
    } finally {
      setPending(false);
    }
  }

  async function handleFinish() {
    if (!attempt) return;
    setPending(true);
    setError(null);
    try {
      const result = await finishBadgeRecovery(attempt.attemptId);
      if (!result.ok) {
        setError(result.error ?? "Could not complete recovery.");
        return;
      }
      router.replace(POST_RECOVERY_PATH);
      router.refresh();
    } catch {
      setError("Something went wrong. Try again.");
    } finally {
      setPending(false);
    }
  }

  // Phase 1: enter the account email.
  if (!attempt) {
    return (
      <form onSubmit={handleStart} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Account email</span>
          <Input
            type="email"
            name="email"
            autoComplete="email"
            placeholder="you@example.com"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <Button type="submit" className="w-full" disabled={pending}>
          {pending ? "Checking…" : "Start recovery"}
        </Button>
        {error ? <p className="text-sm text-red-600">{error}</p> : null}
        {notice ? <p className="text-sm text-neutral-600 dark:text-neutral-400">{notice}</p> : null}
      </form>
    );
  }

  // Phase 2/3: drive re-proofs and watch the score.
  const remaining = score ? Math.max(0, score.requiredScore - score.accumulatedScore) : 0;
  const canEmailReProof =
    attempt.provableTypes.includes("email-domain") && attempt.domains.length > 0;

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md border border-neutral-200 p-3 text-sm dark:border-neutral-800">
        <div className="flex items-baseline justify-between">
          <span className="font-medium">Recovery score</span>
          <span className="font-mono">
            {score?.accumulatedScore ?? 0} / {score?.requiredScore ?? attempt.requiredScore}
          </span>
        </div>
        {score?.satisfied ? (
          <p className="mt-1 text-green-700 dark:text-green-400">
            Threshold reached. Finish to sign in.
          </p>
        ) : (
          <p className="mt-1 text-neutral-600 dark:text-neutral-400">
            {remaining} more point{remaining === 1 ? "" : "s"} needed. Re-prove badges below.
          </p>
        )}
        {score && score.provenTypes.length > 0 ? (
          <p className="mt-1 text-xs text-neutral-500">
            Proven: {score.provenTypes.map((t) => TYPE_LABELS[t] ?? t).join(", ")}
          </p>
        ) : null}
      </div>

      <div>
        <p className="mb-2 text-sm font-medium">Badges you can re-prove</p>
        <ul className="flex flex-col gap-1 text-sm">
          {attempt.provableTypes.map((t) => (
            <li key={t} className="flex items-center justify-between">
              <span>{TYPE_LABELS[t] ?? t}</span>
              {!WIRED_TYPES.has(t) ? (
                <span className="text-xs text-neutral-500">re-proof not yet available</span>
              ) : null}
            </li>
          ))}
        </ul>
      </div>

      {canEmailReProof && !score?.satisfied ? (
        <form
          onSubmit={handleSendEmailReProof}
          className="flex flex-col gap-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800"
        >
          <p className="text-sm font-medium">Re-prove an email domain</p>
          <p className="text-xs text-neutral-500">
            Enter an address at one of these domains: {attempt.domains.join(", ")}. We&apos;ll send
            a one-time link to confirm you still control it.
          </p>
          <Input
            type="email"
            name="reproofEmail"
            autoComplete="email"
            placeholder="you@yourdomain.com"
            required
            value={reproofEmail}
            onChange={(e) => setReproofEmail(e.target.value)}
          />
          <Button type="submit" variant="outline" disabled={pending}>
            {pending ? "Sending…" : sent ? "Resend link" : "Send verification link"}
          </Button>
        </form>
      ) : null}

      <div className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={handleRefreshScore}
          disabled={pending}
        >
          Refresh score
        </Button>
        <Button
          type="button"
          className="flex-1"
          onClick={handleFinish}
          disabled={pending || !score?.satisfied}
        >
          {pending ? "Working…" : "Finish & sign in"}
        </Button>
      </div>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      {notice ? <p className="text-sm text-neutral-600 dark:text-neutral-400">{notice}</p> : null}
    </div>
  );
}
