"use client";

import Link from "next/link";
import { signIn } from "next-auth/webauthn";
import { useState, useTransition } from "react";

import { EnrollmentFlow } from "@/components/anon-seed/enrollment-flow";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { rekeyAnonSeed } from "@/server/anon-seed-actions";

// Client half of re-key. Three phases: confirm (typed phrase → server gates and
// the destructive epoch bump), enroll (generate + forced backup of the NEW root
// at the bumped epoch), checklist (sign back into each connected app to swap the
// leaf there on next login). No key material touches the server at any phase.

const REKEY_PHRASE = "re-key my identity";

interface AppItem {
  appName: string;
}

type Phase = "confirm" | "enroll" | "checklist";

export function RekeyClient({ userId, apps }: { userId: string; apps: AppItem[] }) {
  const [phase, setPhase] = useState<Phase>("confirm");

  return (
    <>
      {phase === "confirm" ? (
        <ConfirmCard onDone={() => setPhase("enroll")} />
      ) : phase === "enroll" ? (
        <Card>
          <CardHeader>
            <CardTitle>Back up your new Private Identity</CardTitle>
            <CardDescription>
              A fresh key was generated in your browser. Back it up now — this new one also can
              never be recovered.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* After a re-key the enrollment is back to `none` at the bumped
                epoch; EnrollmentFlow generates + backs up the new root there. */}
            <EnrollmentFlow
              userId={userId}
              needsRestart={false}
              onComplete={() => setPhase("checklist")}
            />
          </CardContent>
        </Card>
      ) : (
        <ChecklistCard apps={apps} />
      )}
    </>
  );
}

function ConfirmCard({ onDone }: { onDone: () => void }) {
  const [phrase, setPhrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [needsReauth, setNeedsReauth] = useState(false);
  const [pending, startTransition] = useTransition();

  function submit() {
    setError(null);
    setNeedsReauth(false);
    startTransition(async () => {
      const result = await rekeyAnonSeed({ confirmPhrase: phrase });
      if (result.ok) {
        setPhrase("");
        onDone();
        return;
      }
      setError(result.error);
      if ("stepUp" in result && result.stepUp) setNeedsReauth(true);
    });
  }

  return (
    <Card className="border-red-200 dark:border-red-900/40">
      <CardHeader>
        <CardTitle>Confirm re-key</CardTitle>
        <CardDescription>
          Destructive and permanent. Your current anonymous identity becomes unreachable in every
          connected app. Requires a recent passkey sign-in.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? (
          <div className="flex flex-col gap-2 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
            <span>{error}</span>
            {needsReauth ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="self-start"
                onClick={() => signIn("passkey")}
              >
                Re-authenticate with passkey
              </Button>
            ) : null}
          </div>
        ) : null}
        <label htmlFor="rekey-phrase" className="text-sm">
          Type <span className="font-mono font-medium">{REKEY_PHRASE}</span> to confirm.
        </label>
        <div className="flex gap-2">
          <Input
            id="rekey-phrase"
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            autoComplete="off"
            placeholder={REKEY_PHRASE}
          />
          <Button
            type="button"
            variant="destructive"
            disabled={pending || phrase.trim().length === 0}
            onClick={submit}
          >
            {pending ? "Re-keying…" : "Re-key"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function ChecklistCard({ apps }: { apps: AppItem[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Finish re-keying in each app</CardTitle>
        <CardDescription>
          Your new identity reaches each app the next time you sign in there — no action here can do
          it for you, because only your browser holds the new key.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {apps.length === 0 ? (
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            You haven&apos;t connected any apps yet. There&apos;s nothing else to do — your new
            Private Identity is ready.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {apps.map((app) => (
              <li
                key={app.appName}
                className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800"
              >
                <div className="text-sm font-medium">{app.appName}</div>
                <div className="text-sm text-neutral-600 dark:text-neutral-400">
                  Sign in to {app.appName} again to finish re-keying there.
                </div>
              </li>
            ))}
          </ul>
        )}
        <Button asChild variant="outline" className="self-start">
          <Link href="/settings/private-identity">Done</Link>
        </Button>
      </CardContent>
    </Card>
  );
}
