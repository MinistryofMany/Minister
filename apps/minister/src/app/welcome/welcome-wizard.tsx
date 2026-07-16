"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { ProfileForm } from "@/app/settings/profile-form";
import { EnrollmentFlow } from "@/components/anon-seed/enrollment-flow";
import { RegisterPasskeyButton } from "@/components/register-passkey-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { AnonSeedStatus } from "@/server/anon-seed-actions";
import { completeSetup } from "@/server/setup-actions";

// The forced onboarding guide (identity plan §3 "Signup"). Steps 1-2 (email +
// magic link) ARE the sign-in, so this starts after it: passkey → Private
// Identity backup → profile. A cancelled passkey must not trap the user, so the
// passkey step is always skippable; the identity mints whenever a passkey
// exists and no blob does, which the badge-wizard incentive handles later.

interface GravatarOption {
  email: string;
  url: string;
}

type Step = "passkey" | "identity" | "profile";

export function WelcomeWizard({
  userId,
  initialPasskeyCount,
  anonEnabled,
  initialAnonStatus,
  initialDisplayName,
  initialAvatarUrl,
  gravatarOptions,
}: {
  userId: string;
  initialPasskeyCount: number;
  anonEnabled: boolean;
  initialAnonStatus: AnonSeedStatus;
  initialDisplayName: string | null;
  initialAvatarUrl: string | null;
  gravatarOptions: GravatarOption[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [anonStatus, setAnonStatus] = useState<AnonSeedStatus>(initialAnonStatus);

  const identityNeeded = anonEnabled && anonStatus !== "active";

  // Land on the first unfinished step so a returning half-setup user is not
  // walked back through what they already did.
  const [step, setStep] = useState<Step>(() => {
    if (initialPasskeyCount === 0) return "passkey";
    if (anonEnabled && initialAnonStatus !== "active") return "identity";
    return "profile";
  });

  function goAfterPasskey() {
    setStep(identityNeeded ? "identity" : "profile");
  }

  function finish() {
    setError(null);
    startTransition(async () => {
      await completeSetup();
      // Server component re-reads setupCompletedAt; the /welcome guard now lets
      // the profile through instead of bouncing back here.
      router.replace("/profile");
      router.refresh();
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <StepDots step={step} showIdentity={anonEnabled} />

      {step === "passkey" ? (
        <Card>
          <CardHeader>
            <CardTitle>Add a passkey</CardTitle>
            <CardDescription>
              A passkey signs you in with a tap — nothing to phish, no email link to wait on. The
              first passkey is active right away.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {initialPasskeyCount > 0 ? (
              <p className="text-sm font-medium text-green-700 dark:text-green-400">
                Passkey added.
              </p>
            ) : (
              <RegisterPasskeyButton />
            )}
            <div className="flex gap-2">
              <Button type="button" onClick={goAfterPasskey}>
                {initialPasskeyCount > 0 ? "Continue" : "Skip for now"}
              </Button>
            </div>
            {initialPasskeyCount === 0 ? (
              <p className="text-xs text-neutral-500 dark:text-neutral-400">
                You can add one later under Settings → Credentials. Skipping won&apos;t block setup.
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {step === "identity" ? (
        <Card>
          <CardHeader>
            <CardTitle>Set up your Private Identity</CardTitle>
            <CardDescription>
              Generated in your browser, it gives you a separate anonymous identity in every
              connected app. Ministry never sees it and can never recover it — you back it up.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <EnrollmentFlow
              userId={userId}
              needsRestart={anonStatus === "pending_backup"}
              onComplete={() => {
                setAnonStatus("active");
                setStep("profile");
              }}
            />
          </CardContent>
        </Card>
      ) : null}

      {step === "profile" ? (
        <Card>
          <CardHeader>
            <CardTitle>Fill in your profile</CardTitle>
            <CardDescription>
              Optional. Your name and photo are shared with an app only when you choose to disclose
              them.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <ProfileForm
              userId={userId}
              initialDisplayName={initialDisplayName}
              initialAvatarUrl={initialAvatarUrl}
              gravatarOptions={gravatarOptions}
            />
            {error ? <p className="text-sm text-red-600">{error}</p> : null}
            <div>
              <Button type="button" onClick={finish} disabled={pending}>
                {pending ? "Finishing…" : "Finish setup"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function StepDots({ step, showIdentity }: { step: Step; showIdentity: boolean }) {
  const steps: Step[] = showIdentity ? ["passkey", "identity", "profile"] : ["passkey", "profile"];
  const labels: Record<Step, string> = {
    passkey: "Passkey",
    identity: "Private Identity",
    profile: "Profile",
  };
  const currentIndex = steps.indexOf(step);
  return (
    <ol className="flex flex-wrap gap-3 text-xs">
      {steps.map((s, i) => (
        <li
          key={s}
          className={
            i <= currentIndex
              ? "font-medium text-neutral-900 dark:text-neutral-100"
              : "text-neutral-400 dark:text-neutral-600"
          }
        >
          {i + 1}. {labels[s]}
        </li>
      ))}
    </ol>
  );
}
