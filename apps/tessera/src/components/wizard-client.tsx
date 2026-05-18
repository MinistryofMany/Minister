"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import type {
  ExtensionActionStepPayload,
  FormStepPayload,
  InfoStepPayload,
  MagicLinkStepPayload,
  RedirectStepPayload,
  WizardState,
} from "@tessera/plugin-sdk";
// Per-kind payload types are still imported so the per-step renderer
// signatures are explicit; the dispatcher above relies on the union
// narrowing rather than `as` casts.

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { submitStepAction } from "@/server/wizard-actions";

interface Props {
  sessionId: string;
  initialState: WizardState;
}

export function WizardClient({ sessionId, initialState }: Props) {
  const router = useRouter();
  const [state, setState] = useState<WizardState>(initialState);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function handleSubmit(input: unknown) {
    setError(null);
    startTransition(async () => {
      const result = await submitStepAction(sessionId, input);
      if (result.kind === "error") {
        setError(result.message);
      } else if (result.kind === "complete") {
        // Badge issued — bounce back to profile with the new badge in
        // place. router.refresh ensures the badge grid re-fetches.
        router.push("/profile");
        router.refresh();
      } else {
        setState(result.state);
      }
    });
  }

  const step = state.currentStep;

  return (
    <Card>
      {error ? (
        <div className="mx-6 mt-6 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}

      {step.kind === "form" ? (
        <FormStep payload={step.payload} pending={pending} onSubmit={handleSubmit} />
      ) : step.kind === "magic-link" ? (
        <MagicLinkStep payload={step.payload} />
      ) : step.kind === "redirect" ? (
        <RedirectStep payload={step.payload} />
      ) : step.kind === "extension-action" ? (
        <ExtensionActionStep payload={step.payload} />
      ) : (
        // Exhaustive: 'info' is the last kind in the WizardStep union.
        // TypeScript verifies this dispatch covers every variant; adding
        // a new step kind will fail the typecheck here.
        <InfoStep
          payload={step.payload}
          pending={pending}
          onSubmit={() => handleSubmit({})}
        />
      )}
    </Card>
  );
}

function FormStep({
  payload,
  pending,
  onSubmit,
}: {
  payload: FormStepPayload;
  pending: boolean;
  onSubmit(input: Record<string, string>): void;
}) {
  return (
    <>
      <CardHeader>
        <CardTitle>{payload.title}</CardTitle>
        {payload.description ? (
          <CardDescription>{payload.description}</CardDescription>
        ) : null}
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const fd = new FormData(e.currentTarget);
            const input: Record<string, string> = {};
            payload.fields.forEach((f) => {
              const v = fd.get(f.name);
              if (typeof v === "string") input[f.name] = v;
            });
            onSubmit(input);
          }}
        >
          {payload.fields.map((field) => (
            <label key={field.name} className="flex flex-col gap-1 text-sm">
              <span className="font-medium">{field.label}</span>
              <Input
                name={field.name}
                type={field.type === "number" ? "number" : field.type}
                placeholder={field.placeholder}
                required={field.required}
              />
              {field.helpText ? (
                <span className="text-xs text-neutral-500">
                  {field.helpText}
                </span>
              ) : null}
            </label>
          ))}
          <Button type="submit" disabled={pending}>
            {pending ? "Working…" : (payload.submitLabel ?? "Continue")}
          </Button>
        </form>
      </CardContent>
    </>
  );
}

function RedirectStep({ payload }: { payload: RedirectStepPayload }) {
  // Manual click rather than auto-navigation: avoids tight loops if
  // the upstream provider bounces back here (e.g. user denies on
  // their side and gets re-redirected). Also lets the user read the
  // description and decide.
  return (
    <>
      <CardHeader>
        <CardTitle>Continue elsewhere</CardTitle>
        <CardDescription>
          {payload.description ??
            "We'll send you to an external provider to complete this step. Come back here to finish."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Button asChild>
          <a href={payload.url}>Continue</a>
        </Button>
        <p className="break-all text-xs text-neutral-500">{payload.url}</p>
      </CardContent>
    </>
  );
}

function ExtensionActionStep({
  payload,
}: {
  payload: ExtensionActionStepPayload;
}) {
  // Polled by the extension via the browser bridge. The page itself
  // does nothing reactive — when the extension POSTs the presentation
  // to /api/tlsn/submit and completes the wizard, the user navigates
  // back to /profile (extension popup signals "done"). For now we just
  // show what's pending; Stage 6+ adds an SSE / postMessage handshake
  // to auto-redirect on completion.
  return (
    <>
      <CardHeader>
        <CardTitle>Use the Tessera browser extension</CardTitle>
        <CardDescription>
          {payload.description ??
            "This step happens inside the Tessera extension so the sensitive proof bytes never leave your device."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm text-neutral-600 dark:text-neutral-400">
        <p>
          Open the extension popup. It will recognize this in-flight
          wizard and walk you through the TLSNotary proof. When it&apos;s done,
          come back here and refresh.
        </p>
        <p className="text-xs text-neutral-500">
          Action: <code>{payload.action}</code>
        </p>
      </CardContent>
    </>
  );
}

function MagicLinkStep({ payload }: { payload: MagicLinkStepPayload }) {
  return (
    <>
      <CardHeader>
        <CardTitle>Check your inbox</CardTitle>
        <CardDescription>
          We sent a verification link to{" "}
          <span className="font-medium">{payload.sentTo}</span>. Click it to
          finish issuing this badge.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm text-neutral-600 dark:text-neutral-400">
        {payload.description ? <p>{payload.description}</p> : null}
        <p className="text-xs text-neutral-500">
          In dev, the link is printed to the server console — look for
          <code className="ml-1">[tessera:mailer]</code>.
        </p>
      </CardContent>
    </>
  );
}

function InfoStep({
  payload,
  pending,
  onSubmit,
}: {
  payload: InfoStepPayload;
  pending: boolean;
  onSubmit(): void;
}) {
  return (
    <>
      <CardHeader>
        <CardTitle>{payload.title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <p className="text-sm text-neutral-700 dark:text-neutral-300">
          {payload.body}
        </p>
        <Button onClick={onSubmit} disabled={pending}>
          {payload.continueLabel ?? "Continue"}
        </Button>
      </CardContent>
    </>
  );
}
