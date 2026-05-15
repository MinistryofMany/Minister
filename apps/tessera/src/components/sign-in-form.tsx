"use client";

import { useState } from "react";
import { signIn as signInReact } from "next-auth/react";
import { signIn as signInWebAuthn } from "next-auth/webauthn";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function SignInForm() {
  const [email, setEmail] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);

  async function handleEmail(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEmailError(null);
    const result = await signInReact("email", {
      email,
      redirect: false,
    });
    if (result?.error) {
      setEmailError(result.error);
      return;
    }
    setEmailSent(true);
  }

  async function handlePasskey() {
    await signInWebAuthn("passkey");
  }

  return (
    <div className="flex flex-col gap-6">
      <Button onClick={handlePasskey} className="w-full">
        Sign in with a passkey
      </Button>

      <div className="flex items-center gap-3 text-xs uppercase tracking-wide text-neutral-400">
        <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
        or
        <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
      </div>

      {emailSent ? (
        <p className="rounded-md border border-neutral-200 bg-neutral-50 p-4 text-sm dark:border-neutral-800 dark:bg-neutral-900">
          Check the server logs for your magic link (dev mode).
        </p>
      ) : (
        <form onSubmit={handleEmail} className="flex flex-col gap-3">
          <Input
            type="email"
            name="email"
            placeholder="you@example.com"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Button type="submit" variant="outline" className="w-full">
            Email me a magic link
          </Button>
          {emailError ? (
            <p className="text-xs text-red-600">{emailError}</p>
          ) : null}
        </form>
      )}
    </div>
  );
}
