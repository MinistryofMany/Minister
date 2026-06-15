"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { signIn as signInReact } from "next-auth/react";
import { signIn as signInWebAuthn } from "next-auth/webauthn";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// Whitelist allowed callback prefixes. NextAuth requires callbackUrls
// to be on the same origin anyway, but defense-in-depth: only return
// to paths we know we own. /oidc/authorize is the obvious one
// (mid-OIDC flow); /profile etc. are also acceptable post-sign-in
// landings.
function safeCallbackUrl(from: string | null): string | undefined {
  if (!from) return undefined;
  if (!from.startsWith("/")) return undefined;
  if (from.startsWith("//")) return undefined; // protocol-relative
  return from;
}

export function SignInForm() {
  const searchParams = useSearchParams();
  const callbackUrl = safeCallbackUrl(searchParams.get("from"));

  const [email, setEmail] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);

  async function handleEmail(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEmailError(null);
    const result = await signInReact("email", {
      email,
      redirect: false,
      callbackUrl,
    });
    if (result?.error) {
      setEmailError(result.error);
      return;
    }
    setEmailSent(true);
  }

  async function handlePasskey() {
    await signInWebAuthn("passkey", callbackUrl ? { callbackUrl } : undefined);
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
          {emailError ? <p className="text-xs text-red-600">{emailError}</p> : null}
        </form>
      )}
    </div>
  );
}
