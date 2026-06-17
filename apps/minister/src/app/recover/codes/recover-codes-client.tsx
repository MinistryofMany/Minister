"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { redeemRecoveryCodeAndSignIn } from "@/server/recovery-code-actions";

// Unauthenticated recovery-code redemption form. On success the server action
// has already established a quarantined `recovered` session (via signIn with
// redirect:false), so we just route the browser to the passkey-enrollment
// landing. The new session cookie is set by the server action's response.
//
// Where to land after recovery. /settings/credentials is where the user enrolls
// a fresh passkey to climb back to AAL2; the recovered session can do that and
// little else until then.
const POST_RECOVERY_PATH = "/settings/credentials";

export function RecoverCodesClient() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const result = await redeemRecoveryCodeAndSignIn(email, code);
      if (result.ok) {
        // Recovered session is live. Full reload so server components re-read
        // the new session cookie, then land on passkey enrollment.
        router.replace(POST_RECOVERY_PATH);
        router.refresh();
        return;
      }
      if (result.reason === "rate-limited") {
        setError(
          `Too many attempts. Wait about ${result.retryAfterSeconds}s and try again.`,
        );
      } else {
        // Opaque on purpose — never reveals whether the email or the code was
        // the wrong part.
        setError("That email and recovery code don't match. Check both and try again.");
      }
    } catch {
      setError("Something went wrong. Try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Email</span>
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

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Recovery code</span>
        <Input
          type="text"
          name="code"
          inputMode="text"
          autoComplete="one-time-code"
          autoCapitalize="characters"
          spellCheck={false}
          placeholder="XXXX-XXXX-XXXX"
          required
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="font-mono tracking-widest"
        />
      </label>

      <Button type="submit" className="w-full" disabled={pending}>
        {pending ? "Checking…" : "Recover my account"}
      </Button>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
    </form>
  );
}
