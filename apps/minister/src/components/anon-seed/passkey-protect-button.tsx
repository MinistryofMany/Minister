"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { enrollPasskeyBlob, prfCapabilityHint } from "@/lib/anon-seed/vault";

// L1 storage offer (spec §7.1): wrap the vault-held seed under a PRF-passkey
// KEK and store the ciphertext with Ministry. All crypto happens in the vault
// module; this component only drives the UI. Hidden when the client is known
// NOT to support the PRF extension; otherwise feature-detected at click.

export function PasskeyProtectButton({
  userId,
  onStored,
}: {
  userId: string;
  onStored?: () => void;
}) {
  const [hint, setHint] = useState<boolean | null>(null);
  const [state, setState] = useState<"idle" | "working" | "stored">("idle");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void prfCapabilityHint().then((h) => {
      if (!cancelled) setHint(h);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (hint === false) return null;

  async function protect() {
    setMessage(null);
    setState("working");
    const result = await enrollPasskeyBlob(userId);
    if (result.ok) {
      setState("stored");
      onStored?.();
      return;
    }
    setState("idle");
    setMessage(result.message);
  }

  return (
    <div className="rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
      <div className="text-sm font-medium">Protect with your passkey</div>
      <p className="mt-0.5 text-sm text-neutral-600 dark:text-neutral-400">
        One tap unlocks your Private Identity here later. Ministry stores only an encrypted copy it
        cannot read; your passkey holds the only way in.
      </p>
      <div className="mt-2">
        {state === "stored" ? (
          <p className="text-sm font-medium text-green-700 dark:text-green-400">
            Protected by your passkey.
          </p>
        ) : (
          <Button type="button" variant="outline" onClick={protect} disabled={state === "working"}>
            {state === "working" ? "Waiting for your passkey…" : "Use my passkey"}
          </Button>
        )}
      </div>
      {message ? (
        <p className="mt-2 text-sm text-amber-700 dark:text-amber-400">{message}</p>
      ) : null}
    </div>
  );
}
