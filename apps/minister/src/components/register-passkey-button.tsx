"use client";

import { signIn } from "next-auth/webauthn";
import { Button } from "@/components/ui/button";

// Shown to already-authenticated users so they can attach a passkey to
// their account (e.g. after signing in via magic link).
export function RegisterPasskeyButton({ className }: { className?: string }) {
  return (
    <Button
      variant="outline"
      className={className}
      onClick={() => signIn("passkey", { action: "register" })}
    >
      Add a passkey
    </Button>
  );
}
