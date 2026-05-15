"use client";

import { useTransition } from "react";
import { LogOut } from "lucide-react";

import { Button } from "@/components/ui/button";
import { revokeAllSessions } from "@/server/account-actions";

export function RevokeAllButton() {
  const [pending, startTransition] = useTransition();

  return (
    <Button
      type="button"
      variant="destructive"
      disabled={pending}
      onClick={() => {
        if (
          typeof window !== "undefined" &&
          !window.confirm(
            "Sign out of every device that's currently logged in to this account? You'll need to sign in again on each one.",
          )
        ) {
          return;
        }
        startTransition(async () => {
          await revokeAllSessions();
        });
      }}
    >
      <LogOut className="h-4 w-4" />
      {pending ? "Revoking…" : "Sign out of all devices"}
    </Button>
  );
}
