"use client";

import { useState, useTransition } from "react";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { revokeInviteCode } from "@/server/admin-actions";

export function AdminInviteRevokeButton({ inviteCodeId }: { inviteCodeId: string }) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="flex items-center gap-2">
      {error ? <span className="text-xs text-red-600">{error}</span> : null}
      <Button
        type="button"
        variant="ghost"
        size="icon"
        disabled={pending}
        title="Revoke this invite code"
        aria-label="Revoke this invite code"
        onClick={() => {
          if (
            typeof window !== "undefined" &&
            !window.confirm(
              "Revoke this invite code? It stops working immediately; badges already issued are unaffected.",
            )
          ) {
            return;
          }
          setError(null);
          startTransition(async () => {
            const result = await revokeInviteCode({ inviteCodeId });
            if (!result.ok) setError(result.error);
          });
        }}
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}
