"use client";

import { useTransition } from "react";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { revokeInviteCode } from "@/server/admin-actions";

export function AdminInviteRevokeButton({ inviteCodeId }: { inviteCodeId: string }) {
  const [pending, startTransition] = useTransition();

  return (
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
        startTransition(async () => {
          await revokeInviteCode({ inviteCodeId });
        });
      }}
    >
      <Trash2 className="h-4 w-4" />
    </Button>
  );
}
