"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { setUserBanned } from "@/server/admin-actions";

export function AdminUserBanButton({ userId, banned }: { userId: string; banned: boolean }) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="flex items-center gap-2">
      {error ? <span className="text-xs text-red-600">{error}</span> : null}
      <Button
        type="button"
        variant={banned ? "outline" : "destructive"}
        size="sm"
        disabled={pending}
        onClick={() => {
          if (
            !banned &&
            typeof window !== "undefined" &&
            !window.confirm(
              "Ban this user? Their sessions are revoked immediately and they can't sign back in until unbanned.",
            )
          ) {
            return;
          }
          setError(null);
          startTransition(async () => {
            const result = await setUserBanned({ userId, banned: !banned });
            if (!result.ok) setError(result.error);
          });
        }}
      >
        {pending ? "Working…" : banned ? "Unban" : "Ban"}
      </Button>
    </div>
  );
}
