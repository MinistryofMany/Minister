"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { setUserAdmin } from "@/server/admin-actions";

export function AdminUserRoleButton({ userId, isAdmin }: { userId: string; isAdmin: boolean }) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="flex items-center gap-2">
      {error ? <span className="text-xs text-red-600">{error}</span> : null}
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={pending}
        onClick={() => {
          if (
            typeof window !== "undefined" &&
            !window.confirm(
              isAdmin
                ? "Demote this admin to a regular user?"
                : "Promote this user to admin? They get full access to /admin: users, invite codes, OIDC clients, audit log.",
            )
          ) {
            return;
          }
          setError(null);
          startTransition(async () => {
            const result = await setUserAdmin({ userId, admin: !isAdmin });
            if (!result.ok) setError(result.error);
          });
        }}
      >
        {pending ? "Working…" : isAdmin ? "Demote" : "Make admin"}
      </Button>
    </div>
  );
}
