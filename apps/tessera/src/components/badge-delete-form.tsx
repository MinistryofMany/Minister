"use client";

import { useTransition } from "react";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { deleteBadge } from "@/server/badge-actions";

export function BadgeDeleteForm({ badgeId }: { badgeId: string }) {
  const [pending, startTransition] = useTransition();

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      disabled={pending}
      title="Delete badge"
      aria-label="Delete badge"
      onClick={() => {
        // confirm() blocks the event loop but is fine for a prototype
        // confirmation; we'll wire a proper dialog component later.
        if (
          typeof window !== "undefined" &&
          !window.confirm("Delete this badge? This cannot be undone.")
        ) {
          return;
        }
        startTransition(async () => {
          await deleteBadge({ badgeId });
        });
      }}
    >
      <Trash2 className="h-4 w-4" />
    </Button>
  );
}
