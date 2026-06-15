"use client";

import { useTransition } from "react";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { revokeShareLink } from "@/server/share-actions";

export function ShareLinkRevokeButton({ shareLinkId }: { shareLinkId: string }) {
  const [pending, startTransition] = useTransition();

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      disabled={pending}
      title="Revoke this share link"
      aria-label="Revoke this share link"
      onClick={() => {
        if (
          typeof window !== "undefined" &&
          !window.confirm(
            "Revoke this share link? Anyone with the URL will see a 'link unavailable' page.",
          )
        ) {
          return;
        }
        startTransition(async () => {
          await revokeShareLink({ shareLinkId });
        });
      }}
    >
      <Trash2 className="h-4 w-4" />
    </Button>
  );
}
