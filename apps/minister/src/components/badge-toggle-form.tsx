"use client";

import { useTransition } from "react";
import { Eye, EyeOff } from "lucide-react";

import { Button } from "@/components/ui/button";
import { toggleBadgePublic } from "@/server/badge-actions";

interface Props {
  badgeId: string;
  isPublic: boolean;
}

export function BadgeToggleForm({ badgeId, isPublic }: Props) {
  const [pending, startTransition] = useTransition();

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      disabled={pending}
      title={isPublic ? "Make private" : "Make public"}
      aria-label={isPublic ? "Make private" : "Make public"}
      onClick={() =>
        startTransition(async () => {
          await toggleBadgePublic({ badgeId, isPublic: !isPublic });
        })
      }
    >
      {isPublic ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
    </Button>
  );
}
