"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { setCohortDefPublished } from "@/server/stats-actions";

// Publish / unpublish toggle for one cohort def (admin /admin/stats). A published
// cohort is WORLD-VISIBLE on /transparency — the button label spells out which
// direction the click moves it so an operator can't flip visibility by accident.
export function AdminCohortPublishToggle({ id, published }: { id: string; published: boolean }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function toggle() {
    setError(null);
    startTransition(async () => {
      const result = await setCohortDefPublished({ id, published: !published });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      router.refresh();
    });
  }

  return (
    <div className="flex items-center gap-2">
      <span
        className={
          published
            ? "rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400"
            : "rounded-full bg-neutral-100 px-2 py-0.5 text-xs font-medium text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400"
        }
      >
        {published ? "Public" : "Unpublished"}
      </span>
      <Button type="button" variant="outline" size="sm" onClick={toggle} disabled={pending}>
        {pending ? "Saving…" : published ? "Unpublish" : "Publish"}
      </Button>
      {error ? <span className="text-xs text-red-600 dark:text-red-400">{error}</span> : null}
    </div>
  );
}
