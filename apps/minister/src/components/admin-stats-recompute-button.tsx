"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { recomputeStatsNow } from "@/server/stats-actions";

// The escape-hatch trigger for the materialized stats tables (P2-U0's
// `recomputeAllStats`, run synchronously). Mirrors `AdminOidcEditForm`'s
// pending/error pattern.
export function AdminStatsRecomputeButton() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [lastDurationMs, setLastDurationMs] = useState<number | null>(null);

  function submit() {
    setError(null);
    startTransition(async () => {
      const result = await recomputeStatsNow({});
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setLastDurationMs(result.durationMs);
      router.refresh();
    });
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button type="button" size="sm" onClick={submit} disabled={pending}>
        {pending ? "Recomputing…" : "Recompute now"}
      </Button>
      {error ? (
        <span className="text-xs text-red-600 dark:text-red-400">{error}</span>
      ) : lastDurationMs !== null ? (
        <span className="text-xs text-neutral-500">done in {lastDurationMs}ms</span>
      ) : null}
    </div>
  );
}
