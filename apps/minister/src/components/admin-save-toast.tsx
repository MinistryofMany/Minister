"use client";

import { useEffect } from "react";

// Position-independent save/error feedback for long admin forms (sybil-score,
// recovery-config). Both pages batch several sections/rows into one page; a
// banner pinned to the top of the form is invisible to an operator who just
// saved a control far down the page. A fixed corner toast is visible from any
// scroll position regardless of which section or row produced it, and
// auto-dismisses so it doesn't linger stale after the operator moves on.
export function AdminSaveToast({
  error,
  notice,
  onDismiss,
}: {
  error: string | null;
  notice: string | null;
  onDismiss: () => void;
}) {
  useEffect(() => {
    if (!error && !notice) return;
    const timer = setTimeout(onDismiss, 6000);
    return () => clearTimeout(timer);
  }, [error, notice, onDismiss]);

  if (!error && !notice) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2" role="status">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 shadow-lg dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700 shadow-lg dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-400">
          {notice}
        </div>
      ) : null}
    </div>
  );
}
