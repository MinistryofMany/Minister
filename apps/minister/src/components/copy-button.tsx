"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";

// Copy-to-clipboard with brief "Copied!" feedback. Replaces the silent
// navigator.clipboard buttons scattered across the share / admin forms.
export function CopyButton({
  value,
  label = "Copy",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      aria-live="polite"
      onClick={() => {
        if (typeof navigator === "undefined" || !navigator.clipboard) return;
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? "Copied!" : label}
    </Button>
  );
}
