"use client";

import { useState } from "react";

import { avatarDataUri } from "@/lib/avatar";
import { cn } from "@/lib/utils";

interface AvatarProps {
  // Stable per-user seed for the deterministic fallback (the user id). Never
  // PII — the identicon reveals nothing about the person.
  seed: string;
  // The curated avatar URL (a Gravatar or free-text https URL), or null when
  // the user has chosen the deterministic identicon.
  avatarUrl: string | null;
  // Rendered pixel size (square). Also seeds the SVG viewBox so the fallback
  // stays crisp.
  size?: number;
  className?: string;
}

// One avatar renderer for every surface (profile, public /u, editor preview).
// When a curated URL is set we render it; if it 404s or fails to load (a
// Gravatar with `d=404` for an email that has no Gravatar, or a dead custom
// URL) we fall back to the deterministic identicon — so a user ALWAYS has a
// nice avatar and never a broken image. When no URL is set we render the
// identicon directly.
export function Avatar({ seed, avatarUrl, size = 48, className }: AvatarProps) {
  const [broken, setBroken] = useState(false);
  const useCurated = Boolean(avatarUrl) && !broken;
  const src = useCurated ? (avatarUrl as string) : avatarDataUri(seed, size);

  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={src}
      alt=""
      width={size}
      height={size}
      onError={() => setBroken(true)}
      className={cn(
        "rounded-full border border-neutral-200 object-cover dark:border-neutral-800",
        className,
      )}
    />
  );
}
