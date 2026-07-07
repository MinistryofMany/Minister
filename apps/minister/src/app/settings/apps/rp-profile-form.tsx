"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { updateRpProfile } from "@/server/rp-profile-actions";

interface RpProfileFormProps {
  clientId: string;
  clientName: string;
  // The authoritative current value for this app — the persona field when a
  // persona row exists (null => the field is currently NOT shared), else the
  // global default as the seed for a first persona. Pre-fills the inputs.
  initialDisplayName: string | null;
  initialAvatarUrl: string | null;
}

export function RpProfileForm({
  clientId,
  clientName,
  initialDisplayName,
  initialAvatarUrl,
}: RpProfileFormProps) {
  const [displayName, setDisplayName] = useState(initialDisplayName ?? "");
  const [avatarUrl, setAvatarUrl] = useState(initialAvatarUrl ?? "");
  const [avatarBroken, setAvatarBroken] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setSaved(false);
    try {
      const result = await updateRpProfile({ clientId, displayName, avatarUrl });
      if ("error" in result) {
        setError(result.error);
      } else {
        setSaved(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <label htmlFor={`rp-name-${clientId}`} className="text-sm font-medium">
          Display name for {clientName}
        </label>
        <Input
          id={`rp-name-${clientId}`}
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          maxLength={80}
          placeholder="e.g. Ada Lovelace"
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor={`rp-avatar-${clientId}`} className="text-sm font-medium">
          Avatar URL for {clientName}
        </label>
        <div className="flex items-center gap-3">
          {avatarUrl && !avatarBroken ? (
            // eslint-disable-next-line @next/next/no-img-element -- user-supplied avatar URL; next/image would need per-host remotePatterns config
            <img
              src={avatarUrl}
              alt=""
              onError={() => setAvatarBroken(true)}
              onLoad={() => setAvatarBroken(false)}
              className="h-12 w-12 shrink-0 rounded-full border border-neutral-200 object-cover dark:border-neutral-800"
            />
          ) : (
            <div
              aria-hidden
              className="h-12 w-12 shrink-0 rounded-full bg-neutral-200 dark:bg-neutral-800"
            />
          )}
          <Input
            id={`rp-avatar-${clientId}`}
            value={avatarUrl}
            onChange={(e) => {
              setAvatarUrl(e.target.value);
              setAvatarBroken(false);
            }}
            maxLength={2048}
            placeholder="https://example.com/avatar.png"
            className="flex-1"
          />
        </div>
        <p className="text-xs text-neutral-500 dark:text-neutral-400">
          Must be an https:// URL. Clearing a field stops sharing it with this app.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : "Save"}
        </Button>
        {saved ? (
          <span className="text-sm text-neutral-600 dark:text-neutral-400">Saved.</span>
        ) : null}
      </div>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}
    </form>
  );
}
