"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { updateProfile } from "@/server/profile-actions";

interface ProfileFormProps {
  initialDisplayName: string | null;
  initialAvatarUrl: string | null;
}

export function ProfileForm({ initialDisplayName, initialAvatarUrl }: ProfileFormProps) {
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
      const result = await updateProfile({ displayName, avatarUrl });
      if ("error" in result) {
        setError(result.error);
      } else {
        setSaved(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save profile.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        Your display name and avatar are what apps see when you choose to share your profile. Both
        are optional — clearing a field stops sharing it.
      </p>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="displayName" className="text-sm font-medium">
          Display name
        </label>
        <Input
          id="displayName"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          maxLength={80}
          placeholder="e.g. Ada Lovelace"
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="avatarUrl" className="text-sm font-medium">
          Avatar URL
        </label>
        <div className="flex items-center gap-3">
          {avatarUrl && !avatarBroken ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={avatarUrl}
              alt=""
              onError={() => setAvatarBroken(true)}
              onLoad={() => setAvatarBroken(false)}
              className="h-12 w-12 rounded-full border border-neutral-200 object-cover dark:border-neutral-800"
            />
          ) : (
            <div
              aria-hidden
              className="h-12 w-12 rounded-full bg-neutral-200 dark:bg-neutral-800"
            />
          )}
          <Input
            id="avatarUrl"
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
        <p className="text-xs text-neutral-500 dark:text-neutral-400">Must be an https:// URL.</p>
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
