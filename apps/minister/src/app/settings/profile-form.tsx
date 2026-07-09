"use client";

import { useState } from "react";

import { Avatar } from "@/components/avatar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { updateProfile } from "@/server/profile-actions";
import type { ProfileEditorInput } from "@/server/profile-validation";

interface GravatarOption {
  email: string;
  url: string;
}

interface ProfileFormProps {
  userId: string;
  initialDisplayName: string | null;
  initialAvatarUrl: string | null;
  gravatarOptions: GravatarOption[];
}

type AvatarKind = "deterministic" | "gravatar" | "url";

const GRAVATAR_PREFIX = "https://www.gravatar.com/avatar/";

// Infer the initial editor state from the stored avatarUrl:
//   - null                    -> deterministic (the default identicon)
//   - a gravatar.com URL      -> gravatar (matched back to its email if we can)
//   - any other https URL     -> custom URL
function inferInitial(
  avatarUrl: string | null,
  options: GravatarOption[],
): { kind: AvatarKind; gravatarEmail: string; url: string } {
  if (!avatarUrl) {
    return { kind: "deterministic", gravatarEmail: options[0]?.email ?? "", url: "" };
  }
  if (avatarUrl.startsWith(GRAVATAR_PREFIX)) {
    const match = options.find((o) => o.url === avatarUrl);
    return {
      kind: "gravatar",
      gravatarEmail: match?.email ?? options[0]?.email ?? "",
      url: "",
    };
  }
  return { kind: "url", gravatarEmail: options[0]?.email ?? "", url: avatarUrl };
}

export function ProfileForm({
  userId,
  initialDisplayName,
  initialAvatarUrl,
  gravatarOptions,
}: ProfileFormProps) {
  const initial = inferInitial(initialAvatarUrl, gravatarOptions);

  const [displayName, setDisplayName] = useState(initialDisplayName ?? "");
  const [kind, setKind] = useState<AvatarKind>(initial.kind);
  const [gravatarEmail, setGravatarEmail] = useState(initial.gravatarEmail);
  const [url, setUrl] = useState(initial.url);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const hasGravatar = gravatarOptions.length > 0;

  // What the preview should show for the current selection. Deterministic ->
  // null (Avatar draws the identicon); gravatar -> the chosen email's URL;
  // url -> the typed value (blank falls back to the identicon in the preview).
  const previewUrl =
    kind === "gravatar"
      ? (gravatarOptions.find((o) => o.email === gravatarEmail)?.url ?? null)
      : kind === "url"
        ? url.trim() || null
        : null;

  function buildInput(): ProfileEditorInput {
    switch (kind) {
      case "gravatar":
        return { displayName, avatar: { kind: "gravatar", email: gravatarEmail } };
      case "url":
        return { displayName, avatar: { kind: "url", url } };
      case "deterministic":
      default:
        return { displayName, avatar: { kind: "deterministic" } };
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setSaved(false);
    try {
      const result = await updateProfile(buildInput());
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

  function selectKind(next: AvatarKind) {
    setKind(next);
    setSaved(false);
    setError(null);
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-5">
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        Your display name and avatar are what apps see when you choose to share your profile. Both
        are optional.
      </p>

      <div className="flex flex-col gap-1.5">
        <label htmlFor="displayName" className="text-sm font-medium">
          Display name
        </label>
        <Input
          id="displayName"
          value={displayName}
          onChange={(e) => {
            setDisplayName(e.target.value);
            setSaved(false);
          }}
          maxLength={80}
          placeholder="e.g. Ada Lovelace"
        />
        <p className="text-xs text-neutral-500 dark:text-neutral-400">
          Clearing it stops sharing a name.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        <span className="text-sm font-medium">Avatar</span>

        <div className="flex items-center gap-4">
          <Avatar seed={userId} avatarUrl={previewUrl} size={64} className="h-16 w-16" />
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            This is how your avatar looks now.
          </p>
        </div>

        <fieldset className="flex flex-col gap-3">
          <label className="flex items-start gap-2.5">
            <input
              type="radio"
              name="avatarKind"
              className="mt-1"
              checked={kind === "deterministic"}
              onChange={() => selectKind("deterministic")}
            />
            <span className="flex flex-col">
              <span className="text-sm font-medium">Generated avatar</span>
              <span className="text-xs text-neutral-500 dark:text-neutral-400">
                A unique pattern made just for you. This is the default, and it shares no personal
                info.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2.5">
            <input
              type="radio"
              name="avatarKind"
              className="mt-1"
              checked={kind === "gravatar"}
              disabled={!hasGravatar}
              onChange={() => selectKind("gravatar")}
            />
            <span className="flex flex-col">
              <span className="text-sm font-medium">
                Gravatar
                {!hasGravatar ? (
                  <span className="font-normal text-neutral-500"> — verify an email first</span>
                ) : null}
              </span>
              <span className="text-xs text-neutral-500 dark:text-neutral-400">
                Use the photo from your Gravatar account. Heads up: the avatar link includes a
                scrambled version of your email, so an app you share it with could use it to
                recognize you again.
              </span>
              {hasGravatar && kind === "gravatar" ? (
                <select
                  aria-label="Email for Gravatar"
                  value={gravatarEmail}
                  onChange={(e) => {
                    setGravatarEmail(e.target.value);
                    setSaved(false);
                  }}
                  className="mt-1.5 w-full rounded-md border border-neutral-300 bg-white px-2 py-1.5 text-sm dark:border-neutral-700 dark:bg-neutral-900"
                >
                  {gravatarOptions.map((o) => (
                    <option key={o.email} value={o.email}>
                      {o.email}
                    </option>
                  ))}
                </select>
              ) : null}
            </span>
          </label>

          <label className="flex items-start gap-2.5">
            <input
              type="radio"
              name="avatarKind"
              className="mt-1"
              checked={kind === "url"}
              onChange={() => selectKind("url")}
            />
            <span className="flex w-full flex-col">
              <span className="text-sm font-medium">Image link</span>
              <span className="text-xs text-neutral-500 dark:text-neutral-400">
                Point to an image you host yourself.
              </span>
              {kind === "url" ? (
                <Input
                  aria-label="Avatar image URL"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setSaved(false);
                  }}
                  maxLength={2048}
                  placeholder="https://example.com/avatar.png"
                  className="mt-1.5"
                />
              ) : null}
              {kind === "url" ? (
                <span className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                  Must be an https:// link.
                </span>
              ) : null}
            </span>
          </label>
        </fieldset>
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
