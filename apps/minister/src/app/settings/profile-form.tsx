"use client";

import { useEffect, useRef, useState } from "react";

import { Avatar } from "@/components/avatar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ALLOWED_AVATAR_TYPES, MAX_AVATAR_BYTES } from "@/lib/avatar-image";
import { isUploadedAvatarUrl } from "@/lib/avatar-url";
import { updateProfile, uploadAvatarAction } from "@/server/profile-actions";
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

type AvatarKind = "deterministic" | "gravatar" | "url" | "uploaded";

const GRAVATAR_PREFIX = "https://www.gravatar.com/avatar/";

// The <input accept> string and the human hint both come from the one allowed
// list, so they can't drift from the server's magic-byte gate.
const ACCEPT = ALLOWED_AVATAR_TYPES.join(",");

// Infer the initial editor state from the stored avatarUrl:
//   - null                    -> deterministic (the default identicon)
//   - the internal serve route -> uploaded (a stored photo)
//   - a gravatar.com URL      -> gravatar (matched back to its email if we can)
//   - any other https URL     -> custom URL
function inferInitial(
  userId: string,
  avatarUrl: string | null,
  options: GravatarOption[],
): { kind: AvatarKind; gravatarEmail: string; url: string } {
  if (!avatarUrl) {
    return { kind: "deterministic", gravatarEmail: options[0]?.email ?? "", url: "" };
  }
  if (isUploadedAvatarUrl(avatarUrl, userId)) {
    return { kind: "uploaded", gravatarEmail: options[0]?.email ?? "", url: "" };
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
  const initial = inferInitial(userId, initialAvatarUrl, gravatarOptions);

  // The already-uploaded photo's serve URL (present only if the user currently
  // uses an upload), used for the preview when no new file has been chosen.
  const uploadedUrl = isUploadedAvatarUrl(initialAvatarUrl, userId) ? initialAvatarUrl : null;

  const [displayName, setDisplayName] = useState(initialDisplayName ?? "");
  const [kind, setKind] = useState<AvatarKind>(initial.kind);
  const [gravatarEmail, setGravatarEmail] = useState(initial.gravatarEmail);
  const [url, setUrl] = useState(initial.url);
  const [file, setFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const hasGravatar = gravatarOptions.length > 0;

  // Revoke the object URL when the chosen file changes or the form unmounts, so
  // a live preview blob: URL doesn't leak.
  useEffect(() => {
    return () => {
      if (filePreview) URL.revokeObjectURL(filePreview);
    };
  }, [filePreview]);

  // What the preview should show for the current selection. Deterministic ->
  // null (Avatar draws the identicon); gravatar -> the chosen email's URL;
  // url -> the typed value; uploaded -> the newly picked file, else the existing
  // upload (else the identicon, before a first photo is chosen).
  const previewUrl =
    kind === "gravatar"
      ? (gravatarOptions.find((o) => o.email === gravatarEmail)?.url ?? null)
      : kind === "url"
        ? url.trim() || null
        : kind === "uploaded"
          ? (filePreview ?? uploadedUrl)
          : null;

  function buildInput(): ProfileEditorInput {
    switch (kind) {
      case "gravatar":
        return { displayName, avatar: { kind: "gravatar", email: gravatarEmail } };
      case "url":
        return { displayName, avatar: { kind: "url", url } };
      case "uploaded":
        // Keep the existing photo; a new file goes through uploadAvatarAction.
        return { displayName, avatar: { kind: "uploaded" } };
      case "deterministic":
      default:
        return { displayName, avatar: { kind: "deterministic" } };
    }
  }

  function onFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    setSaved(false);
    setError(null);
    const picked = event.target.files?.[0] ?? null;
    if (filePreview) URL.revokeObjectURL(filePreview);
    if (!picked) {
      setFile(null);
      setFilePreview(null);
      return;
    }
    // Client-side hints only — the server re-validates by magic bytes and size.
    if (!(ALLOWED_AVATAR_TYPES as readonly string[]).includes(picked.type)) {
      setFile(null);
      setFilePreview(null);
      setError("Choose a PNG, JPEG, or WebP image.");
      return;
    }
    if (picked.size > MAX_AVATAR_BYTES) {
      setFile(null);
      setFilePreview(null);
      setError("That image is over 512 KB. Pick a smaller one.");
      return;
    }
    setFile(picked);
    setFilePreview(URL.createObjectURL(picked));
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSaved(false);

    // Uploading a photo but nothing to store yet.
    if (kind === "uploaded" && !file && !uploadedUrl) {
      setError("Choose an image to upload.");
      return;
    }

    setPending(true);
    try {
      const result =
        kind === "uploaded" && file
          ? await (async () => {
              const fd = new FormData();
              fd.set("displayName", displayName);
              fd.set("file", file);
              return uploadAvatarAction(fd);
            })()
          : await updateProfile(buildInput());
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

  function clearUpload() {
    if (filePreview) URL.revokeObjectURL(filePreview);
    setFile(null);
    setFilePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
    selectKind("deterministic");
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
              checked={kind === "uploaded"}
              onChange={() => selectKind("uploaded")}
            />
            <span className="flex w-full flex-col">
              <span className="text-sm font-medium">Upload a photo</span>
              <span className="text-xs text-neutral-500 dark:text-neutral-400">
                Use your own picture. PNG, JPEG, or WebP, up to 512 KB.
              </span>
              {kind === "uploaded" ? (
                <>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept={ACCEPT}
                    aria-label="Avatar image file"
                    onChange={onFileChange}
                    className="mt-1.5 w-full text-sm file:mr-3 file:rounded-md file:border file:border-neutral-300 file:bg-white file:px-3 file:py-1.5 file:text-sm dark:file:border-neutral-700 dark:file:bg-neutral-900"
                  />
                  <span className="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                    {file
                      ? "Ready to save your new photo."
                      : uploadedUrl
                        ? "Your photo is set. Pick a file to replace it."
                        : "Pick a file to upload."}
                  </span>
                </>
              ) : null}
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

        {kind === "uploaded" && uploadedUrl ? (
          <button
            type="button"
            onClick={clearUpload}
            className="self-start text-xs text-neutral-500 underline underline-offset-2 hover:no-underline dark:text-neutral-400"
          >
            Remove photo and use the generated avatar
          </button>
        ) : null}
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
