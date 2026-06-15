"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import { Input } from "@/components/ui/input";
import type { DisplayBadge } from "@/lib/badges";
import { createShareLink } from "@/server/share-actions";
import { summarizeAttributes } from "@/lib/badges";

interface Props {
  badges: DisplayBadge[];
  origin: string;
}

const TTL_OPTIONS = [1, 7, 30, 90] as const;

export function ShareLinkCreateForm({ badges, origin }: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [ttlDays, setTtlDays] = useState<number>(7);
  const [requiresAccount, setRequiresAccount] = useState(false);
  const [sendToEmail, setSendToEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [createdUrl, setCreatedUrl] = useState<string | null>(null);

  function toggle(id: string) {
    setSelected((s) => ({ ...s, [id]: !s[id] }));
  }

  function submit() {
    setError(null);
    const badgeIds = Object.entries(selected)
      .filter(([, v]) => v)
      .map(([id]) => id);
    if (badgeIds.length === 0) {
      setError("Pick at least one badge to share.");
      return;
    }
    startTransition(async () => {
      const result = await createShareLink(
        { badgeIds, ttlDays, requiresAccount, sendToEmail: sendToEmail || undefined },
        origin,
      );
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setCreatedUrl(result.url);
      setSelected({});
      setSendToEmail("");
      router.refresh();
    });
  }

  if (createdUrl) {
    return (
      <div className="flex flex-col gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/30">
        <h3 className="text-sm font-semibold">Share link created</h3>
        <p className="text-sm text-neutral-700 dark:text-neutral-300">
          Anyone with this URL can view the badges you selected, until it expires or you revoke it.
        </p>
        <div className="flex items-center gap-2">
          <Input readOnly value={createdUrl} className="font-mono text-xs" />
          <CopyButton value={createdUrl} />
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setCreatedUrl(null)}
        >
          Create another
        </Button>
      </div>
    );
  }

  if (badges.length === 0) {
    return (
      <p className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
        You don&apos;t have any badges yet. Claim one first, then you can share it.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Badges to include</legend>
        {badges.map((b) => (
          <label
            key={b.id}
            className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 text-sm dark:border-neutral-800"
          >
            <input
              type="checkbox"
              className="mt-1 h-4 w-4"
              checked={Boolean(selected[b.id])}
              onChange={() => toggle(b.id)}
            />
            <span className="flex-1">
              <span className="block font-medium">{b.meta.label}</span>
              {summarizeAttributes(b.type, b.attributes) ? (
                <span className="text-neutral-600 dark:text-neutral-400">
                  {summarizeAttributes(b.type, b.attributes)}
                </span>
              ) : null}
            </span>
          </label>
        ))}
      </fieldset>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Expires after</legend>
        <div className="flex flex-wrap gap-2">
          {TTL_OPTIONS.map((days) => (
            <label
              key={days}
              className={
                "cursor-pointer rounded-md border px-3 py-1 text-sm " +
                (ttlDays === days
                  ? "border-neutral-900 bg-neutral-900 text-white dark:border-neutral-100 dark:bg-neutral-100 dark:text-neutral-900"
                  : "border-neutral-300 dark:border-neutral-700")
              }
            >
              <input
                type="radio"
                name="ttl"
                value={days}
                checked={ttlDays === days}
                onChange={() => setTtlDays(days)}
                className="sr-only"
              />
              {days} day{days === 1 ? "" : "s"}
            </label>
          ))}
        </div>
      </fieldset>

      <label className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 text-sm dark:border-neutral-800">
        <input
          type="checkbox"
          className="mt-1 h-4 w-4"
          checked={requiresAccount}
          onChange={(e) => setRequiresAccount(e.target.checked)}
        />
        <span className="flex-1">
          <span className="block font-medium">Require a Minister account</span>
          <span className="text-neutral-600 dark:text-neutral-400">
            Viewers without an account get a &ldquo;sign-in required&rdquo; page.
          </span>
        </span>
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Email it to someone (optional)</span>
        <Input
          type="email"
          placeholder="recipient@example.com"
          value={sendToEmail}
          onChange={(e) => setSendToEmail(e.target.value)}
        />
      </label>

      <Button type="button" onClick={submit} disabled={pending} className="self-start">
        {pending ? "Creating…" : "Create share link"}
      </Button>
    </div>
  );
}
