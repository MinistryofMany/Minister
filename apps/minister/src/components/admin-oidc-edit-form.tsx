"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { updateOidcClient } from "@/server/admin-actions";

interface Props {
  id: string;
  initialName: string;
  initialRedirectUris: string;
  initialScopes: string[];
  allScopes: string[];
}

export function AdminOidcEditForm({
  id,
  initialName,
  initialRedirectUris,
  initialScopes,
  allScopes,
}: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [name, setName] = useState(initialName);
  const [redirectUris, setRedirectUris] = useState(initialRedirectUris);
  const [scopes, setScopes] = useState<Record<string, boolean>>(
    Object.fromEntries(initialScopes.map((s) => [s, true])),
  );
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function toggleScope(scope: string) {
    if (scope === "openid") return;
    setScopes((s) => ({ ...s, [scope]: !s[scope] }));
  }

  function submit() {
    setError(null);
    setSaved(false);
    startTransition(async () => {
      const result = await updateOidcClient({
        id,
        name,
        redirectUris,
        scopes: Object.entries(scopes)
          .filter(([, v]) => v)
          .map(([k]) => k),
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setSaved(true);
      router.refresh();
    });
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}
      {saved ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-400">
          Saved.
        </div>
      ) : null}

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Name</span>
        <Input value={name} onChange={(e) => setName(e.target.value)} />
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Redirect URIs</span>
        <textarea
          className="min-h-20 rounded-md border border-neutral-300 bg-transparent px-3 py-2 font-mono text-xs shadow-sm placeholder:text-neutral-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400 dark:border-neutral-700"
          value={redirectUris}
          onChange={(e) => setRedirectUris(e.target.value)}
        />
        <span className="text-xs text-neutral-500">
          One per line. Exact match — https required except on localhost.
        </span>
      </label>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Allowed scopes</legend>
        <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
          {allScopes.map((scope) => (
            <label
              key={scope}
              className="flex items-center gap-2 rounded-md border border-neutral-200 px-2 py-1 font-mono text-xs dark:border-neutral-800"
            >
              <input
                type="checkbox"
                className="h-3.5 w-3.5"
                checked={Boolean(scopes[scope])}
                disabled={scope === "openid"}
                onChange={() => toggleScope(scope)}
              />
              {scope}
            </label>
          ))}
        </div>
      </fieldset>

      <Button
        type="button"
        onClick={submit}
        disabled={pending || name.trim().length === 0}
        className="self-start"
      >
        {pending ? "Saving…" : "Save changes"}
      </Button>
    </div>
  );
}
