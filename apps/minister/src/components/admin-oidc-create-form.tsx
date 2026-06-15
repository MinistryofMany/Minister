"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import { Input } from "@/components/ui/input";
import { createOidcClient } from "@/server/admin-actions";

interface Props {
  allScopes: string[];
}

export function AdminOidcCreateForm({ allScopes }: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [name, setName] = useState("");
  const [redirectUris, setRedirectUris] = useState("");
  const [scopes, setScopes] = useState<Record<string, boolean>>({
    openid: true,
    profile: true,
  });
  const [publicClient, setPublicClient] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{
    clientId: string;
    clientSecret: string | null;
  } | null>(null);

  function toggleScope(scope: string) {
    // openid stays on — the flow is meaningless without it.
    if (scope === "openid") return;
    setScopes((s) => ({ ...s, [scope]: !s[scope] }));
  }

  function submit() {
    setError(null);
    startTransition(async () => {
      const result = await createOidcClient({
        name,
        redirectUris,
        scopes: Object.entries(scopes)
          .filter(([, v]) => v)
          .map(([k]) => k),
        publicClient,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setCreated({
        clientId: result.clientId,
        clientSecret: result.clientSecret,
      });
      setName("");
      setRedirectUris("");
      setScopes({ openid: true, profile: true });
      setPublicClient(false);
      router.refresh();
    });
  }

  if (created) {
    return (
      <div className="flex flex-col gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/30">
        <h3 className="text-sm font-semibold">Client registered</h3>
        <CopyRow label="client_id" value={created.clientId} />
        {created.clientSecret ? (
          <>
            <CopyRow label="client_secret" value={created.clientSecret} />
            <p className="text-xs text-amber-700 dark:text-amber-400">
              The secret is hashed at rest — this is the only time it will be shown. Copy it now.
            </p>
          </>
        ) : (
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Public client — no secret. The RP must use PKCE (S256).
          </p>
        )}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setCreated(null)}
        >
          Register another
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Name</span>
        <Input placeholder="Their app" value={name} onChange={(e) => setName(e.target.value)} />
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Redirect URIs</span>
        <textarea
          className="min-h-20 rounded-md border border-neutral-300 bg-transparent px-3 py-2 font-mono text-xs shadow-sm placeholder:text-neutral-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400 dark:border-neutral-700"
          placeholder={
            "https://theirapp.com/auth/callback\nhttp://localhost:3100/api/auth/callback/minister"
          }
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
        <span className="text-xs text-neutral-500">
          The RP can request any subset of these; the user still picks which badges to disclose at
          consent time.
        </span>
      </fieldset>

      <label className="flex items-start gap-3 rounded-md border border-neutral-200 p-2 text-sm dark:border-neutral-800">
        <input
          type="checkbox"
          className="mt-1 h-4 w-4"
          checked={publicClient}
          onChange={(e) => setPublicClient(e.target.checked)}
        />
        <span className="flex-1">
          <span className="block font-medium">Public client</span>
          <span className="text-neutral-600 dark:text-neutral-400">
            For SPAs and native apps that can&apos;t keep a secret. PKCE-only; no client_secret is
            issued.
          </span>
        </span>
      </label>

      <Button
        type="button"
        onClick={submit}
        disabled={pending || name.trim().length === 0}
        className="self-start"
      >
        {pending ? "Registering…" : "Register client"}
      </Button>
    </div>
  );
}

function CopyRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-28 shrink-0 font-mono text-xs text-neutral-500">{label}</span>
      <Input readOnly value={value} className="font-mono text-xs" />
      <CopyButton value={value} />
    </div>
  );
}
