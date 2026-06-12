"use client";

import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  deleteOidcClient,
  rotateOidcClientSecret,
} from "@/server/admin-actions";

export function AdminOidcClientActions({
  id,
  name,
  isPublic,
}: {
  id: string;
  name: string;
  isPublic: boolean;
}) {
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);

  return (
    <div className="flex flex-1 flex-col gap-2">
      <div className="flex items-center gap-2">
        {!isPublic ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={pending}
            onClick={() => {
              if (
                typeof window !== "undefined" &&
                !window.confirm(
                  `Rotate the secret for "${name}"? The old secret stops working immediately.`,
                )
              ) {
                return;
              }
              setError(null);
              startTransition(async () => {
                const result = await rotateOidcClientSecret({ id });
                if (!result.ok) setError(result.error);
                else setRotatedSecret(result.clientSecret);
              });
            }}
          >
            Rotate secret
          </Button>
        ) : null}
        <Button
          type="button"
          variant="destructive"
          size="sm"
          disabled={pending}
          onClick={() => {
            if (
              typeof window !== "undefined" &&
              !window.confirm(
                `Delete "${name}"? Outstanding tokens are revoked and sign-in from this relying party stops working immediately.`,
              )
            ) {
              return;
            }
            setError(null);
            startTransition(async () => {
              const result = await deleteOidcClient({ id });
              if (!result.ok) setError(result.error);
            });
          }}
        >
          Delete
        </Button>
        {error ? <span className="text-xs text-red-600">{error}</span> : null}
      </div>

      {rotatedSecret ? (
        <div className="flex flex-col gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-900/40 dark:bg-amber-950/30">
          <span className="text-xs font-medium text-amber-800 dark:text-amber-300">
            New client_secret — shown once, copy it now:
          </span>
          <div className="flex items-center gap-2">
            <Input
              readOnly
              value={rotatedSecret}
              className="font-mono text-xs"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                if (typeof navigator !== "undefined" && navigator.clipboard) {
                  void navigator.clipboard.writeText(rotatedSecret);
                }
              }}
            >
              Copy
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setRotatedSecret(null)}
            >
              Dismiss
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
