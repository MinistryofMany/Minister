"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import { Input } from "@/components/ui/input";
import { createInviteCode } from "@/server/admin-actions";

const USES_OPTIONS = [
  { value: 1, label: "Single use" },
  { value: 10, label: "10 uses" },
  { value: 100, label: "100 uses" },
  { value: 0, label: "Unlimited" },
] as const;

const TTL_OPTIONS = [
  { value: undefined, label: "Never expires" },
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
] as const;

export function AdminInviteCreateForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [label, setLabel] = useState("");
  const [customCode, setCustomCode] = useState("");
  const [usesTotal, setUsesTotal] = useState<number>(1);
  const [ttlDays, setTtlDays] = useState<number | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [createdCode, setCreatedCode] = useState<string | null>(null);

  function submit() {
    setError(null);
    startTransition(async () => {
      const result = await createInviteCode({
        label,
        customCode: customCode || undefined,
        usesTotal,
        ttlDays,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setCreatedCode(result.code);
      setLabel("");
      setCustomCode("");
      router.refresh();
    });
  }

  if (createdCode) {
    return (
      <div className="flex flex-col gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/30">
        <h3 className="text-sm font-semibold">Invite code minted</h3>
        <div className="flex items-center gap-2">
          <Input readOnly value={createdCode} className="font-mono text-sm" />
          <CopyButton value={createdCode} />
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="self-start"
          onClick={() => setCreatedCode(null)}
        >
          Mint another
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
        <span className="font-medium">Label</span>
        <Input
          placeholder="Beta cohort"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <span className="text-xs text-neutral-500">
          Shown to admins and embedded in the badge the redeemer receives.
        </span>
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Custom code (optional)</span>
        <Input
          placeholder="Leave empty to auto-generate"
          value={customCode}
          onChange={(e) => setCustomCode(e.target.value)}
          className="font-mono"
        />
        <span className="text-xs text-neutral-500">
          4-64 letters, digits, or hyphens. Stored uppercase.
        </span>
      </label>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Uses</legend>
        <div className="flex flex-wrap gap-2">
          {USES_OPTIONS.map((opt) => (
            <PillRadio
              key={opt.label}
              name="uses"
              checked={usesTotal === opt.value}
              onSelect={() => setUsesTotal(opt.value)}
            >
              {opt.label}
            </PillRadio>
          ))}
        </div>
      </fieldset>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium">Expiry</legend>
        <div className="flex flex-wrap gap-2">
          {TTL_OPTIONS.map((opt) => (
            <PillRadio
              key={opt.label}
              name="ttl"
              checked={ttlDays === opt.value}
              onSelect={() => setTtlDays(opt.value)}
            >
              {opt.label}
            </PillRadio>
          ))}
        </div>
      </fieldset>

      <Button
        type="button"
        onClick={submit}
        disabled={pending || label.trim().length === 0}
        className="self-start"
      >
        {pending ? "Minting…" : "Mint code"}
      </Button>
    </div>
  );
}

function PillRadio({
  name,
  checked,
  onSelect,
  children,
}: {
  name: string;
  checked: boolean;
  onSelect(): void;
  children: React.ReactNode;
}) {
  return (
    <label
      className={
        "cursor-pointer rounded-md border px-3 py-1 text-sm " +
        (checked
          ? "border-neutral-900 bg-neutral-900 text-white dark:border-neutral-100 dark:bg-neutral-100 dark:text-neutral-900"
          : "border-neutral-300 dark:border-neutral-700")
      }
    >
      <input
        type="radio"
        name={name}
        checked={checked}
        onChange={onSelect}
        className="sr-only"
      />
      {children}
    </label>
  );
}
