"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { createCohortDef } from "@/server/stats-actions";

const MAX_CLAUSES = 3;

// One clause is `{ type, where?, whereGte? }` (cohort-filter.ts). The form only
// exposes one `where` pair and one `whereGte` pair per clause — enough for every
// current allowlisted key (each type has at most a small handful) and for the
// built-in github cohort, which needs exactly one of each on its numerator
// clause. The server re-validates the assembled filter against the real
// `cohortFilterSchema`, so a sloppy client build just surfaces as an error, never
// a bad write.
interface ClauseInput {
  type: string;
  whereKey: string;
  whereValue: string;
  whereGteKey: string;
  whereGteValue: string;
}

function emptyClause(): ClauseInput {
  return { type: "", whereKey: "", whereValue: "", whereGteKey: "", whereGteValue: "" };
}

// Builds the untrusted JSON blob the server parses with `cohortFilterSchema`.
// Blank clause rows (no type typed yet) are dropped rather than sent as
// `{type: ""}`, so an admin who added a spare clause row and left it empty
// doesn't get a confusing "unknown badge type" error.
function buildFilter(clauses: ClauseInput[]): unknown {
  return {
    clauses: clauses
      .filter((c) => c.type.trim().length > 0)
      .map((c) => {
        const where: Record<string, string> = {};
        if (c.whereKey.trim()) where[c.whereKey.trim()] = c.whereValue.trim();
        const whereGte: Record<string, number> = {};
        if (c.whereGteKey.trim()) whereGte[c.whereGteKey.trim()] = Number(c.whereGteValue.trim());
        return {
          type: c.type.trim(),
          ...(Object.keys(where).length > 0 ? { where } : {}),
          ...(Object.keys(whereGte).length > 0 ? { whereGte } : {}),
        };
      }),
  };
}

function ClauseBuilder({
  title,
  clauses,
  onChange,
}: {
  title: string;
  clauses: ClauseInput[];
  onChange: (next: ClauseInput[]) => void;
}) {
  function update(i: number, patch: Partial<ClauseInput>) {
    onChange(clauses.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }
  function remove(i: number) {
    onChange(clauses.filter((_, idx) => idx !== i));
  }

  return (
    <fieldset className="flex flex-col gap-2 rounded-md border border-neutral-200 p-3 dark:border-neutral-800">
      <legend className="px-1 text-xs font-medium uppercase tracking-wide text-neutral-500">
        {title}
      </legend>
      {clauses.map((c, i) => (
        <div key={i} className="flex flex-wrap items-center gap-2">
          <Input
            className="w-44 font-mono text-xs"
            placeholder="badge type"
            value={c.type}
            onChange={(e) => update(i, { type: e.target.value })}
          />
          <span className="text-xs text-neutral-400">where</span>
          <Input
            className="w-24 font-mono text-xs"
            placeholder="key"
            value={c.whereKey}
            onChange={(e) => update(i, { whereKey: e.target.value })}
          />
          <span className="text-xs text-neutral-400">=</span>
          <Input
            className="w-24 font-mono text-xs"
            placeholder="value"
            value={c.whereValue}
            onChange={(e) => update(i, { whereValue: e.target.value })}
          />
          <span className="text-xs text-neutral-400">and</span>
          <Input
            className="w-24 font-mono text-xs"
            placeholder="key"
            value={c.whereGteKey}
            onChange={(e) => update(i, { whereGteKey: e.target.value })}
          />
          <span className="text-xs text-neutral-400">&gt;=</span>
          <Input
            className="w-16 font-mono text-xs"
            placeholder="value"
            value={c.whereGteValue}
            onChange={(e) => update(i, { whereGteValue: e.target.value })}
          />
          {clauses.length > 1 ? (
            <Button type="button" variant="ghost" size="sm" onClick={() => remove(i)}>
              Remove
            </Button>
          ) : null}
        </div>
      ))}
      {clauses.length < MAX_CLAUSES ? (
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="self-start"
          onClick={() => onChange([...clauses, emptyClause()])}
        >
          + Add clause
        </Button>
      ) : null}
    </fieldset>
  );
}

export function AdminCohortDefForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [label, setLabel] = useState("");
  const [numerator, setNumerator] = useState<ClauseInput[]>([emptyClause()]);
  const [denominator, setDenominator] = useState<ClauseInput[]>([emptyClause()]);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function submit() {
    setError(null);
    setSaved(false);
    startTransition(async () => {
      const result = await createCohortDef({
        label,
        numeratorFilter: buildFilter(numerator),
        denominatorFilter: buildFilter(denominator),
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setSaved(true);
      setLabel("");
      setNumerator([emptyClause()]);
      setDenominator([emptyClause()]);
      router.refresh();
    });
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200">
        A new cohort is created <strong>unpublished</strong>. Once you publish it, its{" "}
        <strong>label and counts become world-visible</strong> on the public /transparency page — so
        keep the label generic and never put anything identifying (a person, an org, a domain) in
        it.
      </div>
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}
      {saved ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-400">
          Added — pending next recompute.
        </div>
      ) : null}

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium">Label</span>
        <Input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Aged GitHub accounts (share of GitHub accounts)"
        />
      </label>

      <ClauseBuilder title="Numerator" clauses={numerator} onChange={setNumerator} />
      <ClauseBuilder title="Denominator" clauses={denominator} onChange={setDenominator} />

      <Button
        type="button"
        onClick={submit}
        disabled={pending || label.trim().length === 0}
        className="self-start"
      >
        {pending ? "Adding…" : "Add cohort"}
      </Button>
    </div>
  );
}
