"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { AdminSaveToast } from "@/components/admin-save-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ScorableBadge, SybilScoringConfig } from "@/lib/sybil-config";
import { buildSybilScoringConfig, sybilScore } from "@/lib/sybil-score";
import {
  saveBucketCutoffs,
  updateSybilCategoryCap,
  updateSybilWeight,
} from "@/server/sybil-admin-actions";

export interface SybilWeightRowView {
  badgeType: string;
  qualifier: string;
  sybilWeight: number;
  // The live recoveryWeight column, kept for display alongside the effective
  // value when they differ (see below) — never used on its own.
  recoveryWeight: number;
  // The value the recovery ENGINE actually uses right now (pending, once due;
  // else live) — resolved server-side by the SAME helper /admin/recovery-config
  // uses, so this read-only mirror can never disagree with that page.
  effectiveRecoveryWeight: number;
  category: string;
  holderCount: number;
  recoveryEligible: boolean;
}

export interface SybilCategoryView {
  name: string;
  cap: number;
}

export interface BucketCutoffsView {
  bucket1Raw: number;
  bucket2Raw: number;
  bucket3Raw: number;
  bucket4Raw: number;
  bucket3MinCats: number;
  bucket4MinCats: number;
}

interface Props {
  initialRows: SybilWeightRowView[];
  initialCategories: SybilCategoryView[];
  initialCutoffs: BucketCutoffsView;
}

const rowKey = (badgeType: string, qualifier: string) => `${badgeType} ${qualifier}`;

// A fixed issuer used only for the client-side preview: every example badge and
// the scoring ctx share it, so the scorer's native-issuer filter is a no-op and
// the preview reflects weights/cutoffs, not issuer hygiene.
const PREVIEW_ISSUER = "did:preview:sybil";

// Canonical example holdings for the live cutoff preview. Bucket 4 gates on
// BOTH raw >= b4Raw AND qualifyingCats >= b4Cats (default 3 categories, each
// needing a same-category contribution >= 8 to "qualify" — see
// CATEGORY_QUALIFY_THRESHOLD in sybil-score.ts) — so at least one example must
// span 3 categories that each individually clear that floor at their seeded
// weight, or no cutoff edit could ever preview bucket 4. github oauth (8,
// social-oauth) + domain-control (10, domain) + tlsn-attestation (10,
// attestation) each qualify alone at their seed weights.
const PREVIEW_EXAMPLES: { label: string; badges: ScorableBadge[] }[] = [
  {
    label: "GitHub OAuth + verified email",
    badges: [
      {
        type: "oauth-account",
        attributes: { provider: "github" },
        expiresAt: null,
        issuer: PREVIEW_ISSUER,
      },
      { type: "email-domain", attributes: {}, expiresAt: null, issuer: PREVIEW_ISSUER },
    ],
  },
  {
    label: "Email only",
    badges: [{ type: "email-domain", attributes: {}, expiresAt: null, issuer: PREVIEW_ISSUER }],
  },
  {
    label: "GitHub OAuth + domain control",
    badges: [
      {
        type: "oauth-account",
        attributes: { provider: "github" },
        expiresAt: null,
        issuer: PREVIEW_ISSUER,
      },
      { type: "domain-control", attributes: {}, expiresAt: null, issuer: PREVIEW_ISSUER },
    ],
  },
  {
    label: "GitHub OAuth + domain control + TLSNotary attestation",
    badges: [
      {
        type: "oauth-account",
        attributes: { provider: "github" },
        expiresAt: null,
        issuer: PREVIEW_ISSUER,
      },
      { type: "domain-control", attributes: {}, expiresAt: null, issuer: PREVIEW_ISSUER },
      { type: "tlsn-attestation", attributes: {}, expiresAt: null, issuer: PREVIEW_ISSUER },
    ],
  },
];

export function AdminSybilForm({ initialRows, initialCategories, initialCutoffs }: Props) {
  const router = useRouter();

  // Editable weights/categories per row (keyed by badgeType+qualifier).
  const [weights, setWeights] = useState<Record<string, number>>(() =>
    Object.fromEntries(initialRows.map((r) => [rowKey(r.badgeType, r.qualifier), r.sybilWeight])),
  );
  const [rowCategories, setRowCategories] = useState<Record<string, string>>(() =>
    Object.fromEntries(initialRows.map((r) => [rowKey(r.badgeType, r.qualifier), r.category])),
  );
  const [cutoffs, setCutoffs] = useState<BucketCutoffsView>(initialCutoffs);
  const [caps, setCaps] = useState<Record<string, number>>(() =>
    Object.fromEntries(initialCategories.map((c) => [c.name, c.cap])),
  );

  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const categoryNames = useMemo(() => initialCategories.map((c) => c.name), [initialCategories]);

  // Build a live SybilScoringConfig from the currently-edited (unsaved) weights,
  // categories, caps, and cutoffs — the pure scorer then runs client-side over
  // the example holdings so the preview updates as the admin types.
  const previewConfig = useMemo<SybilScoringConfig>(() => {
    const weightRows = initialRows.map((r) => {
      const key = rowKey(r.badgeType, r.qualifier);
      return {
        badgeType: r.badgeType,
        qualifier: r.qualifier,
        sybilWeight: Math.max(0, Math.floor(weights[key] ?? r.sybilWeight)),
        category: rowCategories[key] ?? r.category,
      };
    });
    const categories = categoryNames.map((name) => ({
      name,
      cap: Math.max(0, Math.floor(caps[name] ?? 0)),
    }));
    return buildSybilScoringConfig(weightRows, categories, cutoffs);
  }, [initialRows, weights, rowCategories, caps, categoryNames, cutoffs]);

  const previews = useMemo(
    () =>
      PREVIEW_EXAMPLES.map((ex) => ({
        label: ex.label,
        result: sybilScore(ex.badges, previewConfig, {
          now: Date.now(),
          nativeIssuerDid: PREVIEW_ISSUER,
        }),
      })),
    [previewConfig],
  );

  // Group rows by badgeType for display.
  const grouped = useMemo(() => {
    const byType = new Map<string, SybilWeightRowView[]>();
    for (const r of initialRows) {
      const list = byType.get(r.badgeType) ?? [];
      list.push(r);
      byType.set(r.badgeType, list);
    }
    return [...byType.entries()];
  }, [initialRows]);

  function reset() {
    setError(null);
    setNotice(null);
  }

  function run(call: () => Promise<{ ok: boolean; error?: string }>, onOk?: string) {
    reset();
    startTransition(async () => {
      const res = await call();
      if (!res.ok) {
        setError(res.error ?? "Something went wrong.");
        return;
      }
      setNotice(onOk ?? "Saved.");
      router.refresh();
    });
  }

  function saveRow(r: SybilWeightRowView) {
    const key = rowKey(r.badgeType, r.qualifier);
    run(() =>
      updateSybilWeight({
        badgeType: r.badgeType,
        qualifier: r.qualifier,
        sybilWeight: Math.max(0, Math.floor(weights[key] ?? r.sybilWeight)),
        category: rowCategories[key] ?? r.category,
      }),
    );
  }

  function saveCutoffs() {
    run(() => saveBucketCutoffs(cutoffs));
  }

  return (
    <div className="flex flex-col gap-8">
      <AdminSaveToast error={error} notice={notice} onDismiss={reset} />

      {/* Weights */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">Sybil weights</h2>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-200 text-left text-xs text-neutral-500 dark:border-neutral-800">
                <th scope="col" className="py-2 pr-3 font-medium">
                  Type / qualifier
                </th>
                <th scope="col" className="py-2 pr-3 font-medium">
                  Sybil weight
                </th>
                <th scope="col" className="py-2 pr-3 font-medium">
                  Category
                </th>
                <th scope="col" className="py-2 pr-3 font-medium">
                  Holders (approx.)
                </th>
                <th scope="col" className="py-2 pr-3 font-medium">
                  Recovery (read-only)
                </th>
                <th scope="col" className="py-2 pr-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {grouped.map(([type, typeRows]) => (
                <TypeGroup
                  key={type}
                  type={type}
                  rows={typeRows}
                  weights={weights}
                  rowCategories={rowCategories}
                  categoryNames={categoryNames}
                  pending={pending}
                  onWeight={(k, v) => setWeights((w) => ({ ...w, [k]: v }))}
                  onCategory={(k, v) => setRowCategories((c) => ({ ...c, [k]: v }))}
                  onSave={saveRow}
                />
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-neutral-500">
          Holder counts are per badge type and approximate (cached ~60s); every qualifier of a type
          shares its type&apos;s count. Each row saves independently — an amber dot marks a row
          you&apos;ve edited but not yet saved.
        </p>
      </section>

      {/* Categories + caps */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">Categories &amp; caps</h2>
        <div className="flex flex-col gap-2">
          {initialCategories.map((c) => (
            <div key={c.name} className="flex flex-wrap items-center gap-2">
              <span className="w-40 font-mono text-xs">{c.name}</span>
              <label className="flex items-center gap-1 text-xs">
                cap
                <Input
                  type="number"
                  className="h-8 w-20"
                  aria-label={`Cap for category ${c.name}`}
                  value={caps[c.name] ?? c.cap}
                  onChange={(e) => setCaps((m) => ({ ...m, [c.name]: Number(e.target.value) }))}
                />
              </label>
              <Button
                type="button"
                variant="outline"
                className="h-8"
                disabled={pending}
                onClick={() =>
                  run(() =>
                    updateSybilCategoryCap({
                      name: c.name,
                      cap: Math.max(0, Math.floor(caps[c.name] ?? c.cap)),
                    }),
                  )
                }
              >
                Save cap
              </Button>
            </div>
          ))}
        </div>
        <p className="text-xs text-neutral-500">
          Categories are defined in code; only their caps are editable here.
        </p>
      </section>

      {/* Bucket cutoffs + live preview */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">Bucket cutoffs</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <CutoffField
            label="Bucket 1 (raw ≥)"
            value={cutoffs.bucket1Raw}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket1Raw: v }))}
          />
          <CutoffField
            label="Bucket 2 (raw ≥)"
            value={cutoffs.bucket2Raw}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket2Raw: v }))}
          />
          <CutoffField
            label="Bucket 3 (raw ≥)"
            value={cutoffs.bucket3Raw}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket3Raw: v }))}
          />
          <CutoffField
            label="Bucket 4 (raw ≥)"
            value={cutoffs.bucket4Raw}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket4Raw: v }))}
          />
          <CutoffField
            label="Bucket 3 min categories"
            value={cutoffs.bucket3MinCats}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket3MinCats: v }))}
          />
          <CutoffField
            label="Bucket 4 min categories"
            value={cutoffs.bucket4MinCats}
            onChange={(v) => setCutoffs((c) => ({ ...c, bucket4MinCats: v }))}
          />
        </div>

        <div className="rounded-md border border-neutral-200 bg-neutral-50 p-3 text-sm dark:border-neutral-800 dark:bg-neutral-900/40">
          <p className="mb-2 text-xs font-medium text-neutral-500">
            Live preview (unsaved cutoffs + current weights)
          </p>
          <ul className="flex flex-col gap-1">
            {previews.map((p) => (
              <li key={p.label} className="font-mono text-xs">
                {p.label}: raw {p.result.raw} → bucket {p.result.bucket}
              </li>
            ))}
          </ul>
        </div>

        <Button type="button" onClick={saveCutoffs} disabled={pending} className="self-start">
          {pending ? "Saving…" : "Save cutoffs"}
        </Button>
      </section>
    </div>
  );
}

function CutoffField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span>{label}</span>
      <Input
        type="number"
        className="h-8"
        aria-label={label}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </label>
  );
}

// Read-only recovery-weight display: the effective (operative) value, with the
// live column shown alongside when they differ — mirrors the
// admin-recovery-form.tsx effective-threshold note, so the two admin pages
// never present a row's recovery weight in conflicting ways.
function RecoveryCell({ r }: { r: SybilWeightRowView }) {
  if (!r.recoveryEligible) {
    return <span className="text-xs text-neutral-400">{r.recoveryWeight} (n/a)</span>;
  }
  if (r.effectiveRecoveryWeight !== r.recoveryWeight) {
    return (
      <span className="text-xs text-neutral-400">
        {r.effectiveRecoveryWeight}
        <span className="text-amber-600 dark:text-amber-400">
          {" "}
          (live column {r.recoveryWeight}; a scheduled weakening is already in effect)
        </span>
      </span>
    );
  }
  return <span className="text-xs text-neutral-400">{r.effectiveRecoveryWeight}</span>;
}

function TypeGroup({
  type,
  rows,
  weights,
  rowCategories,
  categoryNames,
  pending,
  onWeight,
  onCategory,
  onSave,
}: {
  type: string;
  rows: SybilWeightRowView[];
  weights: Record<string, number>;
  rowCategories: Record<string, string>;
  categoryNames: string[];
  pending: boolean;
  onWeight: (key: string, value: number) => void;
  onCategory: (key: string, value: string) => void;
  onSave: (r: SybilWeightRowView) => void;
}) {
  return (
    <>
      {rows.map((r, i) => {
        const key = rowKey(r.badgeType, r.qualifier);
        const weightValue = weights[key] ?? r.sybilWeight;
        const categoryValue = rowCategories[key] ?? r.category;
        const dirty = weightValue !== r.sybilWeight || categoryValue !== r.category;
        return (
          <tr key={key} className="border-b border-neutral-100 dark:border-neutral-900">
            <td className="py-1 pr-3 font-mono text-xs">
              {i === 0 ? (
                <span className="text-neutral-700 dark:text-neutral-300">{type}</span>
              ) : null}
              <span className="text-neutral-400"> {r.qualifier}</span>
            </td>
            <td className="py-1 pr-3">
              <Input
                type="number"
                className="h-8 w-20"
                aria-label={`Sybil weight for ${r.badgeType} ${r.qualifier}`}
                value={weightValue}
                onChange={(e) => onWeight(key, Number(e.target.value))}
              />
            </td>
            <td className="py-1 pr-3">
              <select
                className="h-8 rounded-md border border-neutral-300 bg-transparent px-2 text-xs dark:border-neutral-700"
                aria-label={`Category for ${r.badgeType} ${r.qualifier}`}
                value={categoryValue}
                onChange={(e) => onCategory(key, e.target.value)}
              >
                {categoryNames.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </td>
            <td className="py-1 pr-3 text-xs text-neutral-500">{r.holderCount}</td>
            <td className="py-1 pr-3">
              <RecoveryCell r={r} />
            </td>
            <td className="py-1 pr-3">
              <div className="flex items-center gap-2">
                {dirty ? (
                  <span
                    className="h-2 w-2 shrink-0 rounded-full bg-amber-500"
                    title="Unsaved changes"
                    aria-label="Unsaved changes"
                  />
                ) : null}
                <Button
                  type="button"
                  variant="outline"
                  className="h-8"
                  disabled={pending || !dirty}
                  onClick={() => onSave(r)}
                >
                  {pending ? "Saving…" : "Save"}
                </Button>
              </div>
            </td>
          </tr>
        );
      })}
    </>
  );
}
