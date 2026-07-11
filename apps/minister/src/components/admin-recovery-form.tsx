"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { signIn as signInWebAuthn } from "next-auth/webauthn";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ActionResult } from "@/server/credential-actions";
import {
  setAllowSoloRecovery,
  updateRecoveryThreshold,
  updateRecoveryWeight,
} from "@/server/recovery-config-actions";

export interface RecoveryWeightRowView {
  badgeType: string;
  qualifier: string;
  recoveryWeight: number;
  pendingRecoveryWeight: number | null;
  recoveryEffectiveAt: string | null;
  allowSoloRecovery: boolean;
  eligible: boolean;
}

export interface RecoveryConfigView {
  threshold: number;
  pendingThreshold: number | null;
  thresholdEffectiveAt: string | null;
}

interface Props {
  initialRows: RecoveryWeightRowView[];
  initialConfig: RecoveryConfigView;
}

const rowKey = (badgeType: string, qualifier: string) => `${badgeType} ${qualifier}`;

// Run a wrapped action; on a step-up result, run a passkey ceremony (which
// re-stamps auth_time), then retry ONCE. Returns the final non-step-up result,
// or null if the step-up was abandoned/failed. Mirrors the credentials manager.
async function withStepUp<T>(
  call: () => Promise<ActionResult<T>>,
): Promise<ActionResult<T> | null> {
  const first = await call();
  if (first.ok || !("stepUp" in first) || !first.stepUp) {
    return first;
  }
  try {
    const res = await signInWebAuthn("passkey", { redirect: false });
    if (res && "error" in res && res.error) return null;
  } catch {
    return null;
  }
  const retried = await call();
  if (!retried.ok && "stepUp" in retried && retried.stepUp) return null;
  return retried;
}

export function AdminRecoveryForm({ initialRows, initialConfig }: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [weights, setWeights] = useState<Record<string, number>>(() =>
    Object.fromEntries(
      initialRows.map((r) => [rowKey(r.badgeType, r.qualifier), r.recoveryWeight]),
    ),
  );
  const [threshold, setThreshold] = useState(initialConfig.threshold);

  const pendingChanges = useMemo(() => {
    const items: string[] = [];
    for (const r of initialRows) {
      if (r.pendingRecoveryWeight != null && r.recoveryEffectiveAt) {
        items.push(
          `${r.badgeType} / ${r.qualifier}: weight → ${r.pendingRecoveryWeight} at ${new Date(r.recoveryEffectiveAt).toLocaleString()}`,
        );
      }
    }
    if (initialConfig.pendingThreshold != null && initialConfig.thresholdEffectiveAt) {
      items.push(
        `threshold → ${initialConfig.pendingThreshold} at ${new Date(initialConfig.thresholdEffectiveAt).toLocaleString()}`,
      );
    }
    return items;
  }, [initialRows, initialConfig]);

  function reset() {
    setError(null);
    setNotice(null);
  }

  // Dispatch an action through the step-up dance; surface result; refresh on ok.
  function dispatch<T>(call: () => Promise<ActionResult<T>>, onOk?: (data: T) => void) {
    reset();
    startTransition(async () => {
      const res = await withStepUp(call);
      if (res === null) {
        setError("A recent passkey re-authentication is required and was not completed.");
        return;
      }
      if (!res.ok) {
        if ("stepUp" in res && res.stepUp) {
          setError("This action needs a recent passkey re-auth. Use a passkey, then try again.");
        } else {
          setError(res.error);
        }
        return;
      }
      onOk?.(res.data);
      router.refresh();
    });
  }

  function saveWeight(r: RecoveryWeightRowView) {
    const key = rowKey(r.badgeType, r.qualifier);
    const value = Math.floor(weights[key] ?? r.recoveryWeight);
    dispatch(
      () =>
        updateRecoveryWeight({
          badgeType: r.badgeType,
          qualifier: r.qualifier,
          recoveryWeight: value,
        }),
      (data) =>
        setNotice(
          data.effectiveAt
            ? `Scheduled — takes effect in 72h at ${new Date(data.effectiveAt).toLocaleString()}.`
            : "Applied immediately.",
        ),
    );
  }

  function toggleSolo(r: RecoveryWeightRowView, next: boolean) {
    dispatch(
      () =>
        setAllowSoloRecovery({
          badgeType: r.badgeType,
          qualifier: r.qualifier,
          allowSoloRecovery: next,
        }),
      () => setNotice("Solo-recovery flag updated."),
    );
  }

  function saveThreshold() {
    dispatch(
      () => updateRecoveryThreshold({ threshold: Math.floor(threshold) }),
      (data) =>
        setNotice(
          data.effectiveAt
            ? `Scheduled — takes effect in 72h at ${new Date(data.effectiveAt).toLocaleString()}.`
            : "Applied immediately.",
        ),
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/30 dark:text-red-400">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-400">
          {notice}
        </div>
      ) : null}

      {pendingChanges.length > 0 ? (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300">
          <p className="mb-1 font-medium">Pending weakening changes</p>
          <ul className="flex flex-col gap-0.5">
            {pendingChanges.map((c) => (
              <li key={c} className="font-mono text-xs">
                {c}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Threshold */}
      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-semibold">Recovery threshold</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs">
            <span>Threshold (100–1000)</span>
            <Input
              type="number"
              className="h-8 w-28"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </label>
          <Button type="button" className="h-8" disabled={pending} onClick={saveThreshold}>
            Save threshold
          </Button>
        </div>
        <p className="text-xs text-neutral-500">
          Live threshold: {initialConfig.threshold}. Raising it applies immediately; lowering it is
          scheduled 72h out.
        </p>
      </section>

      {/* Per-row weights + solo */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold">Recovery weights</h2>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-200 text-left text-xs text-neutral-500 dark:border-neutral-800">
                <th className="py-2 pr-3 font-medium">Type / qualifier</th>
                <th className="py-2 pr-3 font-medium">Recovery weight</th>
                <th className="py-2 pr-3 font-medium">Solo recovery</th>
                <th className="py-2 pr-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {initialRows.map((r) => {
                const key = rowKey(r.badgeType, r.qualifier);
                return (
                  <tr key={key} className="border-b border-neutral-100 dark:border-neutral-900">
                    <td className="py-1 pr-3 font-mono text-xs">
                      <span className="text-neutral-700 dark:text-neutral-300">{r.badgeType}</span>
                      <span className="text-neutral-400"> {r.qualifier}</span>
                      {r.eligible ? null : (
                        <span className="ml-1 text-neutral-400">(ineligible)</span>
                      )}
                    </td>
                    <td className="py-1 pr-3">
                      <Input
                        type="number"
                        className="h-8 w-20"
                        value={weights[key] ?? r.recoveryWeight}
                        disabled={!r.eligible || pending}
                        onChange={(e) =>
                          setWeights((w) => ({ ...w, [key]: Number(e.target.value) }))
                        }
                      />
                    </td>
                    <td className="py-1 pr-3">
                      <input
                        type="checkbox"
                        className="h-4 w-4"
                        checked={r.allowSoloRecovery}
                        disabled={pending}
                        onChange={(e) => toggleSolo(r, e.target.checked)}
                      />
                    </td>
                    <td className="py-1 pr-3">
                      <Button
                        type="button"
                        variant="outline"
                        className="h-8"
                        disabled={!r.eligible || pending}
                        onClick={() => saveWeight(r)}
                      >
                        Save
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-neutral-500">
          The recovery column is editable only for recovery-eligible types (oauth-account,
          email-domain, email-exact, tlsn-attestation). Eligibility is a code property — a plugin
          must be able to nonce-bind a live re-proof — not a DB toggle.
        </p>
      </section>
    </div>
  );
}
