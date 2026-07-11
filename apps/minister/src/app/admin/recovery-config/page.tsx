import {
  AdminRecoveryForm,
  type RecoveryConfigView,
  type RecoveryWeightRowView,
} from "@/components/admin-recovery-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RECOVERY_ELIGIBLE_TYPES } from "@/lib/assurance";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

// /admin/recovery-config — the account-takeover control surface. Editing here is
// walled by the server actions (AAL2 + non-recovered + fresh auth-recency +
// guardrails). recoveryWeight changes apply ASYMMETRICALLY: a defensive edit
// (weight down / threshold up) lands immediately; a weakening (weight up /
// threshold down) is scheduled 72h out and shown in the pending banner.
export default async function AdminRecoveryConfigPage() {
  await requireAdmin();

  const [weightRows, cfg] = await Promise.all([
    prisma.badgeWeight.findMany({ orderBy: [{ badgeType: "asc" }, { qualifier: "asc" }] }),
    prisma.recoveryConfig.findUnique({ where: { id: "singleton" } }),
  ]);

  // Phase 1 has NO promotion job: once a scheduled weakening's effectiveAt
  // passes, the recovery ENGINE reads the pending value (sybil-config.ts
  // effectiveRecoveryWeight / loadEffectiveThreshold) but the live column is
  // never promoted. Compute the EFFECTIVE value here (pending, once due; else
  // live) and hand THAT to the editor as the operative value, so the admin's
  // review surface can never show a stale-but-safe-looking number while an
  // already-landed weakening is silently in force. Display-only — the engine is
  // untouched. `now` is server-stamped so the client's scheduled/in-effect split
  // matches this computation.
  const now = Date.now();
  const effectiveWeight = (r: {
    recoveryWeight: number;
    pendingRecoveryWeight: number | null;
    recoveryEffectiveAt: Date | null;
  }): number =>
    r.pendingRecoveryWeight != null &&
    r.recoveryEffectiveAt != null &&
    r.recoveryEffectiveAt.getTime() <= now
      ? r.pendingRecoveryWeight
      : r.recoveryWeight;

  const rows: RecoveryWeightRowView[] = weightRows.map((r) => ({
    badgeType: r.badgeType,
    qualifier: r.qualifier,
    recoveryWeight: r.recoveryWeight,
    effectiveRecoveryWeight: effectiveWeight(r),
    pendingRecoveryWeight: r.pendingRecoveryWeight,
    recoveryEffectiveAt: r.recoveryEffectiveAt ? r.recoveryEffectiveAt.toISOString() : null,
    allowSoloRecovery: r.allowSoloRecovery,
    eligible: RECOVERY_ELIGIBLE_TYPES.has(r.badgeType),
  }));

  const liveThreshold = cfg?.threshold ?? 100;
  const effectiveThreshold =
    cfg?.pendingThreshold != null &&
    cfg?.thresholdEffectiveAt != null &&
    cfg.thresholdEffectiveAt.getTime() <= now
      ? cfg.pendingThreshold
      : liveThreshold;

  const config: RecoveryConfigView = {
    threshold: liveThreshold,
    effectiveThreshold,
    pendingThreshold: cfg?.pendingThreshold ?? null,
    thresholdEffectiveAt: cfg?.thresholdEffectiveAt ? cfg.thresholdEffectiveAt.toISOString() : null,
  };

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Recovery config</CardTitle>
          <CardDescription>
            Account-recovery weights and threshold. Editing requires a recent passkey re-auth.
            Defensive changes (lower a weight, raise the threshold) apply immediately; weakening
            changes (raise a weight, lower the threshold) take effect after a 72-hour delay and
            email every admin. The recovery column is editable only for recovery-eligible types,
            because &ldquo;recovery-eligible&rdquo; is a code property (a plugin can nonce-bind a
            live re-proof), not a database toggle.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AdminRecoveryForm initialRows={rows} initialConfig={config} now={now} />
        </CardContent>
      </Card>
    </div>
  );
}
