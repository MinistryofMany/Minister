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

  const rows: RecoveryWeightRowView[] = weightRows.map((r) => ({
    badgeType: r.badgeType,
    qualifier: r.qualifier,
    recoveryWeight: r.recoveryWeight,
    pendingRecoveryWeight: r.pendingRecoveryWeight,
    recoveryEffectiveAt: r.recoveryEffectiveAt ? r.recoveryEffectiveAt.toISOString() : null,
    allowSoloRecovery: r.allowSoloRecovery,
    eligible: RECOVERY_ELIGIBLE_TYPES.has(r.badgeType),
  }));

  const config: RecoveryConfigView = {
    threshold: cfg?.threshold ?? 100,
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
          <AdminRecoveryForm initialRows={rows} initialConfig={config} />
        </CardContent>
      </Card>
    </div>
  );
}
