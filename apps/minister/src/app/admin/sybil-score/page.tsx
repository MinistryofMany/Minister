import Link from "next/link";

import { AdminSybilForm, type SybilWeightRowView } from "@/components/admin-sybil-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { holderCountsByType } from "@/lib/anonymity-sets";
import { RECOVERY_ELIGIBLE_TYPES } from "@/lib/assurance";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

// /admin/sybil-score — sybilWeight rows + categories/caps + bucket cutoffs, all
// applied IMMEDIATELY (admin gate only). The recovery column here is READ-ONLY;
// editing it lives behind the AAL2 + auth-recency wall at /admin/recovery-config.
export default async function AdminSybilScorePage() {
  await requireAdmin();

  const [weightRows, categories, bucket, holderCounts] = await Promise.all([
    prisma.badgeWeight.findMany({ orderBy: [{ badgeType: "asc" }, { qualifier: "asc" }] }),
    prisma.sybilCategory.findMany({ orderBy: { name: "asc" } }),
    prisma.sybilBucketConfig.findUnique({ where: { id: "singleton" } }),
    holderCountsByType(),
  ]);

  const rows: SybilWeightRowView[] = weightRows.map((r) => ({
    badgeType: r.badgeType,
    qualifier: r.qualifier,
    sybilWeight: r.sybilWeight,
    recoveryWeight: r.recoveryWeight,
    category: r.category,
    holderCount: holderCounts.get(r.badgeType) ?? 0,
    recoveryEligible: RECOVERY_ELIGIBLE_TYPES.has(r.badgeType),
  }));

  const cutoffs = {
    bucket1Raw: bucket?.bucket1Raw ?? 5,
    bucket2Raw: bucket?.bucket2Raw ?? 15,
    bucket3Raw: bucket?.bucket3Raw ?? 28,
    bucket4Raw: bucket?.bucket4Raw ?? 60,
    bucket3MinCats: bucket?.bucket3MinCats ?? 2,
    bucket4MinCats: bucket?.bucket4MinCats ?? 3,
  };

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Anti-sybil score</CardTitle>
          <CardDescription>
            Tune the RP-facing account-strength score: per-credential sybil weights, category caps,
            and the bucket cutoffs. Changes apply immediately. The recovery column is read-only here
            — it governs account recovery and is edited behind a step-up wall at{" "}
            <Link href="/admin/recovery-config" className="underline underline-offset-2">
              /admin/recovery-config
            </Link>
            .
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AdminSybilForm
            initialRows={rows}
            initialCategories={categories.map((c) => ({ name: c.name, cap: c.cap }))}
            initialCutoffs={cutoffs}
          />
        </CardContent>
      </Card>
    </div>
  );
}
