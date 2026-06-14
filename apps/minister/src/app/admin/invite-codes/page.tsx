import { AdminInviteCreateForm } from "@/components/admin-invite-create-form";
import { AdminInviteRevokeButton } from "@/components/admin-invite-revoke-button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

type CodeStatus = "active" | "expired" | "exhausted" | "revoked";

function statusOf(row: {
  usesTotal: number;
  usesRemaining: number;
  expiresAt: Date | null;
  revokedAt: Date | null;
}): CodeStatus {
  if (row.revokedAt) return "revoked";
  if (row.expiresAt && row.expiresAt < new Date()) return "expired";
  if (row.usesTotal > 0 && row.usesRemaining <= 0) return "exhausted";
  return "active";
}

export default async function AdminInviteCodesPage() {
  await requireAdmin();

  const codes = await prisma.inviteCode.findMany({
    orderBy: { createdAt: "desc" },
    include: { _count: { select: { redemptions: true } } },
  });

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Mint an invite code</CardTitle>
          <CardDescription>
            Users redeem codes through the &ldquo;Invite code&rdquo; badge
            wizard. The issued credential names the label, never the code.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AdminInviteCreateForm />
        </CardContent>
      </Card>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">
          Codes{" "}
          <span className="text-sm font-normal text-neutral-500">
            ({codes.length})
          </span>
        </h2>

        {codes.length === 0 ? (
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            No invite codes yet.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {codes.map((c) => {
              const status = statusOf(c);
              return (
                <li
                  key={c.id}
                  className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-950"
                >
                  <StatusChip status={status} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <code className="truncate font-mono text-sm">
                        {c.code}
                      </code>
                      <span className="truncate text-sm text-neutral-600 dark:text-neutral-400">
                        {c.label}
                      </span>
                    </div>
                    <div className="mt-0.5 text-xs text-neutral-500">
                      {c.usesTotal === 0
                        ? `${c._count.redemptions} redemption${c._count.redemptions === 1 ? "" : "s"} · unlimited`
                        : `${c.usesTotal - c.usesRemaining}/${c.usesTotal} used`}
                      {c.expiresAt
                        ? ` · expires ${c.expiresAt.toLocaleDateString()}`
                        : " · never expires"}
                    </div>
                  </div>
                  {status === "active" || status === "exhausted" ? (
                    <AdminInviteRevokeButton inviteCodeId={c.id} />
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}

function StatusChip({ status }: { status: CodeStatus }) {
  const styles =
    status === "active"
      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
      : status === "revoked"
        ? "bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400"
        : "bg-neutral-100 text-neutral-500 dark:bg-neutral-900 dark:text-neutral-400";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${styles}`}
    >
      {status}
    </span>
  );
}
