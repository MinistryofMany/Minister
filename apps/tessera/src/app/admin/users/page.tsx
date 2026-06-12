import { AdminUserBanButton } from "@/components/admin-user-ban-button";
import { AdminUserRoleButton } from "@/components/admin-user-role-button";
import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

export default async function AdminUsersPage() {
  const session = await requireAdmin();

  const users = await prisma.user.findMany({
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      email: true,
      displayName: true,
      name: true,
      isAdmin: true,
      isBanned: true,
      createdAt: true,
      _count: { select: { badges: true } },
    },
  });

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">
        Users{" "}
        <span className="text-sm font-normal text-neutral-500">
          ({users.length})
        </span>
      </h2>

      <ul className="flex flex-col gap-2">
        {users.map((u) => {
          const label = u.displayName ?? u.name ?? u.email ?? u.id;
          return (
            <li
              key={u.id}
              className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-950"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium">{label}</span>
                  {u.isAdmin ? <Chip tone="violet">admin</Chip> : null}
                  {u.isBanned ? <Chip tone="red">banned</Chip> : null}
                  {u.id === session.user.id ? (
                    <Chip tone="neutral">you</Chip>
                  ) : null}
                </div>
                <div className="mt-0.5 truncate text-xs text-neutral-500">
                  {u.email ?? "no email"} · {u._count.badges} badge
                  {u._count.badges === 1 ? "" : "s"} · joined{" "}
                  {u.createdAt.toLocaleDateString()}
                </div>
              </div>
              {u.id !== session.user.id ? (
                <div className="flex items-center gap-2">
                  {/* Banned users can't be promoted (unban first), and
                      admins can't be banned (demote first). */}
                  {!u.isBanned ? (
                    <AdminUserRoleButton userId={u.id} isAdmin={u.isAdmin} />
                  ) : null}
                  {!u.isAdmin ? (
                    <AdminUserBanButton userId={u.id} banned={u.isBanned} />
                  ) : null}
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Chip({
  tone,
  children,
}: {
  tone: "violet" | "red" | "neutral";
  children: React.ReactNode;
}) {
  const styles =
    tone === "violet"
      ? "bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400"
      : tone === "red"
        ? "bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400"
        : "bg-neutral-100 text-neutral-500 dark:bg-neutral-900 dark:text-neutral-400";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${styles}`}
    >
      {children}
    </span>
  );
}
