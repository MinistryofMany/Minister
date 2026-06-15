import Link from "next/link";

import { prisma } from "@/lib/prisma";
import { requireAdmin } from "@/lib/session";

const PAGE_SIZE = 50;

export default async function AdminAuditPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  await requireAdmin();

  const params = await searchParams;
  const pageParam = Number.parseInt(params.page ?? "1", 10);
  const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1;

  const [entries, total] = await Promise.all([
    prisma.auditLog.findMany({
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
    }),
    prisma.auditLog.count(),
  ]);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">
        Audit log{" "}
        <span className="text-sm font-normal text-neutral-500">
          ({total} entr{total === 1 ? "y" : "ies"})
        </span>
      </h2>

      {entries.length === 0 ? (
        <p className="text-sm text-neutral-600 dark:text-neutral-400">Nothing here yet.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {entries.map((e) => (
            <li
              key={e.id}
              className="rounded-lg border border-neutral-200 bg-white p-3 text-sm dark:border-neutral-800 dark:bg-neutral-950"
            >
              <div className="flex items-baseline justify-between gap-3">
                <code className="font-mono text-xs font-semibold">{e.action}</code>
                <span className="shrink-0 text-xs text-neutral-500">
                  {e.createdAt.toLocaleString()}
                </span>
              </div>
              <div className="mt-1 text-xs text-neutral-500">
                user: <code className="font-mono">{e.userId ?? "—"}</code>
              </div>
              <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-neutral-600 dark:text-neutral-400">
                {JSON.stringify(e.metadata)}
              </pre>
            </li>
          ))}
        </ul>
      )}

      {pageCount > 1 ? (
        <nav className="flex items-center gap-3 text-sm">
          {page > 1 ? (
            <Link href={`/admin/audit?page=${page - 1}`} className="underline underline-offset-2">
              Newer
            </Link>
          ) : null}
          <span className="text-neutral-500">
            Page {page} of {pageCount}
          </span>
          {page < pageCount ? (
            <Link href={`/admin/audit?page=${page + 1}`} className="underline underline-offset-2">
              Older
            </Link>
          ) : null}
        </nav>
      ) : null}
    </section>
  );
}
