import Link from "next/link";
import { redirect } from "next/navigation";

import { getSessionFlags } from "@/lib/session";

// Every /admin page lives under this layout, so the isAdmin gate runs
// exactly once per request. Middleware already bounced anonymous
// visitors; this catches signed-in non-admins.
export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const flags = await getSessionFlags();
  if (!flags?.isAdmin) redirect("/");

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Admin</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Users, invite codes, and the audit trail.
        </p>
      </header>

      <nav className="flex gap-1 border-b border-neutral-200 pb-px text-sm dark:border-neutral-800">
        <AdminTab href="/admin/users">Users</AdminTab>
        <AdminTab href="/admin/invite-codes">Invite codes</AdminTab>
        <AdminTab href="/admin/oidc-clients">OIDC clients</AdminTab>
        <AdminTab href="/admin/audit">Audit log</AdminTab>
      </nav>

      {children}
    </div>
  );
}

function AdminTab({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  // Server layouts can't read the current pathname without a client
  // boundary; a plain link row keeps this whole tree RSC-only. The
  // active page is obvious from its own heading.
  return (
    <Link
      href={href}
      className="rounded-t-md px-3 py-2 font-medium text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-100"
    >
      {children}
    </Link>
  );
}
