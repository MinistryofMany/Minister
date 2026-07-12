import { redirect } from "next/navigation";

import { AdminNav } from "@/components/admin-nav";
import { getSessionFlags } from "@/lib/session";

// Every /admin page lives under this layout, so the isAdmin gate runs
// exactly once per request. Middleware already bounced anonymous
// visitors; this catches signed-in non-admins.
export default async function AdminLayout({ children }: { children: React.ReactNode }) {
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

      {/* AdminNav is a small client island (usePathname) so the active tab is
          marked; the rest of this tree stays a plain RSC page. */}
      <AdminNav />

      {children}
    </div>
  );
}
