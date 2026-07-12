"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const ADMIN_TABS: { href: string; label: string }[] = [
  { href: "/admin/users", label: "Users" },
  { href: "/admin/invite-codes", label: "Invite codes" },
  { href: "/admin/oidc-clients", label: "OIDC clients" },
  { href: "/admin/sybil-score", label: "Sybil score" },
  { href: "/admin/stats", label: "Stats" },
  { href: "/admin/recovery-config", label: "Recovery config" },
  { href: "/admin/audit", label: "Audit log" },
];

// A small client island (usePathname needs one) so the active tab is visibly
// marked — the rest of the admin layout stays a plain RSC tree.
export function AdminNav() {
  const pathname = usePathname();

  return (
    <nav className="flex gap-1 border-b border-neutral-200 pb-px text-sm dark:border-neutral-800">
      {ADMIN_TABS.map((tab) => {
        const active = pathname === tab.href || (pathname?.startsWith(`${tab.href}/`) ?? false);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            aria-current={active ? "page" : undefined}
            className={
              active
                ? "rounded-t-md border-b-2 border-neutral-900 px-3 py-2 font-medium text-neutral-900 dark:border-neutral-100 dark:text-neutral-100"
                : "rounded-t-md px-3 py-2 font-medium text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-100"
            }
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
