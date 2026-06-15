import Link from "next/link";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { ShareLinkCreateForm } from "@/components/share-link-create-form";
import { ShareLinkRevokeButton } from "@/components/share-link-revoke";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loadUserBadges } from "@/lib/badges";
import { getCurrentSession } from "@/lib/session";
import { loadUserShareLinks } from "@/lib/share-links";

export default async function SharesPage() {
  const session = await getCurrentSession();
  if (!session?.user) redirect("/");

  const [badges, shareLinks] = await Promise.all([
    loadUserBadges(session.user.id),
    loadUserShareLinks(session.user.id),
  ]);

  const h = await headers();
  const origin = `${h.get("x-forwarded-proto") ?? "http"}://${h.get("host") ?? "localhost:3000"}`;

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Share links</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Hand a URL to anyone and they&apos;ll see exactly the badges you chose, until the link
          expires or you revoke it.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Create a new link</CardTitle>
          <CardDescription>Pick badges, set an expiry, optionally email the URL.</CardDescription>
        </CardHeader>
        <CardContent>
          <ShareLinkCreateForm badges={badges} origin={origin} />
        </CardContent>
      </Card>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">
          Your share links{" "}
          <span className="text-sm font-normal text-neutral-500">({shareLinks.length})</span>
        </h2>

        {shareLinks.length === 0 ? (
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            You haven&apos;t created any yet.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {shareLinks.map((link) => {
              const url = `${origin}/share/${link.token}`;
              return (
                <li
                  key={link.id}
                  className="flex items-center gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-950"
                >
                  <StatusBadge status={link.status} />
                  <div className="min-w-0 flex-1">
                    <Link
                      href={`/share/${link.token}`}
                      className="block truncate font-mono text-xs underline-offset-2 hover:underline"
                    >
                      {url}
                    </Link>
                    <div className="mt-0.5 text-xs text-neutral-500">
                      {link.badgeCount} badge
                      {link.badgeCount === 1 ? "" : "s"} · {link.viewCount} view
                      {link.viewCount === 1 ? "" : "s"} · expires{" "}
                      {link.expiresAt.toLocaleDateString()}
                      {link.requiresAccount ? " · account-gated" : ""}
                    </div>
                  </div>
                  {link.status === "active" ? (
                    <ShareLinkRevokeButton shareLinkId={link.id} />
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

function StatusBadge({ status }: { status: "active" | "expired" | "revoked" }) {
  const styles =
    status === "active"
      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
      : status === "expired"
        ? "bg-neutral-100 text-neutral-500 dark:bg-neutral-900 dark:text-neutral-400"
        : "bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${styles}`}
    >
      {status}
    </span>
  );
}
