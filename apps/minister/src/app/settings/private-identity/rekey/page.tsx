import { notFound, redirect } from "next/navigation";

import { loadPerAppIds } from "@/app/settings/per-app-ids";
import { env } from "@/env";
import { getCurrentSession } from "@/lib/session";

import { RekeyClient } from "./rekey-client";

// "I lost my key" re-key flow (identity plan, O-6). The account never depended
// on the seed, so the user is signed in normally; the gates and the destructive
// mint live server-side in rekeyAnonSeed. The checklist below is resolved from
// the durable OidcGrants (loadPerAppIds) — every app the user must sign back
// into to finish re-keying there.
export default async function RekeyPage() {
  if (!env.ANON_IDENTITY_ENABLED) notFound();

  const session = await getCurrentSession();
  if (!session?.user?.id) redirect("/");

  const apps = await loadPerAppIds(session.user.id);

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Re-key your Private Identity</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Lost your Private Identity? There&apos;s no recovering it — but you can replace it. Your
          account, badges, and app memberships all survive; only your anonymous identity is new.
        </p>
      </header>

      <RekeyClient userId={session.user.id} apps={apps.map((a) => ({ appName: a.appName }))} />
    </div>
  );
}
