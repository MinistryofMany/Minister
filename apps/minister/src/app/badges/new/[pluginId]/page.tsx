import Link from "next/link";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { ShieldAlert } from "lucide-react";

import { WizardClient } from "@/components/wizard-client";
import { mailTransportConfigured } from "@/lib/mailer";
import { getCurrentSession } from "@/lib/session";
import { getPlugin, isPluginConfigured } from "@/plugins/registry";
import { AnonBackupPendingError, loadWizard, startWizard } from "@/server/wizard";

interface PageProps {
  params: Promise<{ pluginId: string }>;
  searchParams: Promise<{ wsid?: string }>;
}

export default async function PluginWizardPage({ params, searchParams }: PageProps) {
  const { pluginId } = await params;
  const { wsid } = await searchParams;

  const session = await getCurrentSession();
  if (!session?.user) redirect("/");
  const userId = session.user.id;

  const plugin = getPlugin(pluginId);
  if (!plugin) notFound();

  // Defense in depth against a direct URL to an unconfigured plugin: the menu
  // already hides it, but hitting /badges/new/github with no OAuth creds would
  // otherwise reach startWizard and throw an unhandled "Application error".
  if (!isPluginConfigured(plugin)) notFound();

  // First visit: start a fresh wizard session, redirect with wsid so a
  // page refresh keeps the same session.
  if (!wsid) {
    const h = await headers();
    const proto = h.get("x-forwarded-proto") ?? "http";
    const host = h.get("host") ?? "localhost:3000";
    const origin = `${proto}://${host}`;
    let sessionId: string;
    try {
      ({ sessionId } = await startWizard(pluginId, userId, origin));
    } catch (err) {
      // Badge gate (spec §6.4): the user's Private Identity backup isn't done,
      // so no badge can be started. Render the block with a link to finish it
      // rather than crashing with an unhandled "Application error". redirect()
      // stays OUTSIDE this try so its control-flow throw isn't swallowed.
      if (err instanceof AnonBackupPendingError) return <BackupGateNotice href={err.href} />;
      throw err;
    }
    redirect(`/badges/new/${pluginId}?wsid=${sessionId}`);
  }

  const state = await loadWizard(wsid, userId);
  if (!state) {
    // Session expired / not found. Start fresh.
    redirect(`/badges/new/${pluginId}`);
  }

  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{plugin.manifest.name}</h1>
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          {plugin.manifest.description}
        </p>
      </header>

      <WizardClient
        sessionId={wsid}
        initialState={state}
        mailConfigured={mailTransportConfigured()}
      />
    </div>
  );
}

// Shown when the badge gate (spec §6.4) refuses to start a wizard because the
// user's Private Identity enrollment is PENDING_BACKUP.
function BackupGateNotice({ href }: { href: string }) {
  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <div
        role="region"
        aria-label="Finish backing up your Private Identity"
        className="flex flex-col gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-amber-900 dark:border-amber-900/50 dark:bg-amber-900/20 dark:text-amber-200"
      >
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
          <div className="space-y-0.5">
            <p className="text-sm font-semibold">Finish backing up your Private Identity first</p>
            <p className="text-sm text-amber-800 dark:text-amber-300/90">
              You can&apos;t add badges until you back up your Private Identity key. It only takes a
              moment, and it protects your anonymous identity in every connected app.
            </p>
          </div>
        </div>
        <Link
          href={href}
          className="inline-flex w-fit items-center justify-center rounded-md bg-amber-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600"
        >
          Finish backup
        </Link>
      </div>
    </div>
  );
}
