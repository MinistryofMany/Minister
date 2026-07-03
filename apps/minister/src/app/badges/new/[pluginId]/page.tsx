import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

import { WizardClient } from "@/components/wizard-client";
import { getCurrentSession } from "@/lib/session";
import { getPlugin, isPluginConfigured } from "@/plugins/registry";
import { loadWizard, startWizard } from "@/server/wizard";

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
    const { sessionId } = await startWizard(pluginId, userId, origin);
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

      <WizardClient sessionId={wsid} initialState={state} />
    </div>
  );
}
