import type { Plugin } from "@tessera/plugin-sdk";

import { emailDomainPlugin } from "./email-domain";
import { inviteCodePlugin } from "./invite-code";
import { tlsnAttestationPlugin } from "./tlsn-attestation";

// In-process registry — CLAUDE.md explicitly forbids dynamic loading.
// Add a plugin by importing it and appending here.
//
// Plugins whose required env is missing are still registered (the
// plugin list page shows them) but startWizard throws — the user sees
// "plugin is not configured" rather than the plugin silently
// vanishing.
const PLUGINS: Plugin[] = [
  emailDomainPlugin,
  inviteCodePlugin,
  tlsnAttestationPlugin,
];

const byId = new Map(PLUGINS.map((p) => [p.manifest.id, p]));

export function listPlugins(): Plugin[] {
  return [...PLUGINS];
}

export function getPlugin(id: string): Plugin | undefined {
  return byId.get(id);
}
