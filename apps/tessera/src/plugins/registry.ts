import type { Plugin } from "@tessera/plugin-sdk";

import { emailDomainPlugin } from "./email-domain";

// In-process registry — CLAUDE.md explicitly forbids dynamic loading.
// Add a plugin by importing it and appending here.
const PLUGINS: Plugin[] = [emailDomainPlugin];

const byId = new Map(PLUGINS.map((p) => [p.manifest.id, p]));

export function listPlugins(): Plugin[] {
  return [...PLUGINS];
}

export function getPlugin(id: string): Plugin | undefined {
  return byId.get(id);
}
