import type { Plugin } from "@minister/plugin-sdk";

import { dnsTxtPlugin } from "./dns-txt";
import { emailDomainPlugin } from "./email-domain";
import { emailExactPlugin } from "./email-exact";
import { githubPlugin } from "./github";
import { googlePlugin } from "./google";
import { hackernewsPlugin } from "./hackernews";
import { inviteCodePlugin } from "./invite-code";
import { redditPlugin } from "./reddit";
import { steamPlugin } from "./steam";
import { tlsnAttestationPlugin } from "./tlsn-attestation";

// In-process registry — CLAUDE.md explicitly forbids dynamic loading.
// Add a plugin by importing it and appending here.
const PLUGINS: Plugin[] = [
  emailDomainPlugin,
  emailExactPlugin,
  dnsTxtPlugin,
  githubPlugin,
  googlePlugin,
  redditPlugin,
  steamPlugin,
  hackernewsPlugin,
  inviteCodePlugin,
  tlsnAttestationPlugin,
];

const byId = new Map(PLUGINS.map((p) => [p.manifest.id, p]));

// A plugin is available unless it declares an `isConfigured` probe that
// returns false. Plugins that depend on deployment-time config (e.g. the
// GitHub OAuth client credentials) use this to opt out cleanly when that
// config is absent — the menu hides them and the wizard route refuses to
// start, instead of routing the user into a wizard that throws.
export function isPluginConfigured(plugin: Plugin): boolean {
  return plugin.isConfigured?.() ?? true;
}

export function listPlugins(): Plugin[] {
  return [...PLUGINS];
}

// The add-a-badge menu only offers plugins that are actually usable.
export function listAvailablePlugins(): Plugin[] {
  return PLUGINS.filter(isPluginConfigured);
}

export function getPlugin(id: string): Plugin | undefined {
  return byId.get(id);
}
