import { badgeScopes } from "@/lib/oidc-config";

// Validation helpers for the admin OIDC-client management UI. Pure
// functions — the Prisma writes live in server/admin-actions.ts.

export const BASE_SCOPES = ["openid", "profile"] as const;

export function allOidcScopes(): string[] {
  return [...BASE_SCOPES, ...badgeScopes()];
}

export type RedirectUrisResult =
  | { ok: true; uris: string[] }
  | { ok: false; error: string };

// One URI per line. Exact-match semantics downstream (RFC 6749
// §3.1.2.2), so we normalize nothing beyond trimming whitespace —
// what the admin types is what the RP must send.
export function parseRedirectUris(text: string): RedirectUrisResult {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length === 0) {
    return { ok: false, error: "At least one redirect URI is required" };
  }

  for (const line of lines) {
    let url: URL;
    try {
      url = new URL(line);
    } catch {
      return { ok: false, error: `Not an absolute URL: ${line}` };
    }
    if (url.hash) {
      return {
        ok: false,
        error: `Redirect URIs must not contain a fragment: ${line}`,
      };
    }
    if (url.protocol === "https:") continue;
    if (
      url.protocol === "http:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1")
    ) {
      // Plain http is acceptable only for local development loopback.
      continue;
    }
    return {
      ok: false,
      error: `Must be https (or http on localhost): ${line}`,
    };
  }

  const unique = [...new Set(lines)];
  return { ok: true, uris: unique };
}

export type ScopesResult =
  | { ok: true; scopes: string[] }
  | { ok: false; error: string };

// openid is mandatory (the flow is useless without it); everything
// else must come from the known set: profile + badge:<registered type>.
export function validateClientScopes(scopes: string[]): ScopesResult {
  const known = new Set(allOidcScopes());
  const unique = [...new Set(scopes)];

  const unknown = unique.filter((s) => !known.has(s));
  if (unknown.length > 0) {
    return { ok: false, error: `Unknown scope: ${unknown.join(", ")}` };
  }
  if (!unique.includes("openid")) {
    return { ok: false, error: "The openid scope is required" };
  }
  return { ok: true, scopes: unique };
}
