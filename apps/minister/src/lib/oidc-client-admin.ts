import { ANON_APP_ID_PATTERN } from "@minister/shared";

import { badgeScopes } from "@/lib/oidc-config";

// Validation helpers for the admin OIDC-client management UI. Pure
// functions — the Prisma writes live in server/admin-actions.ts.

export const BASE_SCOPES = ["openid", "profile"] as const;

// Frozen clientId charset. Minister-generated ids are `mc_` + base64url
// (`generateClientId`), so a colon — or any delimiter — can never occur. The
// pairwise-sub / jti / share-link derivations use a legacy colon-joined input
// encoding (`${userId}:${clientId}`, `jti:${badgeId}:${clientId}`, etc.); a
// delimiter inside a clientId would let two distinct (id, clientId) tuples
// collide into one HMAC input. Admin creation always uses generateClientId, so
// the only path an operator can smuggle a delimiter through is
// `scripts/seed-client.ts --client-id`; guard both against it. The value is
// frozen forever (Signet's /prf/pairwise oracle relies on the encoding), so a
// re-encode is off the table — a charset guard is the fix (build plan §2.1).
const CLIENT_ID_RE = /^mc_[A-Za-z0-9_-]+$/;

// The docker-compose demo client (`DEMO_CLIENT_ID`, default `demo_client`)
// predates the `mc_` convention and the guard. It contains no delimiter, so it
// is safe; allow its exact id as a legacy exception rather than break the
// existing bootstrap.
const LEGACY_CLIENT_IDS = new Set<string>(["demo_client"]);

export function isValidClientId(clientId: string): boolean {
  return LEGACY_CLIENT_IDS.has(clientId) || CLIENT_ID_RE.test(clientId);
}

export type ClientIdResult = { ok: true; clientId: string } | { ok: false; error: string };

export function validateClientId(clientId: string): ClientIdResult {
  if (!isValidClientId(clientId)) {
    return {
      ok: false,
      error: `Invalid client_id "${clientId}": must match ^mc_[A-Za-z0-9_-]+$`,
    };
  }
  return { ok: true, clientId };
}

export function allOidcScopes(): string[] {
  // `sybil-score` is a non-badge disclosure scope (coarse anti-sybil bucket),
  // assignable to a client exactly like `profile`. Listed here so the admin
  // OIDC-client editor can grant it and validateClientScopes accepts it.
  return [...BASE_SCOPES, "sybil-score", ...badgeScopes()];
}

export type RedirectUrisResult = { ok: true; uris: string[] } | { ok: false; error: string };

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

export type AnonAppIdResult = { ok: true; anonAppId: string | null } | { ok: false; error: string };

// Validate the anonymous-identity namespace slug (anon-identity master spec
// §8.1): a lowercase `^[a-z0-9-]{3,32}$` slug, or empty/absent → null (the
// client is not anon-enabled). Immutability (a set value never changing) is
// enforced by the admin ACTIONS, not here — this only checks shape. Uniqueness
// is enforced by the DB unique constraint plus a pre-check in the action.
export function validateAnonAppId(value: string | undefined | null): AnonAppIdResult {
  const trimmed = (value ?? "").trim();
  if (trimmed.length === 0) return { ok: true, anonAppId: null };
  if (!ANON_APP_ID_PATTERN.test(trimmed)) {
    return {
      ok: false,
      error: `Invalid anon app id "${trimmed}": must match ^[a-z0-9-]{3,32}$`,
    };
  }
  return { ok: true, anonAppId: trimmed };
}

// Decide what an admin edit may do to a client's anonAppId, enforcing
// immutability-once-set (anon-identity master spec §8.1, invariant I7). A set
// value can NEVER change (rotating it silently forks every user's anonymous
// identity in that app); only a null value may be first-set (null → slug). The
// result's `set` is the value to write when it is a first-set, or null to leave
// the field untouched (a blank submit can never clear a set value, and a repeat
// of the current value is a no-op). Uniqueness of a first-set value is the
// caller's job (DB unique constraint + pre-check).
export type AnonAppIdUpdate = { ok: true; set: string | null } | { ok: false; error: string };

export function resolveAnonAppIdUpdate(
  existing: string | null,
  submitted: string | null,
): AnonAppIdUpdate {
  if (existing !== null) {
    if (submitted !== null && submitted !== existing) {
      return { ok: false, error: "anon app id is immutable once set and cannot be changed" };
    }
    return { ok: true, set: null }; // untouched
  }
  return { ok: true, set: submitted }; // null → first-set (or still null)
}

export type ScopesResult = { ok: true; scopes: string[] } | { ok: false; error: string };

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
