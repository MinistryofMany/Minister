// Helpers for the internal avatar SERVE-route URL that an uploaded photo is
// stored under (User.avatarUrl). Pure string/URL work with no server-only
// imports, so BOTH the "use server" upload action and the client-side profile
// form import it — the form uses `isUploadedAvatarUrl` to recognize that the
// stored avatarUrl points at an upload (and therefore preselect the "Upload a
// photo" option) rather than a Gravatar or a free-text link.
//
// The stored value is ABSOLUTE and origin-qualified (e.g.
// `https://ministry.id/api/users/<id>/avatar?v=<updatedAt ms>`) so it flows
// through the OIDC `picture` claim exactly like the gravatar/url cases and is
// reachable by a relying party. The `?v=` is a cache-buster: it changes when the
// user replaces their photo, so a cached copy at an RP or a viewer never goes
// stale.

// The path (no origin, no query) an uploaded avatar is served from for a user.
export function avatarServePath(userId: string): string {
  return `/api/users/${encodeURIComponent(userId)}/avatar`;
}

// Build the absolute, cache-busted serve URL to persist as User.avatarUrl.
// `origin` is a server-controlled canonical origin (Minister's AUTH_URL), never
// a client-supplied Host header, so the persisted-then-disclosed URL can't be
// pointed at an attacker host. `version` is the avatar's updatedAt in ms.
export function buildUploadedAvatarUrl(origin: string, userId: string, version: number): string {
  const base = origin.replace(/\/$/, "");
  return `${base}${avatarServePath(userId)}?v=${version}`;
}

// True when `avatarUrl` points at THIS user's internal avatar serve route — the
// signal that the user's current avatar is an upload (as opposed to a Gravatar,
// a free-text https link, or the null/deterministic default). Parsed as a URL so
// the query string (`?v=`) and any host are handled correctly; a value that
// isn't a parseable absolute URL is simply "not an upload".
export function isUploadedAvatarUrl(avatarUrl: string | null, userId: string): boolean {
  if (!avatarUrl) return false;
  let parsed: URL;
  try {
    parsed = new URL(avatarUrl);
  } catch {
    return false;
  }
  return parsed.pathname === avatarServePath(userId);
}
