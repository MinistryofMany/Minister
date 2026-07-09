// Helpers for the internal avatar SERVE-route URL that an uploaded photo is
// stored under (User.avatarUrl). Pure string/URL work with no server-only
// imports, so BOTH the "use server" upload action and the client-side profile
// form import it — the form uses `isUploadedAvatarUrl` to recognize that the
// stored avatarUrl points at an upload (and therefore preselect the "Upload a
// photo" option) rather than a Gravatar or a free-text link.
//
// The stored value is ABSOLUTE and origin-qualified (e.g.
// `https://ministry.id/api/avatars/<publicId>?v=<updatedAt ms>`) so it flows
// through the OIDC `picture` claim exactly like the gravatar/url cases and is
// reachable by a relying party. Crucially the path carries an OPAQUE, random
// `publicId` — never the internal userId. Serving under the userId would leak
// Minister's global account id to any RP granted the avatar claim (it could then
// dereference `/u/<userId>` and correlate the user across RPs), defeating the
// pairwise `sub`. The `?v=` is a cache-buster: it changes when the user replaces
// their photo, so a cached copy at an RP or a viewer never goes stale.

// The path prefix every uploaded-avatar serve URL sits under. A single constant
// so the builder and the recognizer can never drift.
export const AVATAR_SERVE_PREFIX = "/api/avatars/";

// The path (no origin, no query) an uploaded avatar is served from, keyed on the
// OPAQUE publicId (not the userId).
export function avatarServePath(publicId: string): string {
  return `${AVATAR_SERVE_PREFIX}${encodeURIComponent(publicId)}`;
}

// Build the absolute, cache-busted serve URL to persist as User.avatarUrl.
// `origin` is a server-controlled canonical origin (Minister's AUTH_URL), never
// a client-supplied Host header, so the persisted-then-disclosed URL can't be
// pointed at an attacker host. `version` is the avatar's updatedAt in ms.
export function buildUploadedAvatarUrl(origin: string, publicId: string, version: number): string {
  const base = origin.replace(/\/$/, "");
  return `${base}${avatarServePath(publicId)}?v=${version}`;
}

// True when `avatarUrl` points at the internal avatar serve route — the signal
// that the user's current avatar is an upload (as opposed to a Gravatar, a
// free-text https link, or the null/deterministic default). Parsed as a URL so
// the query string (`?v=`) and any host are handled correctly; a value that
// isn't a parseable absolute URL is simply "not an upload". The check does NOT
// need the userId: the opaque publicId is not derivable from it, and the
// prefix + a non-empty segment is enough to classify the URL.
export function isUploadedAvatarUrl(avatarUrl: string | null): boolean {
  if (!avatarUrl) return false;
  let parsed: URL;
  try {
    parsed = new URL(avatarUrl);
  } catch {
    return false;
  }
  return (
    parsed.pathname.startsWith(AVATAR_SERVE_PREFIX) &&
    parsed.pathname.length > AVATAR_SERVE_PREFIX.length
  );
}
