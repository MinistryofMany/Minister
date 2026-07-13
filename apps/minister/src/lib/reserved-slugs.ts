// Reserved group slugs blocked from FREE (unverified) founding, to stop obvious
// impersonation/squatting (docs/groups-design.md "Namespace and verification").
// Two buckets: platform/routing words (a group slug could otherwise collide with
// or impersonate a first-party path once a public /groups/<slug> directory ships
// in v2), and high-value impersonation targets. Configurable; a future
// verified/paid founding path can bypass this. The input is already normalized
// to [a-z0-9-] and lowercased before it reaches here.

export const RESERVED_GROUP_SLUGS: ReadonlySet<string> = new Set<string>([
  // platform / routing / first-party paths
  "admin",
  "api",
  "app",
  "apps",
  "auth",
  "oidc",
  "login",
  "logout",
  "signin",
  "signout",
  "settings",
  "profile",
  "account",
  "u",
  "user",
  "users",
  "badge",
  "badges",
  "group",
  "groups",
  "share",
  "shares",
  "new",
  "well-known",
  "static",
  "assets",
  "public",
  "help",
  "support",
  "about",
  "terms",
  "privacy",
  "security",
  "status",
  "docs",
  "blog",
  "root",
  "system",
  "null",
  "undefined",
  // high-value impersonation targets
  "minister",
  "ministry",
  "official",
  "verified",
  "ethereum",
  "bitcoin",
  "openai",
  "google",
  "apple",
  "microsoft",
  "amazon",
  "meta",
  "facebook",
  "twitter",
  "discord",
  "github",
]);

export function isReservedGroupSlug(slug: string): boolean {
  return RESERVED_GROUP_SLUGS.has(slug.toLowerCase());
}
