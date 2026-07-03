// Public / freemail email-host denylist.
//
// When a user verifies an email at sign-in we auto-issue an `email-domain`
// badge (see src/server/auto-issue-email-domain.ts) — but only for domains
// that plausibly attest something (a workplace, a school, a personal domain).
// A badge saying "controls an address at gmail.com" is worthless: anyone can
// get one. So we skip issuance for the well-known consumer mailbox providers
// below.
//
// EASY TO EXTEND: add a lowercase host to this set. Matching is exact on the
// full host (see isFreemailDomain), so add each variant a provider uses.
export const FREEMAIL_DOMAINS: ReadonlySet<string> = new Set([
  // Google
  "gmail.com",
  "googlemail.com",
  // Apple
  "icloud.com",
  "me.com",
  "mac.com",
  // Microsoft
  "outlook.com",
  "hotmail.com",
  "live.com",
  "msn.com",
  // Yahoo
  "yahoo.com",
  "ymail.com",
  "yahoo.co.uk",
  "yahoo.ca",
  "yahoo.fr",
  "yahoo.de",
  // Proton
  "proton.me",
  "protonmail.com",
  "pm.me",
  // AOL
  "aol.com",
  // GMX
  "gmx.com",
  "gmx.net",
  "gmx.de",
  "gmx.at",
  // German / European consumer providers
  "web.de",
  "seznam.cz",
  "libero.it",
  "laposte.net",
  // French consumer providers
  "orange.fr",
  "free.fr",
  // Chinese consumer providers
  "qq.com",
  "163.com",
  "126.com",
  "sina.com",
  // Russian consumer providers
  "mail.ru",
  "bk.ru",
  "inbox.ru",
  // Others
  "mail.com",
  "zoho.com",
  "yandex.com",
  "fastmail.com",
  // Tutanota / Tuta
  "tutanota.com",
  "tuta.com",
]);

// True when `domain` is a public/freemail host we must NOT mint an
// email-domain badge for. Caller supplies a host; we lowercase defensively.
export function isFreemailDomain(domain: string): boolean {
  return FREEMAIL_DOMAINS.has(domain.toLowerCase());
}

// Parse the host from an email address, lowercased. Returns null when the
// address has no usable domain part. Kept here so the sign-in path and the
// badge path derive the domain identically.
export function domainFromEmail(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at < 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}
