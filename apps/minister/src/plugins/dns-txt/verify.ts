import type { IssuedBadge } from "@minister/plugin-sdk";

// Pure, network-free helpers for the DNS-TXT domain-control challenge flow, kept
// out of index.ts so the hostname validation, challenge derivation, and TXT
// match are unit-testable without touching a resolver.

// The dedicated challenge host we ask the user to publish the TXT record under.
// A dedicated `_minister-challenge` label (like ACME's `_acme-challenge`) is
// cleaner than the apex: it never collides with the domain's existing apex TXT
// records (SPF, DMARC, other verifications) and the user can delete it freely
// once the badge is issued.
export const CHALLENGE_SUBDOMAIN = "_minister-challenge";

// The TXT record value is `minister-verification=<token>`. A `=`-delimited
// key/value keeps it self-describing among a domain's other TXT records.
export const CHALLENGE_PREFIX = "minister-verification=";

export function challengeHost(domain: string): string {
  return `${CHALLENGE_SUBDOMAIN}.${domain}`;
}

export function challengeValue(token: string): string {
  return `${CHALLENGE_PREFIX}${token}`;
}

// One DNS label: 1-63 chars, ASCII letters/digits/hyphen, no leading/trailing
// hyphen. Anchored; the caller splits on "." and tests each label.
const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/u;

// Strictly validate and canonicalize a user-entered domain into a public,
// resolvable hostname, or return null. This is deliberately far stricter than
// the badge type's storage regex — it is the guard against feeding junk (URLs,
// IPs, localhost, internal names) to the resolver.
//
// Accepts: a bare, lowercase-able hostname of ≥ 2 labels whose final label
// (the effective TLD) is alphabetic (≥ 2 chars), e.g. `example.com`,
// `sub.example.co.uk`. An optional single trailing dot (FQDN form) is allowed
// and stripped.
//
// Rejects: URLs (any scheme/path/query/userinfo/port character), IPv4 (numeric
// final label), IPv6 (colon), single-label names (`localhost`), empty labels
// (`a..b`, leading/trailing dot beyond the one FQDN dot), labels that start or
// end with a hyphen, over-length names, and underscores.
export function normalizeDomain(input: string): string | null {
  if (typeof input !== "string") return null;
  let host = input.trim().toLowerCase();
  if (host.length === 0) return null;

  // Any of these characters means it is not a bare hostname: `/` `?` `#` a path
  // or query, `@` userinfo, `:` a scheme separator / port / IPv6, whitespace.
  if (/[/:@?#\s]/u.test(host)) return null;

  // Allow (and drop) a single trailing dot — the FQDN form. A second trailing
  // dot leaves an empty final label, which the per-label check below rejects.
  if (host.endsWith(".")) host = host.slice(0, -1);

  if (host.length === 0 || host.length > 253) return null;

  const labels = host.split(".");
  // Require a public, multi-label domain: rejects `localhost` and other
  // single-label internal names outright.
  if (labels.length < 2) return null;

  for (const label of labels) {
    if (!LABEL_RE.test(label)) return null;
  }

  // The effective TLD must be alphabetic. This is what rejects a dotted IPv4
  // address (its final octet is numeric) and any all-numeric final label.
  const tld = labels.at(-1);
  if (!tld || !/^[a-z]{2,}$/u.test(tld)) return null;

  return host;
}

// Does any returned TXT record equal our exact challenge value? resolveTxt hands
// back a two-dimensional array: one entry per record, each an array of the
// character-string chunks that make up that record (a >255-char record is split
// on the wire), which must be concatenated before comparison. We trim the joined
// record so trailing whitespace some DNS UIs append does not defeat the match.
export function txtRecordsContainChallenge(records: string[][], expectedValue: string): boolean {
  if (!expectedValue) return false;
  return records.some((chunks) => chunks.join("").trim() === expectedValue);
}

// Build the `domain-control` badge. The domain is BOTH the Sybil anchor and the
// disclosed claim (there is nothing more private to reveal — the whole point is
// attesting the domain), so it legitimately appears in the claims: opt out of
// the runtime's anchor-leak guard via `revealsAnchor`, exactly as the Hacker
// News and email-exact badges do. The runtime still nullifies the anchor for
// one-credential-one-account dedup.
export function buildDomainControlBadge(domain: string): IssuedBadge {
  return {
    type: "domain-control",
    attributes: { domain },
    claims: { domain },
    sybilAnchor: domain,
    revealsAnchor: true,
  };
}
