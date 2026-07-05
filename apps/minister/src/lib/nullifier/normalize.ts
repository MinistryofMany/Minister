// Email Sybil-anchor normalization (crypto-core Phase 5 / build-plan §2.3).
//
// The Sybil anchor for the `email-domain` and `email-exact` badges is the
// NORMALIZED FULL address. Normalization is deliberately MINIMAL and
// PROVIDER-EXPLICIT: it collapses two addresses that deliver to the SAME inbox
// onto one anchor, WITHOUT over-collapsing addresses at providers whose plus/dot
// semantics we do not know for certain.
//
// The table:
//   - always trim + lowercase (SMTP hosts are case-insensitive, and every
//     mainstream provider treats the local-part case-insensitively too);
//   - fold googlemail.com -> gmail.com (the same Google mailbox);
//   - gmail.com: strip a "+tag" suffix AND remove ALL local-part dots (Google
//     ignores both — `j.o.hn+news@gmail.com` and `john@gmail.com` are one inbox);
//   - outlook.com / hotmail.com / live.com: strip a "+tag" suffix only
//     (Microsoft ignores the tag but HONORS dots);
//   - EVERY other domain: lowercase ONLY. No generic plus-stripping: a "+"
//     mailbox at an unknown provider may be a genuinely distinct address, so
//     collapsing it would wrongly deny a real owner with `taken`. Preserving it
//     is fail-open toward NOT over-matching, which is the safe direction for a
//     dedup anchor.
//
// VERSIONING (append-only): this table versions the anchor. Changing a rule
// (adding a provider, altering a fold) RE-KEYS every affected anchor — an
// address verified before the change and the same address verified after would
// no longer collide, silently reopening a Sybil path OR stranding a holder.
// Any behavior change MUST bump ANCHOR_NORMALIZATION_VERSION and be treated as a
// re-verification event for the affected addresses. Additions here are therefore
// append-only and deliberate.
export const ANCHOR_NORMALIZATION_VERSION = 1;

// Providers that ignore a "+tag" suffix but HONOR local-part dots.
const PLUS_TAG_IGNORING_PROVIDERS: ReadonlySet<string> = new Set([
  "outlook.com",
  "hotmail.com",
  "live.com",
]);

// Drop everything from the first "+" onward (a sub-address / detail tag).
function stripPlusTag(localPart: string): string {
  const plus = localPart.indexOf("+");
  return plus < 0 ? localPart : localPart.slice(0, plus);
}

// Normalize a submitted email into its Sybil anchor (the normalized full
// address, `local@domain`). Throws on an address with no usable local@domain
// split — callers validate with Zod's `.email()` first, so a throw here signals
// a programmer error, not raw user input.
export function normalizeEmailAnchor(email: string): string {
  const trimmed = email.trim().toLowerCase();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1) {
    throw new Error("normalizeEmailAnchor: address has no local@domain split");
  }
  let local = trimmed.slice(0, at);
  let domain = trimmed.slice(at + 1);

  // Google: googlemail.com is an alias of gmail.com (identical mailbox).
  if (domain === "googlemail.com") domain = "gmail.com";

  if (domain === "gmail.com") {
    // Google ignores both a "+tag" suffix and local-part dots.
    local = stripPlusTag(local).replace(/\./gu, "");
  } else if (PLUS_TAG_IGNORING_PROVIDERS.has(domain)) {
    // Microsoft ignores the "+tag" suffix but honors dots.
    local = stripPlusTag(local);
  }
  // Every other domain: lowercase only (already applied above).

  return `${local}@${domain}`;
}
