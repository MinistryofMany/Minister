import { audit } from "@/lib/audit";
import { domainFromEmail, isFreemailDomain } from "@/lib/freemail-domains";
import { prisma } from "@/lib/prisma";
import { issueBadge } from "@/server/issue-badge";

// Auto-issue an `email-domain` badge when a user verifies an email at sign-in
// (magic link or OTP). The email is verified as a side effect of signing in,
// so this is the natural place to mint the badge the email-domain plugin
// would otherwise require a separate wizard round-trip for.
//
// NO-PII: only the domain is ever derived, validated, or stored — never the
// full address. The VC shape is identical to the email-domain plugin's
// because both go through issueBadge (pluginId "email-domain").
//
// Idempotent: skips if the user already holds an email-domain badge for that
// exact domain. Freemail hosts (gmail, icloud, …) are skipped — a badge for a
// public mailbox provider attests nothing.
//
// Fail-open: this runs off the sign-in event; a failure here must never block
// login. Callers should already be in a try/catch, but we also swallow-and-
// audit internally so a transient DB hiccup during issuance is non-fatal.
const PLUGIN_ID = "email-domain";
const BADGE_TYPE = "email-domain";

export async function autoIssueEmailDomainBadge(userId: string, email: string): Promise<void> {
  const domain = domainFromEmail(email);
  if (!domain) return;

  if (isFreemailDomain(domain)) {
    await audit(userId, "badge.email_domain.auto_issue_skipped", { reason: "freemail" });
    return;
  }

  try {
    // Cheap idempotency pre-check on the denormalized attribute so the common
    // already-issued path skips VC signing. The AUTHORITATIVE guard against a
    // concurrent double-mint is the unique Badge.dedupeKey below: two
    // near-simultaneous sign-ins can both pass this read, so the DB constraint
    // is what actually prevents the duplicate.
    const existing = await prisma.badge.findFirst({
      where: { userId, type: BADGE_TYPE, attributes: { path: ["domain"], equals: domain } },
      select: { id: true },
    });
    if (existing) return;

    const badgeId = await issueBadge({
      userId,
      pluginId: PLUGIN_ID,
      badge: { type: BADGE_TYPE, attributes: { domain }, claims: { domain } },
      dedupeKey: `${BADGE_TYPE}:${userId}:${domain}`,
    });
    await audit(userId, "badge.email_domain.auto_issued", { domain, badgeId });
  } catch (err) {
    // A unique-constraint violation means a concurrent sign-in already minted
    // this exact badge — benign, not a failure: the race lost cleanly.
    if (typeof err === "object" && err !== null && "code" in err && err.code === "P2002") {
      await audit(userId, "badge.email_domain.auto_issue_skipped", { reason: "duplicate" });
      return;
    }
    // Never let a genuine badge-issuance failure surface as a failed sign-in.
    await audit(userId, "badge.email_domain.auto_issue_failed", {
      domain,
      error: err instanceof Error ? err.message : "unknown",
    });
  }
}
