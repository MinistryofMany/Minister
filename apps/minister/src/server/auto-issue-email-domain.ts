import { audit } from "@/lib/audit";
import { domainFromEmail, isFreemailDomain } from "@/lib/freemail-domains";
import { ensureDedupHandle, nullifierService, runPostCommit } from "@/lib/nullifier";
import { normalizeEmailAnchor } from "@/lib/nullifier/normalize";
import { prisma } from "@/lib/prisma";
import { issueBadge } from "@/server/issue-badge";

// Auto-issue an `email-domain` badge when a user verifies an email at sign-in
// (magic link or OTP). The email is verified as a side effect of signing in,
// so this is the natural place to mint the badge the email-domain plugin
// would otherwise require a separate wizard round-trip for.
//
// NO-PII: only the domain is ever derived, validated, or stored on the badge —
// never the full address. The raw address is used ONLY to compute the Sybil
// anchor (below) and is then DISCARDED, exactly as the wizard runtime does. The
// VC shape is identical to the email-domain plugin's (both go through issueBadge
// with pluginId "email-domain").
//
// SYBIL DEDUP (crypto-core Phase 5): this path shares the email-domain
// credential's ONE-account dedup namespace with the wizard. Inbox control IS
// proven here — a magic-link/OTP sign-in is exactly the capture-at-verify event
// §2.3 requires — so we normalize the login address into the Sybil anchor,
// register it in the ledger, and persist the opaque nullifierRef. Without this
// the auto-issue path minted nullifier-less email-domain badges, letting one
// person hold the same-mailbox credential on two accounts (auto-issued on one,
// wizard-issued on the other): a clean 2x Sybil on the exact type Phase 5 gates.
//
// `taken` = a DIFFERENT account already holds this mailbox's credential → skip
// issuance (fail-open: the login still succeeds, just no badge). This is the
// same refusal the wizard surfaces as an error, here silent because auto-issue
// is a best-effort side effect.
//
// Idempotent: skips if the user already holds an email-domain badge for that
// exact domain. Freemail hosts (gmail, icloud, …) are skipped — a badge for a
// public mailbox provider attests nothing (and never registers an anchor).
//
// Fail-open: this runs off the sign-in event; a failure here must never block
// login. Callers should already be in a try/catch, but we also swallow-and-
// audit internally so a transient DB hiccup during issuance is non-fatal.
//
// TOCTOU note: unlike the wizard runtime this path does NOT wrap the mint in
// serializeMintWindow + a mint-side re-validation probe. The dangerous
// delete-vs-reissue window is closed on the RELEASE side (the interim backend's
// release is atomically sibling-guarded — it cannot free an entry a committed
// Badge references), and a fresh `registered` entry is unreachable by any
// release until this badge's INSERT commits (nobody else holds the ref). The
// residual pre-INSERT window is a strictly-smaller re-open of the window the
// wizard closes; acceptable for a best-effort login side effect at the interim
// scale, and unified when this path folds into the shared issuance core
// (Phase 3 backend split — see Minister/TODO.md).
const PLUGIN_ID = "email-domain";
const BADGE_TYPE = "email-domain";

export async function autoIssueEmailDomainBadge(userId: string, email: string): Promise<void> {
  const domain = domainFromEmail(email);
  if (!domain) return;

  if (isFreemailDomain(domain)) {
    await audit(userId, "badge.email_domain.auto_issue_skipped", { reason: "freemail" });
    return;
  }

  // Compute the Sybil anchor from the verified login address, then DISCARD the
  // raw address (only `anchor` and `domain` survive past this line; `anchor` is
  // handed to the ledger and never persisted in the clear).
  let anchor: string;
  try {
    anchor = normalizeEmailAnchor(email);
  } catch (err) {
    // A malformed/degenerate address (non-ASCII, empty local part) — the login
    // provider should never hand us one, but never fail sign-in over it.
    await audit(userId, "badge.email_domain.auto_issue_failed", {
      domain,
      error: err instanceof Error ? err.message : "unknown",
    });
    return;
  }

  try {
    // Cheap idempotency pre-check on the denormalized attribute so the common
    // already-issued path skips both anchor registration AND VC signing. The
    // AUTHORITATIVE guard against a concurrent double-mint is the unique
    // Badge.dedupeKey below.
    const existing = await prisma.badge.findFirst({
      where: { userId, type: BADGE_TYPE, attributes: { path: ["domain"], equals: domain } },
      select: { id: true },
    });
    if (existing) return;

    // Register the anchor BEFORE minting (one credential, one account). Runs
    // outside any transaction per the nullifier network-I/O contract.
    const ownerHandle = await ensureDedupHandle(userId);
    const reg = await nullifierService.registerDedup({
      anchor,
      badgeType: BADGE_TYPE,
      ownerHandle,
    });
    if (reg.status === "taken") {
      // Another account owns this mailbox's credential — refuse, fail-open.
      await audit(userId, "badge.email_domain.auto_issue_skipped", { reason: "taken" });
      return;
    }
    const nullifierRef = reg.entryRef;
    const freshlyRegistered = reg.status === "registered";

    try {
      const badgeId = await issueBadge({
        userId,
        pluginId: PLUGIN_ID,
        badge: { type: BADGE_TYPE, attributes: { domain }, claims: { domain } },
        dedupeKey: `${BADGE_TYPE}:${userId}:${domain}`,
        nullifierRef,
      });
      await audit(userId, "badge.email_domain.auto_issued", { domain, badgeId });
    } catch (mintErr) {
      // A unique-constraint violation means a concurrent sign-in already minted
      // this exact badge — benign, the race lost cleanly. Do NOT release the
      // entry: the winning badge legitimately references it (and the interim
      // release is sibling-guarded regardless).
      if (
        typeof mintErr === "object" &&
        mintErr !== null &&
        "code" in mintErr &&
        mintErr.code === "P2002"
      ) {
        await audit(userId, "badge.email_domain.auto_issue_skipped", { reason: "duplicate" });
        return;
      }
      // Genuine mint failure: release a FRESH registration so a signing error
      // never strands the credential (an `already_yours` entry predates this
      // attempt and is left alone). Post-commit discipline, idempotent retry.
      if (freshlyRegistered) {
        await runPostCommit(
          () => nullifierService.release({ entryRef: nullifierRef, ownerHandle }),
          "auto-issue-email-domain-release",
        );
      }
      throw mintErr;
    }
  } catch (err) {
    // Never let a genuine badge-issuance failure surface as a failed sign-in.
    await audit(userId, "badge.email_domain.auto_issue_failed", {
      domain,
      error: err instanceof Error ? err.message : "unknown",
    });
  }
}
