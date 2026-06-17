import { audit } from "@/lib/audit";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";

// Out-of-band notification for credential changes. Every credential
// mutation (add/remove a passkey or email, promote a primary, redeem a
// recovery code, complete a recovery/merge) calls this so a compromised
// session can't silently rewrite the credential set: the legitimate owner
// is mailed at every verified address and can act on a change they didn't
// make. Slice 2's credential-management actions are the callers.
//
// Delivery goes to ALL verified addresses (a quarantined/compromised inbox
// can't suppress the alert reaching the others). One-click revoke-link
// tokens are deferred — the email links to /settings/credentials where the
// owner can review and revoke. An AuditLog row is written regardless of how
// many emails went out, so the change is recorded even for a user with no
// verified email yet.
//
// Send failures are surfaced (this function rejects) so a caller can decide
// whether a mutation should proceed without its notification — we never
// silently swallow a failed alert. The audit row is written first so the
// record survives even if mail egress is down.
export async function notifyCredentialChange(userId: string, summary: string): Promise<void> {
  const emails = await prisma.userEmail.findMany({
    where: { userId, verifiedAt: { not: null } },
    select: { email: true },
  });

  // Record the change first — the audit trail must not depend on mail
  // delivery succeeding.
  await audit(userId, "credential.changed", { summary });

  const subject = "A credential changed on your Minister account";
  const text = [
    `A credential changed on your Minister account: ${summary}.`,
    "",
    "If this wasn't you, go to /settings/credentials and revoke it.",
  ].join("\n");
  const html = [
    `<p>A credential changed on your Minister account: ${summary}.</p>`,
    `<p>If this wasn't you, go to <a href="/settings/credentials">/settings/credentials</a> and revoke it.</p>`,
  ].join("");

  // Send to every verified address. Run sequentially so a single transport
  // failure is surfaced deterministically (sendMail throws on a misconfigured
  // or failed Resend send); we don't want a partial fan-out to hide an error.
  for (const { email } of emails) {
    await sendMail({ to: email, subject, text, html });
  }
}
