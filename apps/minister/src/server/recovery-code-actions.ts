"use server";

import { headers } from "next/headers";

import { signIn } from "@/auth";
import { notifyCredentialChange } from "@/lib/credential-notify";
import { prisma } from "@/lib/prisma";
import { clientIpFrom, createRateLimiter } from "@/lib/rate-limit";
import { generateRecoveryCodes, redeemRecoveryCode } from "@/lib/recovery-codes";
import { issueRecoveryTicket } from "@/lib/recovery-ticket";
import { getCurrentSession, requireAal } from "@/lib/session";

// Server actions for slice 3 (recovery codes). Two surfaces:
//   * generateMyRecoveryCodes — AUTHENTICATED, AAL2-gated. Mint a fresh batch
//     and return the plaintext once.
//   * redeemRecoveryCodeAndSignIn — UNAUTHENTICATED recovery entry. Resolve a
//     user by email, redeem a code, and land a quarantined AAL1 `recovered`
//     session via the "recovery" Credentials provider.

// ---------------------------------------------------------------------------
// Generate (authenticated, AAL2)
// ---------------------------------------------------------------------------

// Mint a new batch of recovery codes for the signed-in user. Requires AAL2
// (DESIGNDECISIONS #4/#6): you must already hold a phishing-resistant factor to
// create the codes that can later bypass it. Returns the PLAINTEXT codes; the
// caller renders them once and never persists them. Regenerating invalidates
// the previous unused batch (handled in generateRecoveryCodes).
//
// KNOWN GAP H-1: the AAL2 gate below does NOT also check the acting credential
// is past its quarantine cooldown (see credential-actions.ts header + TODO.md).
// Accepted for alpha.
export async function generateMyRecoveryCodes(): Promise<{ codes: string[] }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  // Throws StepUpRequiredError when below AAL2; the UI catches it to route into
  // step-up rather than showing a generic failure.
  requireAal(session, 2);

  const codes = await generateRecoveryCodes(session.user.id);

  // Out-of-band alert to every verified address: regenerating recovery codes is
  // a credential change a compromised session could attempt.
  await notifyCredentialChange(session.user.id, "recovery codes regenerated");

  return { codes };
}

// ---------------------------------------------------------------------------
// Redeem (unauthenticated recovery entry)
// ---------------------------------------------------------------------------

// Per-IP redemption limiter. Recovery-code redemption is an unauthenticated
// guess-and-check surface, so it must be rate-limited independently of the
// signed-in flows. Reuses the app's createRateLimiter (same util as every other
// guarded surface); a dedicated instance because the shared exports in
// rate-limit.ts are scoped to their own endpoints. Caps are deliberately low —
// a human recovering an account makes a handful of attempts, not dozens.
const recoveryRedeemLimiter = createRateLimiter({
  windowMs: 15 * 60_000,
  max: Number.parseInt(process.env.MINISTER_RL_RECOVERY_MAX ?? "", 10) || 10,
});

export type RedeemResult =
  | { ok: true }
  | { ok: false; reason: "rate-limited"; retryAfterSeconds: number }
  | { ok: false; reason: "invalid" };

// Unauthenticated entry point: the user supplies an email they control and one
// of their recovery codes. On success we mint a recovery ticket and immediately
// hand it to Auth.js, landing a quarantined AAL1 `recovered` session (see
// RecoveryProvider in src/auth.ts and the jwt callback in auth.config.ts).
//
// Anti-enumeration: a wrong email, a wrong code, an unknown account, and a
// banned/merged account ALL return the same opaque { ok: false, reason:
// "invalid" }. The flow never discloses whether the email exists or whether the
// account has codes. Rate-limited per client IP to blunt online guessing.
export async function redeemRecoveryCodeAndSignIn(
  userIdentifier: string,
  code: string,
): Promise<RedeemResult> {
  const ip = clientIpFrom(await headers());
  const verdict = recoveryRedeemLimiter.check(ip);
  if (!verdict.allowed) {
    return { ok: false, reason: "rate-limited", retryAfterSeconds: verdict.retryAfterSeconds };
  }

  const userId = await resolveUserId(userIdentifier);
  if (!userId) {
    // Unknown / banned / merged account — indistinguishable from a wrong code.
    return { ok: false, reason: "invalid" };
  }

  const redeemed = await redeemRecoveryCode(userId, code);
  if (!redeemed) {
    return { ok: false, reason: "invalid" };
  }

  // Notify EVERY verified address that a recovery code was used — a recovery
  // the legitimate owner didn't initiate must reach them out of band.
  await notifyCredentialChange(userId, "a recovery code was used to sign in");

  // Mint a single-use ticket and exchange it for a quarantined AAL1 recovered
  // session. redirect:false so this server action returns control to the caller
  // (the UI then routes the user to enroll a fresh passkey).
  const ticket = await issueRecoveryTicket(userId);
  await signIn("recovery", { ticket, redirect: false });

  return { ok: true };
}

// Resolve the supplied identifier to a usable userId, mirroring the adapter's
// email lookup (UserEmail first, then the legacy User.email primary cache). A
// banned or merged (tombstoned) account resolves to null — recovery must not
// resurrect either (the RecoveryProvider enforces the same, this is
// defence-in-depth and saves a pointless code verify).
//
// If the identifier already looks like an opaque user id (the UI may carry one
// it trusts), we still re-validate ban/merge before returning it.
async function resolveUserId(identifier: string): Promise<string | null> {
  const trimmed = identifier.trim();
  if (trimmed.length === 0) return null;

  const email = trimmed.toLowerCase();

  const owned = await prisma.userEmail.findUnique({
    where: { email },
    select: { user: { select: { id: true, isBanned: true, mergedIntoUserId: true } } },
  });
  if (owned) {
    const u = owned.user;
    return u.isBanned || u.mergedIntoUserId !== null ? null : u.id;
  }

  const legacy = await prisma.user.findFirst({
    where: { email },
    select: { id: true, isBanned: true, mergedIntoUserId: true },
  });
  if (legacy) {
    return legacy.isBanned || legacy.mergedIntoUserId !== null ? null : legacy.id;
  }

  return null;
}
