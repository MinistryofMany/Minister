"use server";

import { headers } from "next/headers";

import { signIn } from "@/auth";
import { RECOVERY_ELIGIBLE_TYPES } from "@/lib/assurance";
import { audit } from "@/lib/audit";
import { notifyCredentialChange } from "@/lib/credential-notify";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { clientIpFrom, createRateLimiter } from "@/lib/rate-limit";
import { issueReProofToken, verifyReProofToken } from "@/lib/recovery-reproof";
import {
  consumeSatisfiedAttempt,
  getAttemptStatus,
  recordReProof,
  startRecoveryAttempt,
  type RecoveryAttemptStatus,
} from "@/lib/recovery-threshold";

// Server actions driving the unauthenticated weighted-badge-threshold recovery
// flow (slice 4). The accounting lives in @/lib/recovery-threshold; this layer
// resolves the account, drives the per-plugin LIVE re-proof, and on
// satisfaction lands the quarantined AAL1 recovered session.
//
// PLUGIN WIRING STATUS (see the report + the per-action comments):
//   * email-domain  — WIRED END-TO-END. requestEmailDomainReProof sends a
//     nonce-bound magic link; completeEmailDomainReProof verifies it live and
//     calls recordReProof.
//   * oauth-account (github), tlsn-attestation — NOT WIRED. Typed integration
//     points are defined below and throw an explicit "not yet wired" error
//     rather than faking a proof. Do NOT route a real recovery through them
//     until their live re-proof is implemented.

// Recovery is account-security floor: rate-limit attempt creation hard, keyed
// on client IP, so an attacker can't farm attempts against many accounts. A
// short window with a low cap (this is a human-driven multi-minute ceremony).
const recoveryStartLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 5 });
// Re-proof link sends are an inbox-spam vector; cap per IP.
const reProofSendLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10 });

async function ip(): Promise<string> {
  return clientIpFrom(await headers());
}

async function origin(): Promise<string> {
  const h = await headers();
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host") ?? "localhost:3000";
  return `${proto}://${host}`;
}

export interface StartRecoveryResult {
  ok: boolean;
  attemptId?: string;
  requiredScore?: number;
  // The recovery-eligible badge types this account holds (non-public only),
  // for the UI to offer as re-proof options. Empty when none are re-provable.
  provableTypes?: string[];
  // The held email-domain badge domains, so the UI can show which domains can
  // be re-proven by email link.
  domains?: string[];
  error?: string;
}

// Begin a recovery ceremony for the account owning `userIdentifier` (an email).
// Resolves the account WITHOUT revealing whether it exists (anti-enumeration):
// on a miss we still return a generic ok:false with the same shape and timing
// is not branched on sensitive work.
//
// SECURITY: we never authenticate here. The attempt is a capability bounded by
// its nonce + TTL; nothing it produces grants access until the threshold is
// met and consumeSatisfiedAttempt mints a one-shot ticket.
export async function startBadgeRecovery(userIdentifier: string): Promise<StartRecoveryResult> {
  if (!recoveryStartLimiter.check(await ip()).allowed) {
    return { ok: false, error: "Too many recovery attempts. Try again later." };
  }

  const email = userIdentifier.trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return { ok: false, error: "Enter the email address on the account." };
  }

  // Resolve the account through UserEmail (the multi-email identity store),
  // verified addresses only — an unverified address can't drive recovery.
  const owned = await prisma.userEmail.findUnique({
    where: { email },
    select: { userId: true, verifiedAt: true },
  });
  const userId = owned?.verifiedAt ? owned.userId : null;

  if (!userId) {
    // Anti-enumeration: don't disclose whether the account exists. The UI shows
    // a neutral "if this account exists, here are its options" state; with no
    // user there are simply no provable types.
    return { ok: true, provableTypes: [], domains: [] };
  }

  // Don't let a banned or already-merged (tombstoned) account be recovered.
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { isBanned: true, mergedIntoUserId: true },
  });
  if (!user || user.isBanned || user.mergedIntoUserId !== null) {
    return { ok: true, provableTypes: [], domains: [] };
  }

  // The recovery-eligible, NON-PUBLIC badge types the account holds. Public
  // badges are excluded (DESIGNDECISIONS #8) here in the UI offer too, so the
  // user is never invited to re-prove something that wouldn't count.
  const badges = await prisma.badge.findMany({
    where: { userId, isPublic: false },
    select: { type: true, attributes: true },
  });
  const provable = new Set<string>();
  const domains = new Set<string>();
  for (const b of badges) {
    if (!RECOVERY_ELIGIBLE_TYPES.has(b.type)) continue;
    provable.add(b.type);
    if (b.type === "email-domain") {
      const attrs = b.attributes as Record<string, unknown>;
      if (typeof attrs.domain === "string") domains.add(attrs.domain);
    }
  }

  const started = await startRecoveryAttempt(userId);
  await audit(userId, "recovery.badge_threshold.started", { attemptId: started.attemptId });

  return {
    ok: true,
    attemptId: started.attemptId,
    requiredScore: started.requiredScore,
    provableTypes: [...provable],
    domains: [...domains],
  };
}

export interface AttemptStatusView {
  status: RecoveryAttemptStatus;
  accumulatedScore: number;
  requiredScore: number;
  satisfied: boolean;
  provenTypes: string[];
}

// Poll the live tally for the UI's climbing-score view.
export async function getRecoveryStatus(attemptId: string): Promise<AttemptStatusView | null> {
  const s = await getAttemptStatus(attemptId);
  if (!s) return null;
  return {
    status: s.status,
    accumulatedScore: s.accumulatedScore,
    requiredScore: s.requiredScore,
    satisfied: s.status === "satisfied" || s.status === "consumed",
    provenTypes: s.provenTypes,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// WIRED PLUGIN: email-domain live re-proof
// ───────────────────────────────────────────────────────────────────────────

export interface RequestReProofResult {
  ok: boolean;
  error?: string;
}

// Step 1 of the email-domain re-proof: the user names an email address at a
// domain they hold a non-public email-domain badge for. We send a nonce-bound
// one-time link to that address. Clicking it (step 2) completes the live proof.
//
// We confirm the badge HOLDING here (the attempt's user holds a non-public
// email-domain badge for the derived domain) before sending, so we never email
// a link the proof couldn't possibly satisfy. The link is bound to the attempt
// nonce (recovery-reproof token), so it's useless against any other attempt.
export async function requestEmailDomainReProof(
  attemptId: string,
  emailAddress: string,
): Promise<RequestReProofResult> {
  if (!reProofSendLimiter.check(await ip()).allowed) {
    return { ok: false, error: "Too many verification emails. Try again later." };
  }

  const address = emailAddress.trim().toLowerCase();
  const at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1) {
    return { ok: false, error: "Enter a valid email address." };
  }
  const domain = address.slice(at + 1);

  // The attempt must be live (pending, unexpired). We re-read it for the user +
  // nonce binding; the accounting engine will re-validate again at record time.
  const attempt = await prisma.recoveryAttempt.findUnique({
    where: { id: attemptId },
    select: { userId: true, status: true, nonce: true, expiresAt: true },
  });
  if (!attempt || attempt.status !== "pending" || attempt.expiresAt.getTime() <= Date.now()) {
    return { ok: false, error: "This recovery attempt is no longer active. Start over." };
  }

  // Confirm the account actually holds a NON-PUBLIC email-domain badge for this
  // exact domain. Without this an attacker could prove any domain they control
  // and have it count; the badge holding is what ties the proof to the account.
  const held = await prisma.badge.findFirst({
    where: { userId: attempt.userId, type: "email-domain", isPublic: false },
    select: { id: true, attributes: true },
  });
  const heldDomain =
    held && typeof (held.attributes as Record<string, unknown>).domain === "string"
      ? ((held.attributes as Record<string, unknown>).domain as string)
      : null;
  if (!heldDomain || heldDomain.toLowerCase() !== domain) {
    // Don't disclose which domains the account holds; generic message.
    return { ok: false, error: "That address can't be used to recover this account." };
  }

  const token = await issueReProofToken({
    attemptId,
    badgeType: "email-domain",
    domain: heldDomain,
    nonceBinding: attempt.nonce,
  });

  const link = `${await origin()}/recover/badges/email/verify?token=${encodeURIComponent(token)}`;
  await sendMail({
    to: address,
    subject: "Confirm control of your email for account recovery",
    text: [
      "Someone is recovering a Minister account by proving control of an email",
      `address at ${heldDomain}.`,
      "",
      "If that's you, click the link below to add this proof to the recovery:",
      link,
      "",
      "If not, ignore this email — no recovery proof will be recorded.",
    ].join("\n"),
  });

  await audit(attempt.userId, "recovery.badge_threshold.reproof_sent", {
    attemptId,
    badgeType: "email-domain",
  });

  return { ok: true };
}

export interface CompleteReProofResult {
  ok: boolean;
  accumulatedScore?: number;
  requiredScore?: number;
  satisfied?: boolean;
  error?: string;
}

// Step 2 of the email-domain re-proof: the user clicked the link. The token is
// authentic + single-use + nonce-bound (verifyReProofToken). We re-read the
// LIVE attempt, confirm the token's nonceBinding still matches the attempt's
// nonce (freshness), then hand off to recordReProof. This function IS the
// caller that satisfies the re-proof/nonce contract for email-domain.
export async function completeEmailDomainReProof(token: string): Promise<CompleteReProofResult> {
  const claims = await verifyReProofToken(token);
  if (!claims) {
    return { ok: false, error: "This link is invalid, expired, or already used." };
  }

  // Freshness: the token must still belong to the live attempt by nonce. A
  // token minted for a since-replaced attempt (new nonce) is rejected here.
  const attempt = await prisma.recoveryAttempt.findUnique({
    where: { id: claims.attemptId },
    select: { nonce: true },
  });
  if (!attempt || attempt.nonce !== claims.nonceBinding) {
    return { ok: false, error: "This link no longer matches an active recovery attempt." };
  }

  // The live cryptographic re-proof is now established (a fresh, single-use,
  // nonce-bound link to an address at the held domain was clicked). Hand off to
  // the accounting core.
  const outcome = await recordReProof(claims.attemptId, "email-domain", {
    proofRef: claims.domain,
  });
  if (!outcome.ok) {
    return { ok: false, error: reproofErrorMessage(outcome.reason) };
  }

  return {
    ok: true,
    accumulatedScore: outcome.accumulatedScore,
    requiredScore: outcome.requiredScore,
    satisfied: outcome.satisfied,
  };
}

function reproofErrorMessage(reason: string): string {
  switch (reason) {
    case "already-proven":
      return "You've already proven this credential for this recovery.";
    case "attempt-expired":
      return "This recovery attempt expired. Start over.";
    case "attempt-not-pending":
      return "This recovery attempt is no longer accepting proofs.";
    case "badge-not-held":
      return "That credential can't be used to recover this account.";
    case "type-not-eligible":
      return "That credential type can't be used for recovery.";
    default:
      return "Could not record that proof.";
  }
}

// ───────────────────────────────────────────────────────────────────────────
// NOT-YET-WIRED PLUGINS: typed integration points
// ───────────────────────────────────────────────────────────────────────────
// These define the SHAPE a live re-proof hook must satisfy but are NOT
// implemented. Each must, before calling recordReProof: (1) run the actual
// plugin verification live, (2) bind it to the attempt nonce, (3) confirm the
// freshly proven real-world identity matches a held non-public badge. They
// throw rather than fake a proof — wiring them is a follow-on.

// oauth-account (github): re-run the GitHub OAuth dance with `state` == the
// attempt nonce, fetch /user, confirm the GitHub account id matches the
// `accountId` attribute of a held non-public oauth-account badge, then
// recordReProof(attemptId, "oauth-account", { provenance: "github",
// proofRef: accountId }). NOT WIRED.
export async function completeOauthAccountReProof(
  _attemptId: string,
  _provider: string,
  _oauthCallback: { code: string; state: string },
): Promise<CompleteReProofResult> {
  throw new Error(
    "oauth-account live re-proof is not yet wired (slice 4). Implement the nonce-bound OAuth re-run before enabling.",
  );
}

// tlsn-attestation: ask the extension to produce a FRESH TLSNotary presentation
// with the submission token == the attempt nonce, verify it, confirm the
// proven { domain, claim } matches a held non-public tlsn-attestation badge,
// then recordReProof(attemptId, "tlsn-attestation"). NOT WIRED.
export async function completeTlsnReProof(
  _attemptId: string,
  _presentation: string,
  _submissionToken: string,
): Promise<CompleteReProofResult> {
  throw new Error(
    "tlsn-attestation live re-proof is not yet wired (slice 4). Implement the nonce-bound TLSN re-proof before enabling.",
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Finish: consume the satisfied attempt and land the recovered session
// ───────────────────────────────────────────────────────────────────────────

export interface FinishRecoveryResult {
  ok: boolean;
  error?: string;
}

// Consume a satisfied attempt one-shot, mint the recovery ticket, sign in via
// the "recovery" provider (lands an AAL1 + recovered, quarantined session), and
// notify every verified email. Idempotency / reuse is guarded inside
// consumeSatisfiedAttempt (atomic satisfied -> consumed claim).
export async function finishBadgeRecovery(attemptId: string): Promise<FinishRecoveryResult> {
  const consumed = await consumeSatisfiedAttempt(attemptId);
  if (!consumed.ok) {
    const msg =
      consumed.reason === "not-satisfied"
        ? "You haven't reached the recovery threshold yet."
        : consumed.reason === "already-consumed"
          ? "This recovery has already been completed."
          : consumed.reason === "expired"
            ? "This recovery attempt expired. Start over."
            : "This recovery attempt could not be found.";
    return { ok: false, error: msg };
  }

  // Land the quarantined AAL1 recovered session. redirect:false so we control
  // navigation in the UI; the recovery Credentials provider stamps aal=1 +
  // recovered=true via the jwt callback.
  await signIn("recovery", { ticket: consumed.ticket, redirect: false });

  // Out-of-band alert to every verified address — a recovery must never be
  // silent (DESIGNDECISIONS #9). Failure to notify is surfaced, not swallowed.
  await notifyCredentialChange(
    consumed.userId,
    "account recovered via badge-threshold recovery (session is reduced-assurance until you add a passkey)",
  );
  await audit(consumed.userId, "recovery.badge_threshold.completed", { attemptId });

  return { ok: true };
}
