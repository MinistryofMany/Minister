"use server";

import { randomBytes } from "node:crypto";

import { SignJWT, jwtVerify } from "jose";

import { CREDENTIAL_QUARANTINE_MS } from "@/lib/assurance";
import { audit } from "@/lib/audit";
import { requirePrivilegedAction } from "@/lib/credential-gate";
import {
  effectiveCredentialStatus as asStatus,
  PrivilegedActionQuarantineError,
  type CredentialStatus,
  type QuarantineRefusal,
} from "@/lib/credential-lifecycle";
import { notifyCredentialChange } from "@/lib/credential-notify";
import {
  emailButton,
  emailFinePrint,
  emailLinkFallback,
  emailText,
  renderEmail,
} from "@/lib/email-layout";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";
import { getCurrentSession, requireAal, StepUpRequiredError } from "@/lib/session";
import { EmailCollisionError } from "@/server/credential-errors";
import type { Session } from "next-auth";

// ---------------------------------------------------------------------------
// Credential-management server actions (slices 1 + 2).
//
// Every mutation here:
//   * loads the acting principal with getCurrentSession() (gen/ban/merge
//     enforced), bailing with "Not signed in" when there is none;
//   * enforces the AAL floor the operation declares via requireAal(), which
//     throws StepUpRequiredError the UI catches to route into a passkey
//     step-up;
//   * refuses to act for a `recovered` session (a reduced-capability session
//     obtained via recovery code / badge threshold may climb to AAL2 by
//     enrolling a passkey, but must NOT be able to evict or rewrite other
//     credentials — DESIGNDECISIONS #9);
//   * notifies every verified address on success (notifyCredentialChange),
//     so a compromised session can't silently rewrite the credential set.
//
// Quarantine: a freshly added email lands status="quarantined" here;
// passkeys are stamped at WRITE time by the adapter's createAuthenticator
// override in src/auth.ts (so a raw WebAuthn ceremony can't skip it). The
// bootstrap first passkey on a passkey-less account is the one exception
// (DESIGNDECISIONS #4) — it is active immediately so the user can reach AAL2.
//
// H-1 ENFORCEMENT (closed 2026-07-12; was the accepted alpha gap): the
// privileged pivots a grafted credential wants — startMerge / confirmMerge
// (merge-actions.ts), generateMyRecoveryCodes (recovery-code-actions.ts), and
// setPrimaryEmail (below) — now run the quarantine gate
// (src/lib/credential-gate.ts) in addition to the AAL2 floor and the
// recovered-session refusal. The gate requires (1) at least one
// non-quarantined passkey on the account and (2) when the session's `cred`
// JWT claim names the acting passkey, that passkey to be non-quarantined
// itself. Refusals surface as typed, user-facing results (never a bare
// throw across the RSC boundary) with copy saying when/how they clear.
// ---------------------------------------------------------------------------

export type CredentialKind = "email" | "passkey" | "oauth";
// Canonical definition lives in credential-lifecycle.ts (shared with the
// gate and the client-side "clears in …" hints); re-exported for existing
// importers of this module.
export type { CredentialStatus };

export interface CredentialEmail {
  kind: "email";
  id: string;
  email: string;
  isPrimary: boolean;
  verified: boolean;
  status: CredentialStatus;
  quarantinedUntil: string | null;
  createdAt: string;
}

export interface CredentialPasskey {
  kind: "passkey";
  credentialID: string;
  label: string | null;
  status: CredentialStatus;
  quarantinedUntil: string | null;
  addedAt: string;
  lastUsedAt: string | null;
}

export interface CredentialAccount {
  kind: "oauth";
  /** Badge id — the stable React list key. */
  id: string;
  /** OAuth provider slug: "github" | "google" | … */
  provider: string;
  /** Disclosed handle, when the badge carries one. */
  handle: string | null;
  /** When the account was linked (the badge's issuedAt), ISO string. */
  linkedAt: string;
}

export interface CredentialListing {
  emails: CredentialEmail[];
  passkeys: CredentialPasskey[];
  accounts: CredentialAccount[];
  /** Whether the acting session is a reduced-capability recovery session. */
  recovered: boolean;
  /** Whether the user currently holds zero passkeys (drives bootstrap copy). */
  canBootstrapPasskey: boolean;
}

// Load the acting principal, throwing a plain "Not signed in" (distinct from
// StepUpRequiredError) when there is no valid session. Callers then apply the
// AAL floor with requireAal().
async function requirePrincipal(): Promise<Session & { user: { id: string } }> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    throw new Error("Not signed in");
  }
  return session as Session & { user: { id: string } };
}

// A recovered (reduced-capability) session must not mutate the credential set
// beyond enrolling its own first climb to AAL2. We reject it from every
// destructive/grafting action here. (DESIGNDECISIONS #9.)
function rejectRecovered(session: Session): void {
  if (session.recovered === true) {
    throw new Error(
      "This is a recovery session with reduced capabilities. Re-establish a passkey to manage credentials.",
    );
  }
}

// ---------------------------------------------------------------------------
// Email verification token
//
// A dedicated, single-use, short-TTL signed token (HS256 over AUTH_SECRET,
// same key handling as recovery-ticket) that resolves to a specific UserEmail
// row. addEmail mints one and mails a verify link; verifyEmail consumes it and
// stamps verifiedAt. Single-use is durable: the jti is recorded in
// VerificationToken under a namespaced identifier at issue and atomically
// deleted at verify, so a link works exactly once even across app instances.
// ---------------------------------------------------------------------------

const VERIFY_ALG = "HS256";
const VERIFY_TYP = "minister-email-verify";
const VERIFY_TTL_SECONDS = 24 * 60 * 60; // 24h to click the verify link
const VERIFY_CONSUMPTION_IDENTIFIER = "email-verify";

function verifyKey(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set (≥32 chars) for email-verify tokens");
  }
  return new TextEncoder().encode(secret);
}

async function issueEmailVerifyToken(userEmailId: string): Promise<string> {
  const jti = randomBytes(24).toString("base64url");
  await prisma.verificationToken.create({
    data: {
      identifier: VERIFY_CONSUMPTION_IDENTIFIER,
      token: jti,
      expires: new Date(Date.now() + VERIFY_TTL_SECONDS * 1000),
    },
  });
  return new SignJWT({ userEmailId })
    .setProtectedHeader({ alg: VERIFY_ALG, typ: VERIFY_TYP })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${VERIFY_TTL_SECONDS}s`)
    .sign(verifyKey());
}

// Verify signature + exp, then atomically consume the single-use marker.
// Returns the UserEmail id on success, null on any failure. Never throws on a
// bad token — verifyEmail turns null into a clear error.
async function consumeEmailVerifyToken(token: string): Promise<{ userEmailId: string } | null> {
  let userEmailId: string;
  let jti: string;
  try {
    const { payload } = await jwtVerify(token, verifyKey(), {
      algorithms: [VERIFY_ALG],
      typ: VERIFY_TYP,
    });
    if (typeof payload.userEmailId !== "string" || typeof payload.jti !== "string") {
      return null;
    }
    userEmailId = payload.userEmailId;
    jti = payload.jti;
  } catch {
    return null;
  }

  try {
    await prisma.verificationToken.delete({
      where: {
        identifier_token: { identifier: VERIFY_CONSUMPTION_IDENTIFIER, token: jti },
      },
    });
  } catch {
    // Already consumed, or expired-and-swept — a verified-but-unconsumable
    // token must not verify an email.
    return null;
  }

  return { userEmailId };
}

function verifyLinkBase(): string {
  // Built so the verify link is absolute in mail. NEXTAUTH_URL/AUTH_URL is the
  // canonical app origin; fall back to localhost in dev. We never embed the
  // token in the audit log.
  const base = process.env.AUTH_URL ?? process.env.NEXTAUTH_URL ?? "http://localhost:3000";
  return base.replace(/\/$/, "");
}

// ---------------------------------------------------------------------------
// listCredentials — the union the management UI renders.
// ---------------------------------------------------------------------------

// Collapse the user's `oauth-account` badges into one row per linked account.
// Re-proving a link mints a fresh badge, so the same provider+handle can appear
// more than once; badges arrive issuedAt-ascending, so the first occurrence is
// the earliest link and each account is listed exactly once.
function dedupeAccounts(
  badges: { id: string; attributes: unknown; issuedAt: Date }[],
): CredentialAccount[] {
  const byKey = new Map<string, CredentialAccount>();
  for (const b of badges) {
    const attrs = (b.attributes ?? {}) as { provider?: unknown; handle?: unknown };
    if (typeof attrs.provider !== "string") continue;
    const handle = typeof attrs.handle === "string" ? attrs.handle : null;
    const key = `${attrs.provider}:${handle ?? ""}`;
    if (byKey.has(key)) continue;
    byKey.set(key, {
      kind: "oauth",
      id: b.id,
      provider: attrs.provider,
      handle,
      linkedAt: b.issuedAt.toISOString(),
    });
  }
  return [...byKey.values()];
}

export async function listCredentials(): Promise<CredentialListing> {
  const session = await requirePrincipal();
  const userId = session.user.id;

  const [emails, passkeys, accounts] = await Promise.all([
    prisma.userEmail.findMany({
      where: { userId },
      orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
      select: {
        id: true,
        email: true,
        isPrimary: true,
        verifiedAt: true,
        status: true,
        quarantinedUntil: true,
        createdAt: true,
      },
    }),
    prisma.authenticator.findMany({
      where: { userId },
      orderBy: { addedAt: "asc" },
      select: {
        credentialID: true,
        label: true,
        status: true,
        quarantinedUntil: true,
        addedAt: true,
        lastUsedAt: true,
      },
    }),
    // "Linked accounts" = the OAuth accounts the user linked. In Minister that
    // link lives as an `oauth-account` BADGE (provider + optional handle), NOT
    // an Auth.js Account row: there are no OAuth SIGN-IN providers, so the
    // Account table only ever holds passkey (type="webauthn") and magic-link
    // (type="email") rows — never a linked GitHub/Google. Reading Account here
    // is why the section showed passkeys and never the real linked accounts;
    // read the badges instead.
    prisma.badge.findMany({
      where: { userId, type: "oauth-account" },
      orderBy: { issuedAt: "asc" },
      select: { id: true, attributes: true, issuedAt: true },
    }),
  ]);

  return {
    emails: emails.map((e) => ({
      kind: "email" as const,
      id: e.id,
      email: e.email,
      isPrimary: e.isPrimary,
      verified: e.verifiedAt !== null,
      status: asStatus(e.status, e.quarantinedUntil),
      quarantinedUntil: e.quarantinedUntil?.toISOString() ?? null,
      createdAt: e.createdAt.toISOString(),
    })),
    passkeys: passkeys.map((p) => ({
      kind: "passkey" as const,
      credentialID: p.credentialID,
      label: p.label,
      status: asStatus(p.status, p.quarantinedUntil),
      quarantinedUntil: p.quarantinedUntil?.toISOString() ?? null,
      addedAt: p.addedAt.toISOString(),
      lastUsedAt: p.lastUsedAt?.toISOString() ?? null,
    })),
    accounts: dedupeAccounts(accounts),
    recovered: session.recovered === true,
    canBootstrapPasskey: passkeys.length === 0,
  };
}

// ---------------------------------------------------------------------------
// addEmail — AAL2. Quarantined, unverified; mails a verify link.
// ---------------------------------------------------------------------------

// Minimal, conservative email shape check. The verify round-trip is the real
// proof of control; this only rejects obvious garbage before we mint a row.
function normalizeEmail(raw: string): string {
  const email = raw.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Enter a valid email address.");
  }
  return email;
}

export async function addEmail(emailInput: string): Promise<{ id: string; email: string }> {
  const session = await requirePrincipal();
  rejectRecovered(session);
  requireAal(session, 2);
  const userId = session.user.id;
  const email = normalizeEmail(emailInput);

  // UserEmail.email is globally unique — an address belongs to at most one
  // account. Create the quarantined row and handle the unique violation
  // explicitly (P2002) rather than pre-checking (which would race).
  let row: { id: string };
  try {
    row = await prisma.userEmail.create({
      data: {
        userId,
        email,
        isPrimary: false,
        verifiedAt: null,
        status: "quarantined",
        quarantinedUntil: new Date(Date.now() + CREDENTIAL_QUARANTINE_MS),
      },
      select: { id: true },
    });
  } catch (err) {
    if (
      typeof err === "object" &&
      err !== null &&
      "code" in err &&
      (err as { code?: unknown }).code === "P2002"
    ) {
      throw new EmailCollisionError(email);
    }
    throw err;
  }

  // Mail the verify link. A send failure must surface (we don't leave a row
  // the user can never verify silently): roll the row back, then rethrow.
  try {
    const token = await issueEmailVerifyToken(row.id);
    const url = `${verifyLinkBase()}/settings/credentials/verify?token=${encodeURIComponent(token)}`;
    await sendMail({
      to: email,
      subject: "Verify your email for Minister",
      text: [
        "Confirm this address to add it to your Minister account:",
        "",
        url,
        "",
        "If you didn't request this, you can ignore this email. The link expires in 24 hours.",
      ].join("\n"),
      html: renderEmail({
        title: "Verify your email for Minister",
        heading: "Confirm your email address",
        blocks: [
          emailText("Confirm this address to add it to your Minister account:"),
          emailButton("Verify this email", url),
          emailLinkFallback(url),
          emailFinePrint(
            "If you didn't request this, you can ignore this email. The link expires in 24 hours.",
          ),
        ],
      }),
    });
  } catch (err) {
    await prisma.userEmail.delete({ where: { id: row.id } }).catch(() => {
      // Best-effort cleanup; the original send error is what matters.
    });
    throw err;
  }

  // Notify the existing verified addresses that an email was added (the new,
  // unverified address is not yet a notification target).
  await notifyCredentialChange(userId, `email ${email} added (pending verification)`);

  return { id: row.id, email };
}

// ---------------------------------------------------------------------------
// verifyEmail — consume the link token and mark the row verified.
//
// Unauthenticated by design: the magic link is the proof of control, and the
// owner may click it from an inbox session that isn't signed into Minister. We
// still scope the consumed token to a single UserEmail row, so it can only
// verify the address it was minted for.
// ---------------------------------------------------------------------------

export async function verifyEmail(token: string): Promise<{ email: string }> {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("Missing verification token.");
  }
  const consumed = await consumeEmailVerifyToken(token);
  if (!consumed) {
    throw new Error("This verification link is invalid or has expired.");
  }

  const existing = await prisma.userEmail.findUnique({
    where: { id: consumed.userEmailId },
    select: { id: true, email: true, userId: true, verifiedAt: true },
  });
  if (!existing) {
    // The row was removed after the link was issued.
    throw new Error("This email is no longer associated with an account.");
  }

  if (existing.verifiedAt === null) {
    await prisma.userEmail.update({
      where: { id: existing.id },
      data: { verifiedAt: new Date() },
    });
    await audit(existing.userId, "credential.email_verified", { email: existing.email });
  }

  return { email: existing.email };
}

// ---------------------------------------------------------------------------
// removeEmail — AAL2. Never strand the account with zero verified emails.
// ---------------------------------------------------------------------------

export async function removeEmail(emailId: string): Promise<void> {
  const session = await requirePrincipal();
  rejectRecovered(session);
  requireAal(session, 2);
  const userId = session.user.id;

  const target = await prisma.userEmail.findUnique({
    where: { id: emailId },
    select: { id: true, userId: true, email: true, isPrimary: true, verifiedAt: true },
  });
  if (!target || target.userId !== userId) {
    throw new Error("Email not found.");
  }

  // Refuse to leave the account with zero verified emails. Removing a verified
  // (or the primary) email is allowed only when ANOTHER verified email remains.
  const otherVerifiedCount = await prisma.userEmail.count({
    where: { userId, verifiedAt: { not: null }, id: { not: emailId } },
  });
  const targetIsVerified = target.verifiedAt !== null;
  if ((targetIsVerified || target.isPrimary) && otherVerifiedCount === 0) {
    throw new Error(
      "You can't remove your last verified email. Add and verify another address first.",
    );
  }

  await prisma.userEmail.delete({ where: { id: emailId } });
  await notifyCredentialChange(userId, `email ${target.email} removed`);
}

// ---------------------------------------------------------------------------
// setPrimaryEmail — AAL2. Single-primary enforced in one transaction.
// ---------------------------------------------------------------------------

export async function setPrimaryEmail(emailId: string): Promise<void> {
  const session = await requirePrincipal();
  rejectRecovered(session);
  requireAal(session, 2);
  const userId = session.user.id;
  // H-1 quarantine gate: the primary email is where security notifications
  // land, so promoting one is a pivot a grafted credential must not reach.
  // Throws PrivilegedActionQuarantineError; the action wrapper below turns it
  // into a typed result with user-facing copy.
  await requirePrivilegedAction(userId, session.cred, "email.set-primary");

  const target = await prisma.userEmail.findUnique({
    where: { id: emailId },
    select: { id: true, userId: true, email: true, verifiedAt: true },
  });
  if (!target || target.userId !== userId) {
    throw new Error("Email not found.");
  }
  if (target.verifiedAt === null) {
    throw new Error("Verify this email before making it your primary address.");
  }

  // Single transaction: clear isPrimary on all of the user's emails, set it on
  // this one, and refresh the User.email primary cache. The two-write order
  // (clear-all then set-one) enforces the single-primary invariant in-tx
  // (DESIGNDECISIONS #10).
  await prisma.$transaction([
    prisma.userEmail.updateMany({
      where: { userId, isPrimary: true },
      data: { isPrimary: false },
    }),
    prisma.userEmail.update({
      where: { id: emailId },
      data: { isPrimary: true },
    }),
    prisma.user.update({
      where: { id: userId },
      data: { email: target.email },
    }),
  ]);

  await notifyCredentialChange(userId, `primary email set to ${target.email}`);
}

// ---------------------------------------------------------------------------
// Passkey enrollment lifecycle
//
// The WebAuthn ceremony itself is client-side via Auth.js
// signIn("passkey",{action:"register"}); these actions own the BEFORE/AFTER
// policy around it:
//
//   canAddPasskey()      — the gate the client checks BEFORE the ceremony.
//   markPasskeyEnrolled()— the lifecycle stamp the client calls AFTER it.
// ---------------------------------------------------------------------------

export interface CanAddPasskeyResult {
  allowed: boolean;
  /** True when this would be the bootstrap first passkey on an AAL1 session. */
  bootstrap: boolean;
  reason?: string;
}

// Bootstrap rule (DESIGNDECISIONS #4): a brand-new account with NO existing
// passkey may enroll its FIRST passkey from an AAL1 session (otherwise it could
// never reach AAL2). A second/replacement passkey requires AAL2. A recovered
// session may also enroll its climb-to-AAL2 passkey (DESIGNDECISIONS #9), so
// we do NOT reject `recovered` here — only at the destructive actions.
export async function canAddPasskey(): Promise<CanAddPasskeyResult> {
  const session = await requirePrincipal();
  const userId = session.user.id;
  const existing = await prisma.authenticator.count({ where: { userId } });
  const aal: number = session.aal ?? 0;

  if (existing === 0) {
    // Bootstrap: allowed from AAL1+ (a verified magic-link session). A bare
    // AAL0 session shouldn't reach here (requirePrincipal needs a signed-in
    // user), but require AAL>=1 explicitly.
    if (aal < 1) {
      return { allowed: false, bootstrap: true, reason: "Sign in before adding a passkey." };
    }
    return { allowed: true, bootstrap: true };
  }

  // Second/replacement passkey: AAL2 required.
  if (aal < 2) {
    return {
      allowed: false,
      bootstrap: false,
      reason: "Adding another passkey requires step-up to AAL2.",
    };
  }
  return { allowed: true, bootstrap: false };
}

// Called by the client AFTER a successful WebAuthn registration ceremony.
// READ-ONLY: the credential lifecycle (bootstrap-active vs quarantined) and
// the out-of-band notification are both applied at WRITE time by the
// adapter's createAuthenticator override (src/auth.ts) — the only code path
// that can insert an Authenticator row — so a raw ceremony that never calls
// this changes nothing, and this action being client-callable gives an
// attacker no lever (it stamps nothing, promotes nothing). It only reports
// whether the just-enrolled (newest) passkey landed quarantined so the UI
// can explain the security hold.
export async function markPasskeyEnrolled(): Promise<{ quarantined: boolean }> {
  const session = await requirePrincipal();
  const userId = session.user.id;

  const newest = await prisma.authenticator.findFirst({
    where: { userId },
    orderBy: { addedAt: "desc" },
    select: { status: true, quarantinedUntil: true },
  });
  if (!newest) {
    throw new Error("No passkey found to finalize. The enrollment may not have completed.");
  }
  return { quarantined: asStatus(newest.status, newest.quarantinedUntil) === "quarantined" };
}

// ---------------------------------------------------------------------------
// removePasskey — AAL2. Refuse to remove the user's last passkey.
// ---------------------------------------------------------------------------

export async function removePasskey(credentialID: string): Promise<void> {
  const session = await requirePrincipal();
  rejectRecovered(session);
  requireAal(session, 2);
  const userId = session.user.id;

  const target = await prisma.authenticator.findUnique({
    where: { userId_credentialID: { userId, credentialID } },
    select: { credentialID: true, userId: true },
  });
  if (!target || target.userId !== userId) {
    throw new Error("Passkey not found.");
  }

  const total = await prisma.authenticator.count({ where: { userId } });
  if (total <= 1) {
    // For tonight: refuse to remove the last passkey rather than stranding the
    // user's only AAL2 factor. A confirm-and-downgrade path is a follow-on.
    throw new Error(
      "You can't remove your last passkey — it's your only phishing-resistant factor. Add another passkey first.",
    );
  }

  await prisma.authenticator.delete({
    where: { userId_credentialID: { userId, credentialID } },
  });

  // We do NOT touch a surviving passkey's quarantine here. Promoting an
  // in-window quarantined survivor on removal would defeat the cooldown
  // (DESIGNDECISIONS #5): a hijacked AAL2 session could add a quarantined
  // passkey, then remove the victim's original (total was 2, so the
  // last-passkey refusal above still passes) to instantly hand the new passkey
  // full power. Instead we leave the window intact — a survivor whose window is
  // still open stays quarantined until it lapses, and a survivor whose window
  // has already lapsed reads as active via asStatus's lazy expiry. That is also
  // what fixes the "my only passkey is quarantined forever" display bug: the
  // status is judged against the clock at read time, not rewritten on removal.
  await notifyCredentialChange(userId, "a passkey was removed");
}

// ---------------------------------------------------------------------------
// Client dispatch wrapper
//
// The actions above THROW (StepUpRequiredError for an AAL shortfall, plain
// Errors otherwise) — the contract slices 3/4/5 and tests rely on. But a
// thrown Server Action error does NOT cross the RSC boundary with its class or
// message intact (Next replaces it with an opaque digest in production), so a
// client component can't reliably `instanceof StepUpRequiredError` on a throw.
//
// This wrapper is the client's channel: it runs an action and translates the
// outcome into a tagged result the client CAN branch on — `{ stepUp: true }`
// when step-up is required (the UI runs signIn("passkey",...) and retries),
// `{ ok: false, error }` for a presentable failure, `{ ok: true, data }` on
// success. The throwing actions remain the source of truth; this only adapts
// their result for transport.
// ---------------------------------------------------------------------------

export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; stepUp: true; requiredAal: number }
  // `quarantine` is present when the H-1 gate refused: `error` already carries
  // the finished user-facing copy, and the structured refusal lets the UI
  // offer a passkey re-auth (canStepUp) or a "clears in …" hint (retryAt).
  | { ok: false; stepUp?: false; quarantine?: QuarantineRefusal; error: string };

async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    if (err instanceof StepUpRequiredError) {
      return { ok: false, stepUp: true, requiredAal: err.requiredAal };
    }
    if (err instanceof PrivilegedActionQuarantineError) {
      return { ok: false, quarantine: err.refusal, error: err.refusal.message };
    }
    const error = err instanceof Error ? err.message : "Something went wrong.";
    return { ok: false, error };
  }
}

// addEmail has one extra outcome the generic run() can't express: a
// collision with an address already on another account. We surface it as a
// distinct `collision` result so the UI can offer a merge (prefilling the
// address) instead of showing a dead-end error. Everything else flows through
// run() unchanged.
export type AddEmailResult =
  | ActionResult<{ id: string; email: string }>
  | { ok: false; stepUp?: false; collision: true; email: string; error: string };

export async function addEmailAction(email: string): Promise<AddEmailResult> {
  try {
    return { ok: true, data: await addEmail(email) };
  } catch (err) {
    if (err instanceof StepUpRequiredError) {
      return { ok: false, stepUp: true, requiredAal: err.requiredAal };
    }
    if (err instanceof EmailCollisionError) {
      return { ok: false, collision: true, email: err.email, error: err.message };
    }
    const error = err instanceof Error ? err.message : "Something went wrong.";
    return { ok: false, error };
  }
}

export async function removeEmailAction(emailId: string): Promise<ActionResult<void>> {
  return run(() => removeEmail(emailId));
}

export async function setPrimaryEmailAction(emailId: string): Promise<ActionResult<void>> {
  return run(() => setPrimaryEmail(emailId));
}

export async function removePasskeyAction(credentialID: string): Promise<ActionResult<void>> {
  return run(() => removePasskey(credentialID));
}

export async function markPasskeyEnrolledAction(): Promise<ActionResult<{ quarantined: boolean }>> {
  return run(() => markPasskeyEnrolled());
}

export async function canAddPasskeyAction(): Promise<ActionResult<CanAddPasskeyResult>> {
  return run(() => canAddPasskey());
}

export async function listCredentialsAction(): Promise<ActionResult<CredentialListing>> {
  return run(() => listCredentials());
}
