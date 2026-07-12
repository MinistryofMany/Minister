"use server";

import { randomBytes } from "node:crypto";

import { headers } from "next/headers";

import { audit } from "@/lib/audit";
import { gatePrivilegedAction } from "@/lib/credential-gate";
import type { QuarantineRefusal } from "@/lib/credential-lifecycle";
import {
  emailButton,
  emailFinePrint,
  emailInlineLink,
  emailLinkFallback,
  emailParagraph,
  emailText,
  renderEmail,
} from "@/lib/email-layout";
import { sendMail } from "@/lib/mailer";
import { mergeAccounts } from "@/lib/merge";
import { issueDonorProof, verifyDonorProof } from "@/lib/merge-proof";
import { prisma } from "@/lib/prisma";
import { clientIpFrom, createRateLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";

// Server actions driving the account-merge ceremony (slice 5). The dual-control
// shape (DESIGNDECISIONS #12):
//   1. startMerge()        — the SURVIVOR, signed in at AAL2 and NOT recovered,
//      declares the donor by an email it controls. We mail a single-use,
//      nonce-bound "prove this is also you" magic link to that donor address.
//   2. completeDonorLink() — the donor clicks the link. We verify it, confirm it
//      resolves to a real, eligible donor account, and mint a single-use
//      donor-proof TICKET (merge-proof.ts) bound to that donorUserId. The ticket
//      is the portable second factor handed back to the survivor's session.
//   3. confirmMerge()      — back in the SURVIVOR session (re-checked AAL2 + not
//      recovered), verify+consume the donor-proof ticket, re-check the bound
//      donorUserId is the donor we intend, run all the eligibility guards, then
//      mergeAccounts(). Notify every email on BOTH accounts.
//
// SECURITY anchor: a donor-proof ticket is NEVER minted from an unauthenticated
// request. It is minted only inside completeDonorLink, after a single-use,
// short-TTL link delivered to a VERIFIED donor email has been clicked — i.e.
// after the donor demonstrably controls that inbox. The link token itself is the
// donor's authentication; the ticket is its consumable receipt.

// The merge-link magic token is a single-use marker in the VerificationToken
// table under a dedicated namespace (same durable single-use mechanism as the
// recovery/donor-proof tickets), carrying the survivor + donor binding.
const MERGE_LINK_IDENTIFIER = "merge-donor-link";
// The donor link lives a bit longer than the donor-proof ticket: the human has
// to receive the email and click it. Fifteen minutes.
const MERGE_LINK_TTL_MS = 15 * 60 * 1000;

// Merge is an AAL2, low-frequency ceremony. Cap link sends per IP so a survivor
// session can't spray donor-link emails as an inbox-spam vector.
const mergeLinkLimiter = createRateLimiter({ windowMs: 15 * 60_000, max: 10 });

async function ip(): Promise<string> {
  return clientIpFrom(await headers());
}

async function origin(): Promise<string> {
  const h = await headers();
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host") ?? "localhost:3000";
  return `${proto}://${host}`;
}

// Resolve a donor email to a usable donor account id, mirroring the recovery
// flow's resolution: VERIFIED UserEmail only, and never a banned or already
// merged (tombstoned) account. Returns null on any of those (the caller does not
// disclose which).
async function resolveVerifiedUserIdByEmail(email: string): Promise<string | null> {
  const owned = await prisma.userEmail.findUnique({
    where: { email },
    select: {
      verifiedAt: true,
      user: { select: { id: true, isBanned: true, mergedIntoUserId: true } },
    },
  });
  if (!owned || !owned.verifiedAt) return null;
  const u = owned.user;
  if (u.isBanned || u.mergedIntoUserId !== null) return null;
  return u.id;
}

// ---------------------------------------------------------------------------
// Step 1 — startMerge (survivor, AAL2)
// ---------------------------------------------------------------------------

export interface StartMergeResult {
  ok: boolean;
  // True when the session is below the AAL2 floor: the UI routes into a
  // passkey step-up and retries. Returned (not thrown) because a thrown
  // server-action error reaches the client as an opaque digest in production.
  stepUp?: boolean;
  // Present when the H-1 quarantine gate refused; `error` carries its copy.
  quarantine?: QuarantineRefusal;
  error?: string;
}

// Begin a merge from the signed-in SURVIVOR account. Requires AAL2, a
// non-recovered session (a reduced-assurance recovered session must never start
// a merge — DESIGNDECISIONS #9), and the H-1 quarantine gate (a session held up
// only by a freshly-grafted, still-quarantined passkey must not open the merge
// ceremony). `donorEmail` is an address the survivor claims to ALSO control; we
// mail it a single-use prove-it link. We do NOT disclose whether that email
// maps to an account (anti-enumeration): a hit and a miss both return ok:true.
export async function startMerge(donorEmail: string): Promise<StartMergeResult> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    return { ok: false, error: "Not signed in" };
  }
  if ((session.aal ?? 0) < 2) {
    return {
      ok: false,
      stepUp: true,
      error: "Merging accounts requires signing in with a passkey first.",
    };
  }
  if (session.recovered) {
    return {
      ok: false,
      error: "A recovered session can't start an account merge. Add a passkey first.",
    };
  }

  if (!mergeLinkLimiter.check(await ip()).allowed) {
    return { ok: false, error: "Too many merge requests. Try again later." };
  }

  const survivorUserId = session.user.id;

  // H-1 quarantine gate — refuse before any donor link is even minted.
  const refusal = await gatePrivilegedAction(survivorUserId, session.cred, "merge.start");
  if (refusal) {
    return { ok: false, quarantine: refusal, error: refusal.message };
  }
  const email = donorEmail.trim().toLowerCase();
  if (!email.includes("@")) {
    return { ok: false, error: "Enter the email on the account you want to merge in." };
  }

  const donorUserId = await resolveVerifiedUserIdByEmail(email);

  // Anti-enumeration: if there's no eligible donor for this email we STILL return
  // ok and simply send no link. The survivor learns nothing about the address.
  // We also refuse a self-merge silently (the donor resolves to the survivor).
  if (!donorUserId || donorUserId === survivorUserId) {
    await audit(survivorUserId, "merge.link_requested", { delivered: false });
    return { ok: true };
  }

  // Mint a single-use marker carrying the survivor↔donor binding. The token is
  // the VerificationToken row's `token` (a high-entropy opaque secret); the
  // identifier namespaces it AND binds it to this exact survivor↔donor pair, so
  // a link minted for one pair can never be consumed for another.
  const token = randomBytes(32).toString("base64url");
  await prisma.verificationToken.create({
    data: {
      identifier: `${MERGE_LINK_IDENTIFIER}:${survivorUserId}:${donorUserId}`,
      token,
      expires: new Date(Date.now() + MERGE_LINK_TTL_MS),
    },
  });

  const link = `${await origin()}/settings/merge/confirm-donor?token=${encodeURIComponent(token)}&s=${encodeURIComponent(survivorUserId)}&d=${encodeURIComponent(donorUserId)}`;
  await sendMail({
    to: email,
    subject: "Confirm merging this account into another",
    text: [
      "Someone signed in to a Minister account is asking to MERGE this account",
      "into theirs. If that's you, click the link below to confirm you control",
      "this account too. After confirming, this account becomes part of the",
      "other one and can no longer be signed into on its own.",
      "",
      link,
      "",
      "If this wasn't you, ignore this email — nothing will be merged.",
    ].join("\n"),
    html: renderEmail({
      title: "Confirm merging this account into another",
      heading: "Confirm merging your account",
      blocks: [
        emailParagraph(
          "Someone signed in to a Minister account is asking to <strong>merge this account into theirs</strong>.",
        ),
        emailText("If that's you, confirm you control this account too:"),
        emailButton("Confirm and continue the merge", link),
        emailLinkFallback(link),
        emailFinePrint(
          "After confirming, this account becomes part of the other one and can no longer be signed into on its own. If this wasn't you, ignore this email — nothing will be merged.",
        ),
      ],
    }),
  });

  await audit(survivorUserId, "merge.link_requested", { delivered: true, donorUserId });
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Step 2 — completeDonorLink (donor clicked the emailed link)
// ---------------------------------------------------------------------------

export interface CompleteDonorLinkResult {
  ok: boolean;
  // On success: the donor-proof ticket the survivor's session feeds to
  // confirmMerge. It is short-lived and single-use.
  donorProof?: string;
  // Echoed so the UI can show "you're about to merge <donorEmail> in". Opaque ids
  // only — no email is echoed back to a possibly-different viewer.
  survivorUserId?: string;
  donorUserId?: string;
  error?: string;
}

// The donor clicked the prove-it link. Consume the single-use marker (binding
// survivor↔donor), confirm the donor account is still eligible, and mint the
// donor-proof ticket. This is the ONLY place a donor-proof is minted, and it
// runs only after a verified-donor-inbox link was clicked.
//
// The survivor + donor ids arrive both in the URL (s/d) AND in the marker's
// namespaced identifier; we require them to match, so a tampered URL that swaps
// the donor can't consume a marker minted for a different pair.
export async function completeDonorLink(
  token: string,
  survivorUserId: string,
  donorUserId: string,
): Promise<CompleteDonorLinkResult> {
  if (!token || !survivorUserId || !donorUserId) {
    return { ok: false, error: "This confirmation link is malformed." };
  }
  if (survivorUserId === donorUserId) {
    return { ok: false, error: "An account can't be merged into itself." };
  }

  // Atomic single-use: delete the marker for this exact (identifier, token). If
  // it's gone (already used, expired-and-swept, or the s/d in the URL don't match
  // the binding) the delete throws and we reject.
  const identifier = `${MERGE_LINK_IDENTIFIER}:${survivorUserId}:${donorUserId}`;
  let consumed = false;
  try {
    const deleted = await prisma.verificationToken.deleteMany({
      where: { identifier, token, expires: { gt: new Date() } },
    });
    consumed = deleted.count === 1;
  } catch {
    consumed = false;
  }
  if (!consumed) {
    return { ok: false, error: "This confirmation link is invalid, expired, or already used." };
  }

  // Re-validate the donor is still an eligible, non-tombstoned account at click
  // time (it could have been banned/merged since the link was sent).
  const donor = await prisma.user.findUnique({
    where: { id: donorUserId },
    select: { isBanned: true, mergedIntoUserId: true },
  });
  if (!donor || donor.isBanned || donor.mergedIntoUserId !== null) {
    return { ok: false, error: "This account can no longer be merged." };
  }

  // Mint the single-use donor-proof bound to donorUserId. confirmMerge verifies
  // it and re-checks the bound id against the donor it intends to merge.
  const donorProof = await issueDonorProof(donorUserId);
  await audit(donorUserId, "merge.donor_proven", { survivorUserId });

  return { ok: true, donorProof, survivorUserId, donorUserId };
}

// ---------------------------------------------------------------------------
// Step 3 — confirmMerge (survivor, AAL2; consumes the donor proof)
// ---------------------------------------------------------------------------

export interface ConfirmMergeResult {
  ok: boolean;
  // Same typed refusal channel as StartMergeResult (see there).
  stepUp?: boolean;
  quarantine?: QuarantineRefusal;
  error?: string;
  // Present on success: counts moved, overrides created, and the stranded-RP
  // client list for the UI's "what got left behind" notice.
  moved?: Record<string, number>;
  overridesCreated?: number;
  strandedClients?: string[];
  mergeRecordId?: string;
}

// Finish the merge. Must run in the SURVIVOR session (re-checked AAL2 + not
// recovered). Verifies+consumes the donor-proof, re-checks the bound donorUserId
// is the donor we intend (the ticket is single-account-bound, but we still
// compare — defence in depth), runs the eligibility guards, then mergeAccounts.
// Notifies every email on BOTH accounts.
//
// `intendedDonorUserId` is the donor the survivor's UI is showing — we require
// the donor-proof's bound id to equal it. This closes the gap where a survivor
// could be handed a proof for a DIFFERENT donor than the one they confirmed.
export async function confirmMerge(
  donorProofTicket: string,
  intendedDonorUserId: string,
): Promise<ConfirmMergeResult> {
  const session = await getCurrentSession();
  if (!session?.user?.id) {
    return { ok: false, error: "Not signed in" };
  }
  if ((session.aal ?? 0) < 2) {
    return {
      ok: false,
      stepUp: true,
      error: "Completing a merge requires signing in with a passkey first.",
    };
  }
  if (session.recovered) {
    return {
      ok: false,
      error: "A recovered session can't complete an account merge. Add a passkey first.",
    };
  }

  const survivorUserId = session.user.id;

  // H-1 quarantine gate — re-checked at CONFIRM time so a merge started before
  // a credential change can't be laundered through a stale start. Deliberately
  // runs BEFORE the donor proof is consumed: a refused attempt must not burn
  // the single-use ticket (the user can clear the gate and retry with the same
  // proof rather than restarting the whole ceremony).
  const refusal = await gatePrivilegedAction(survivorUserId, session.cred, "merge.confirm");
  if (refusal) {
    return { ok: false, quarantine: refusal, error: refusal.message };
  }

  // Verify + consume the donor-proof. Null on any failure (bad sig, expired,
  // wrong typ, already used).
  const proven = await verifyDonorProof(donorProofTicket);
  if (!proven) {
    return { ok: false, error: "Donor confirmation is invalid, expired, or already used." };
  }
  // Re-check the bound donor is the one the survivor intends to merge.
  if (proven.donorUserId !== intendedDonorUserId) {
    return { ok: false, error: "Donor confirmation doesn't match the account you selected." };
  }
  const donorUserId = proven.donorUserId;

  if (donorUserId === survivorUserId) {
    return { ok: false, error: "An account can't be merged into itself." };
  }

  // Final eligibility re-read (state can have changed since the proof was minted).
  const [survivor, donor] = await Promise.all([
    prisma.user.findUnique({
      where: { id: survivorUserId },
      select: { mergedIntoUserId: true },
    }),
    prisma.user.findUnique({
      where: { id: donorUserId },
      select: { isBanned: true, mergedIntoUserId: true },
    }),
  ]);
  if (!survivor || survivor.mergedIntoUserId !== null) {
    // The survivor itself was tombstoned out from under us — refuse.
    return { ok: false, error: "Your account is no longer in a state that can absorb a merge." };
  }
  if (!donor || donor.mergedIntoUserId !== null) {
    return {
      ok: false,
      error: "That account can no longer be merged (already merged or missing).",
    };
  }
  // A banned donor is NOT a hard block on the merge itself — the survivor inherits
  // the ban via sticky-OR (DESIGNDECISIONS #13). We allow it through to
  // mergeAccounts, which applies the sticky-OR.

  // Collect every notification address on BOTH accounts BEFORE the merge moves
  // the donor's emails onto the survivor (after merge they all read as the
  // survivor's; we want the full set regardless).
  const emails = await prisma.userEmail.findMany({
    where: { userId: { in: [survivorUserId, donorUserId] }, verifiedAt: { not: null } },
    select: { email: true },
  });

  // Do the surgery.
  const summary = await mergeAccounts(survivorUserId, donorUserId);

  await audit(survivorUserId, "merge.completed", {
    donorUserId,
    mergeRecordId: summary.mergeRecordId,
    moved: summary.moved,
    overridesCreated: summary.overridesCreated,
    strandedClients: summary.strandedClients,
  });

  // Notify every verified address on both accounts. A merge must never be
  // silent: the legitimate owner of EITHER account must learn it happened.
  // Failures are surfaced (sendMail throws) rather than swallowed.
  const subject = "Two Minister accounts were merged";
  const text = [
    "Two Minister accounts were merged into one.",
    "",
    "If you started this, no action is needed. If you didn't, go to",
    "/settings and review your account immediately — a merge can be reversed",
    "for a limited time.",
  ].join("\n");
  const html = renderEmail({
    title: subject,
    heading: "Two accounts were merged",
    blocks: [
      emailText("Two Minister accounts were merged into one."),
      emailParagraph(
        `If you started this, no action is needed. If you didn't, go to ${emailInlineLink("/settings", "/settings")} and review your account immediately — a merge can be reversed for a limited time.`,
      ),
    ],
  });
  for (const { email } of emails) {
    await sendMail({ to: email, subject, text, html });
  }

  return {
    ok: true,
    moved: summary.moved,
    overridesCreated: summary.overridesCreated,
    strandedClients: summary.strandedClients,
    mergeRecordId: summary.mergeRecordId,
  };
}
