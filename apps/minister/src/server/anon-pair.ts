import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { generateSessionId } from "@minister/shared/pair-protocol";

import { audit } from "@/lib/audit";
import { emailInlineLink, emailParagraph, emailText, renderEmail } from "@/lib/email-layout";
import { sendMail } from "@/lib/mailer";
import { prisma } from "@/lib/prisma";

// QR device-pairing relay logic (identity plan, "QR pairing"). The route
// handlers under app/api/anon/pair/ are thin adapters over these functions;
// keeping the DB logic here makes the C2 same-account control unit-testable
// against a mocked prisma. The relay is BLIND: nothing here ever sees or stores
// the recipient public key, the HPKE shared secret, or the root — only the
// sessionId, two IPs/UAs, best-effort geo, and the 64-byte opaque blob.

/** Session lifetime: 3 minutes. A long time for a screenshot to travel; short
 * enough to bound a captured QR. */
export const PAIR_TTL_MS = 3 * 60 * 1000;

/** Opportunistic-sweep grace: rows whose seal window expired this long ago are
 * dead (even a sealed-but-slow-to-claim row is claimed within seconds in the
 * happy path). Deleted on the next `create` so the table — and any lingering
 * sealed ciphertext — cannot grow unbounded without cron infra. */
const PAIR_SWEEP_GRACE_MS = 60 * 60 * 1000;

/** Length of the creator secret (bytes) before base64url encoding. The display
 * device holds it; only its SHA-256 is stored, and it is the claim capability. */
const CREATOR_SECRET_BYTES = 32;

function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

/** Constant-time compare of a presented creator secret against the stored hash.
 * Hashing first makes both sides fixed-length, so timingSafeEqual never throws
 * on a length mismatch (which would itself leak length). */
function secretMatches(presented: string, storedHash: string): boolean {
  const a = Buffer.from(hashSecret(presented), "hex");
  const b = Buffer.from(storedHash, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ponytail: /24 (IPv4) and /48 (IPv6) prefix match — a coarse "same network"
// heuristic, not proximity. Phone-on-cellular + laptop-on-Wi-Fi is a DIFFERENT
// network in the happy path, which is exactly why the copy treats "different"
// as informational and the country check (not this) forces the typed code.
function sameNetwork(a: string | null, b: string | null): boolean {
  if (!a || !b || a === "unknown" || b === "unknown") return false;
  if (a === b) return true;
  const a4 = a.split(".");
  const b4 = b.split(".");
  if (a4.length === 4 && b4.length === 4) {
    return a4[0] === b4[0] && a4[1] === b4[1] && a4[2] === b4[2];
  }
  if (a.includes(":") && b.includes(":")) {
    const prefix = (s: string) => s.split(":").slice(0, 3).join(":");
    return prefix(a) === prefix(b);
  }
  return false;
}

type SessionRow = {
  id: string;
  userId: string;
  state: string;
  sealedPayload: string | null;
  creatorSecretHash: string;
  expiresAt: Date;
  creatorIp: string | null;
  creatorCountry: string | null;
  creatorCity: string | null;
};

export type PairState = "waiting" | "sealed" | "claimed" | "expired" | "not_found";

/** A waiting row past its TTL reads as `expired`; a sealed row stays claimable
 * (the seal already happened in-window), so TTL gates SEAL, not CLAIM. */
function effectiveState(row: SessionRow, now: Date): PairState {
  if (row.state === "waiting" && row.expiresAt <= now) return "expired";
  if (row.state === "waiting" || row.state === "sealed" || row.state === "claimed") {
    return row.state;
  }
  return "not_found";
}

// --- create ---------------------------------------------------------------

export interface CreatePairArgs {
  userId: string;
  ip: string | null;
  ua: string | null;
  country: string | null;
  city: string | null;
}

export interface CreatePairResult {
  sessionId: string;
  creatorSecret: string;
  expiresAt: string;
}

/** The DISPLAYING device mints a relay session for its OWN authenticated
 * account. The recipient public key is NOT sent here (it never touches the
 * wire) — it goes only into the QR the page renders from memory. */
export async function createPairSession(args: CreatePairArgs): Promise<CreatePairResult> {
  const sessionId = generateSessionId();
  const creatorSecret = randomBytes(CREATOR_SECRET_BYTES).toString("base64url");
  const expiresAt = new Date(Date.now() + PAIR_TTL_MS);
  // FIX 3: opportunistic TTL sweep — bound table growth (and drop any lingering
  // sealed ciphertext) without cron infra. Best-effort: a sweep failure must not
  // block minting a fresh session.
  try {
    await prisma.anonPairSession.deleteMany({
      where: { expiresAt: { lt: new Date(Date.now() - PAIR_SWEEP_GRACE_MS) } },
    });
  } catch {
    // Non-fatal: the row bound is a hygiene property, not a correctness one.
  }
  await prisma.anonPairSession.create({
    data: {
      id: sessionId,
      userId: args.userId,
      state: "waiting",
      creatorSecretHash: hashSecret(creatorSecret),
      expiresAt,
      creatorIp: args.ip,
      creatorUa: args.ua,
      creatorCountry: args.country,
      creatorCity: args.city,
    },
  });
  await audit(args.userId, "anon.pair.created", { sessionId });
  return { sessionId, creatorSecret, expiresAt: expiresAt.toISOString() };
}

// --- poll (peer facts for the scanner) ------------------------------------

export interface PairPeerFacts {
  country: string | null;
  city: string | null;
  sameNetworkAsYou: boolean;
  // True only when both countries are known AND equal. When it is false — a
  // different country OR either country unknown — the scanner MUST require the
  // typed code (fail-safe): a foreign-country peer is the phish signature.
  sameCountryAsYou: boolean;
}

export interface PollPairResult {
  state: PairState;
  expiresAt: string | null;
  peer: PairPeerFacts | null;
}

/** The SCANNING device reads the DISPLAYING device's connection facts so the
 * user can judge "is that really my other device?". `peer` describes the creator
 * relative to the scanner's own IP. Requires only the sessionId (from the QR);
 * the creator secret is not needed and must not be, since the scanner never has
 * it. */
export async function pollPairSession(args: {
  sessionId: string;
  requesterIp: string | null;
  requesterCountry: string | null;
}): Promise<PollPairResult> {
  const row = await prisma.anonPairSession.findUnique({ where: { id: args.sessionId } });
  if (!row) return { state: "not_found", expiresAt: null, peer: null };
  const now = new Date();
  const sameCountryAsYou =
    row.creatorCountry !== null &&
    args.requesterCountry !== null &&
    row.creatorCountry === args.requesterCountry;
  return {
    state: effectiveState(row, now),
    expiresAt: row.expiresAt.toISOString(),
    peer: {
      country: row.creatorCountry,
      city: row.creatorCity,
      sameNetworkAsYou: sameNetwork(row.creatorIp, args.requesterIp),
      sameCountryAsYou,
    },
  };
}

// --- seal (the C2 same-account control) -----------------------------------

export type SealPairResult =
  { ok: true } | { ok: false; reason: "cross_account" | "expired" | "already_used" | "not_found" };

/**
 * The SCANNING device (holding the root) deposits its HPKE-sealed payload.
 *
 * C2 (CRITICAL): the atomic conditional update carries `userId =
 * :sessionUserId` — the sealer's OWN authenticated session user. This is the
 * SOLE barrier against the remote phish, NOT defense in depth: `pk` authenticates
 * the channel but says nothing about WHO holds the recipient key, so only this
 * server-side account equality distinguishes "my other device" from "an
 * attacker's screen on the real origin". A sealer authenticated as account B
 * matches zero of account A's rows, so the payload is never written.
 */
export async function sealPairSession(args: {
  sessionId: string;
  sessionUserId: string;
  payload: string;
  ip: string | null;
  ua: string | null;
  country: string | null;
  city: string | null;
}): Promise<SealPairResult> {
  const now = new Date();
  const res = await prisma.anonPairSession.updateMany({
    where: {
      id: args.sessionId,
      userId: args.sessionUserId, // C2: the load-bearing same-account condition.
      state: "waiting",
      expiresAt: { gt: now },
    },
    data: {
      state: "sealed",
      sealedPayload: args.payload,
      sealerIp: args.ip,
      sealerUa: args.ua,
    },
  });
  if (res.count === 1) {
    await audit(args.sessionUserId, "anon.pair.sealed", { sessionId: args.sessionId });
    // FIX 2a: root delivery is irreversible, so also alert the owner out of band.
    // Fail-open — a mail error must never break or roll back a completed pairing.
    await notifyDeviceAdded(args.sessionUserId, args.sessionId, args.country, args.city);
    return { ok: true };
  }
  // The update above is the barrier. This read exists ONLY to pick the right
  // user-facing copy — a cross-account mismatch gets the S3 attack warning, not
  // a "try again". It never widens what the update permits.
  const row = await prisma.anonPairSession.findUnique({ where: { id: args.sessionId } });
  if (!row) return { ok: false, reason: "not_found" };
  if (row.userId !== args.sessionUserId) {
    // FIX 2b: a C2-blocked cross-account deposit is a root-theft phish signature.
    // Record it against the phished (victim) account whose session was used.
    await audit(args.sessionUserId, "anon.pair.cross_account_blocked", {
      sessionId: args.sessionId,
    });
    return { ok: false, reason: "cross_account" };
  }
  if (row.expiresAt <= now) return { ok: false, reason: "expired" };
  if (row.state !== "waiting") return { ok: false, reason: "already_used" };
  return { ok: false, reason: "not_found" };
}

/**
 * FIX 2a: out-of-band alert that a new device was added to the user's Private
 * Identity. Mailed to every verified address (a compromised inbox can't suppress
 * the others). Fail-open by contract: swallow any transport error and record it
 * to the audit log — the pairing already succeeded and must never be rolled back
 * or blocked by a mail failure (mirrors the credential-notify pattern, but
 * fail-open rather than surfacing). Dev/test degrades to a console log inside the
 * mailer.
 */
async function notifyDeviceAdded(
  userId: string,
  sessionId: string,
  country: string | null,
  city: string | null,
): Promise<void> {
  try {
    const emails = await prisma.userEmail.findMany({
      where: { userId, verifiedAt: { not: null } },
      select: { email: true },
    });
    const where = city ?? country ?? "an unknown location";
    const when = new Date().toUTCString();
    const subject = "A new device was added to your Private Identity";
    const text = [
      `A new device was just added to your Minister Private Identity.`,
      ``,
      `Time: ${when}`,
      `From: ${where}`,
      ``,
      `If this wasn't you, someone may have your key. Go to /settings/private-identity and re-key your identity immediately.`,
    ].join("\n");
    const html = renderEmail({
      title: subject,
      heading: "A new device was added to your Private Identity",
      blocks: [
        emailText(`A new device was just added to your Minister Private Identity.`),
        emailText(`Time: ${when}`, { muted: true }),
        emailText(`From: ${where}`, { muted: true }),
        // Trusted static copy plus a pre-rendered inline link — emailParagraph,
        // not emailText, so the link markup is not double-escaped.
        emailParagraph(
          `If this wasn't you, someone may have your key. Go to ${emailInlineLink(
            "/settings/private-identity",
            "/settings/private-identity",
          )} and re-key your identity immediately.`,
        ),
      ],
    });
    for (const { email } of emails) {
      await sendMail({ to: email, subject, text, html });
    }
  } catch (err) {
    // Fail-open: never let a mail failure break the pairing. Record it so the
    // missed alert is at least traceable.
    await audit(userId, "anon.pair.notify_failed", {
      sessionId,
      error: err instanceof Error ? err.message : String(err),
    }).catch(() => {
      // Even the audit write is best-effort here; nothing else to do.
    });
  }
}

// --- claim (single-use handoff to the creator) ----------------------------

export type ClaimPairResult =
  | { ok: true; state: "waiting" | "expired" }
  | { ok: true; state: "claimed"; payload: string | null }
  | { ok: false; reason: "not_found" | "forbidden" | "bad_secret" };

/**
 * The DISPLAYING device retrieves the sealed payload with its creator secret.
 * The payload is NULLed in the SAME statement that hands it over (single-use):
 * only the update that flips sealed→claimed returns bytes; a racing second
 * claim gets `payload: null`. Also gated on the claimer's own session user
 * matching the row (defense) and on the creator-secret hash (the capability).
 */
export async function claimPairSession(args: {
  sessionId: string;
  sessionUserId: string;
  creatorSecret: string;
}): Promise<ClaimPairResult> {
  const row = await prisma.anonPairSession.findUnique({ where: { id: args.sessionId } });
  if (!row) return { ok: false, reason: "not_found" };
  if (row.userId !== args.sessionUserId) return { ok: false, reason: "forbidden" };
  if (!secretMatches(args.creatorSecret, row.creatorSecretHash)) {
    return { ok: false, reason: "bad_secret" };
  }
  const now = new Date();
  if (row.state === "claimed") return { ok: true, state: "claimed", payload: null };
  if (row.state === "waiting") {
    return { ok: true, state: row.expiresAt <= now ? "expired" : "waiting" };
  }
  // state === "sealed": hand off and NULL atomically.
  const res = await prisma.anonPairSession.updateMany({
    where: { id: args.sessionId, state: "sealed" },
    data: { state: "claimed", sealedPayload: null },
  });
  if (res.count === 1 && row.sealedPayload !== null) {
    await audit(args.sessionUserId, "anon.pair.claimed", { sessionId: args.sessionId });
    return { ok: true, state: "claimed", payload: row.sealedPayload };
  }
  return { ok: true, state: "claimed", payload: null };
}
