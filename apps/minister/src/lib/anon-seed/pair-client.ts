import {
  derivePairCode,
  encodePairQr,
  generateRecipientKeyPair,
  parsePairQr,
} from "@minister/shared/pair-protocol";

import { receiveRootFromPeer, sealRootToPeer } from "./vault";

// Browser-side orchestration for QR device pairing (identity plan, "QR
// pairing"). This module owns the network (fetch to the four relay routes), the
// ephemeral X25519 key pair, and the QR render/scan. It NEVER touches raw seed
// bytes: sealing and opening happen inside vault.ts, which reads the root from
// its own memory and returns only the opaque relay body / nothing. That is why
// this module is allowed to do network I/O and the vault is not.
//
// It is deliberately NOT under components/anon-seed/ (the invariants test bans
// network there) — it is a lib module the two pairing pages call.

export class PairClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PairClientError";
  }
}

interface JsonResponse {
  status: number;
  ok: boolean;
  body: Record<string, unknown>;
}

async function postJson(url: string, body?: unknown): Promise<JsonResponse> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
    credentials: "same-origin",
    cache: "no-store",
  });
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await res.json()) as Record<string, unknown>;
  } catch {
    // Non-JSON error body: leave parsed empty; status carries the signal.
  }
  return { status: res.status, ok: res.ok, body: parsed };
}

// ---------------------------------------------------------------------------
// DISPLAY side (the device that NEEDS the root): mint a session, keep the
// ephemeral key pair in memory, render the QR, poll for the sealed payload.
// ---------------------------------------------------------------------------

export interface DisplaySession {
  sessionId: string;
  creatorSecret: string;
  /** ms epoch; the page runs a visible countdown to it. */
  expiresAt: number;
  qrText: string;
  /** The forcing-function code to show the user (S1): they will be asked to type
   * it on the scanning device. Shown here, never compared here. */
  code: string;
  /** Memory-only recipient key pair; the private half never leaves this object,
   * never serialized, never uploaded. */
  keyPair: CryptoKeyPair;
}

/** Create a relay session and build the QR for it. */
export async function startDisplaySession(): Promise<DisplaySession> {
  const res = await postJson("/api/anon/pair/create");
  if (!res.ok || res.body.ok !== true) {
    throw new PairClientError(
      res.status === 401 ? "Sign in first." : "Could not start pairing. Try again.",
    );
  }
  const sessionId = String(res.body.sessionId);
  const creatorSecret = String(res.body.creatorSecret);
  const expiresAt = Date.parse(String(res.body.expiresAt));
  const { keyPair, publicKey } = await generateRecipientKeyPair();
  const qrText = encodePairQr(sessionId, publicKey);
  const code = derivePairCode(sessionId, publicKey);
  return { sessionId, creatorSecret, expiresAt, qrText, code, keyPair };
}

export type ClaimPoll =
  | { status: "waiting" }
  | { status: "received" }
  | { status: "expired" }
  | { status: "error"; message: string };

/**
 * Poll the relay for the sealed payload. On receipt, HANDS THE PAYLOAD TO
 * vault.receiveRootFromPeer, which opens it and loads the root — the raw root
 * never enters this module. `userId`/`epoch` are the display device's OWN server
 * session/enrollment state (C2), never read from the relay.
 */
export async function pollForRoot(
  session: DisplaySession,
  userId: string,
  epoch: number,
): Promise<ClaimPoll> {
  const res = await postJson("/api/anon/pair/claim", {
    sessionId: session.sessionId,
    creatorSecret: session.creatorSecret,
  });
  if (!res.ok || res.body.ok !== true) {
    return { status: "error", message: "Pairing failed. Start again on both devices." };
  }
  const state = String(res.body.state);
  if (state === "expired") return { status: "expired" };
  if (state === "claimed" && typeof res.body.payload === "string" && res.body.payload.length > 0) {
    try {
      await receiveRootFromPeer({
        userId,
        sessionId: session.sessionId,
        recipientKeyPair: session.keyPair,
        relayBody: res.body.payload,
        epoch,
      });
    } catch {
      // A tampered/substituted payload fails GCM here — a hard error, never a
      // silently wrong root. The user must restart on both devices.
      return { status: "error", message: "The received key failed verification. Start again." };
    }
    return { status: "received" };
  }
  return { status: "waiting" };
}

// ---------------------------------------------------------------------------
// SCAN side (the device that HOLDS the root): parse the QR, read peer facts,
// seal to the scanned key, deposit it.
// ---------------------------------------------------------------------------

export interface ScannedQr {
  sessionId: string;
  publicKey: Uint8Array;
  /** The forcing-function code the user must TYPE (S1) — computed here from the
   * scanned QR, shown ONLY on the display device's screen, never compared. */
  code: string;
}

/** Parse scanned text. Returns null for anything that is not a Ministry pairing
 * code (a URL, a foreign QR, a truncated capture). */
export function parseScannedQr(text: string): ScannedQr | null {
  const parsed = parsePairQr(text);
  if (!parsed) return null;
  return {
    sessionId: parsed.sessionId,
    publicKey: parsed.publicKey,
    code: derivePairCode(parsed.sessionId, parsed.publicKey),
  };
}

export interface PeerFacts {
  state: "waiting" | "sealed" | "claimed" | "expired" | "not_found";
  country: string | null;
  city: string | null;
  sameNetworkAsYou: boolean;
  sameCountryAsYou: boolean;
}

/** Read the DISPLAYING device's connection facts (to inform the confirm step).
 * Only the sessionId is sent — never the creator secret. */
export async function fetchPeerFacts(sessionId: string): Promise<PeerFacts | null> {
  const res = await postJson("/api/anon/pair/poll", { sessionId });
  if (!res.ok || res.body.ok !== true) return null;
  const peer = (res.body.peer ?? {}) as Record<string, unknown>;
  return {
    state: String(res.body.state) as PeerFacts["state"],
    country: typeof peer.country === "string" ? peer.country : null,
    city: typeof peer.city === "string" ? peer.city : null,
    sameNetworkAsYou: peer.sameNetworkAsYou === true,
    sameCountryAsYou: peer.sameCountryAsYou === true,
  };
}

export type SealOutcome =
  | { ok: true }
  | {
      ok: false;
      reason: "vault" | "cross_account" | "expired" | "already_used" | "not_found" | "error";
      message: string;
    };

/**
 * Seal this device's root to the scanned key and deposit it. `userId` is the
 * SEALER's OWN authenticated session user and `sessionId` is the OPTICALLY
 * SCANNED value (C2) — neither is read from the relay. vault.sealRootToPeer
 * refuses (S4) unless this device's vault is unlocked and ACTIVE.
 */
export async function sealToPeer(params: {
  userId: string;
  sessionId: string;
  publicKey: Uint8Array;
}): Promise<SealOutcome> {
  let payload: string;
  try {
    payload = await sealRootToPeer({
      userId: params.userId,
      sessionId: params.sessionId,
      recipientPublicKey: params.publicKey,
    });
  } catch {
    return {
      ok: false,
      reason: "vault",
      message: "Unlock your Private Identity on this device before adding another device.",
    };
  }
  const res = await postJson("/api/anon/pair/seal", { sessionId: params.sessionId, payload });
  if (res.ok && res.body.ok === true) return { ok: true };
  const reason = normalizeSealReason(res.body.reason);
  return { ok: false, reason, message: sealErrorCopy(reason) };
}

type SealFailure = "cross_account" | "expired" | "already_used" | "not_found" | "error";

function normalizeSealReason(raw: unknown): SealFailure {
  switch (raw) {
    case "cross_account":
    case "expired":
    case "already_used":
    case "not_found":
      return raw;
    default:
      return "error";
  }
}

/** User-facing copy per seal failure. `cross_account` is the S3 attack warning —
 * blunt on purpose, never "try again". */
export function sealErrorCopy(reason: string): string {
  switch (reason) {
    case "cross_account":
      return "That code belongs to a different Ministry account. If you did not expect this, someone may be trying to take your key. Do not continue.";
    case "expired":
      return "That code expired. Ask the other device to show a fresh one.";
    case "already_used":
      return "That code was already used. Ask the other device to show a fresh one.";
    case "not_found":
      return "That code is not valid. Make sure you scanned the code on your other device.";
    default:
      return "Could not add the device. Try again.";
  }
}

// ---------------------------------------------------------------------------
// QR render + scan (zxing-wasm, lazy-loaded — the wasm never ships in the main
// bundle and only loads on the two pairing pages).
// ---------------------------------------------------------------------------

/** Render a QR payload to a PNG `data:` URL for an `<img src>`. Deliberately not
 * an inline SVG string: this origin can read the root (Lane B), so no code path
 * injects raw HTML, even library-generated markup for our own payload. */
export async function renderQrImageUrl(text: string): Promise<string> {
  const { writeBarcode } = await import("zxing-wasm/writer");
  const result = await writeBarcode(text, { format: "QRCode", scale: 8 });
  if (result.error || !result.image) {
    throw new PairClientError("Could not render the pairing code.");
  }
  return await blobToDataUrl(result.image);
}

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new PairClientError("Could not render the pairing code."));
    reader.readAsDataURL(blob);
  });
}

/** Read a single QR from a captured frame. Returns its text, or null when no
 * valid QR is present in the frame. */
export async function scanQrFromImage(image: ImageData): Promise<string | null> {
  const { readBarcodes } = await import("zxing-wasm/reader");
  const results = await readBarcodes(image, {
    formats: ["QRCode"],
    tryHarder: true,
    maxNumberOfSymbols: 1,
  });
  const hit = results.find((r) => r.isValid && r.text.length > 0);
  return hit?.text ?? null;
}
