import { createHmac } from "node:crypto";

import {
  createHttpsTransport,
  resolvePem,
  type SignetResponse,
  type SignetTransport,
} from "@/lib/nullifier/signet-backend";

// ===========================================================================
// Pairwise-sub backend seam (crypto-core Phase 7 / build-plan §4 Step 0)
// ===========================================================================
//
// Wraps ALL FOUR pairwise derivation families behind one env-selected backend so
// the pairwise `sub` (and the disclosure jti / share-link pseudonyms) can be
// staged out of Minister and into Signet WITHOUT changing runtime behavior at
// merge time:
//
//   MINISTER_SUB_BACKEND = local | shadow | signet-fallback | signet   (default local)
//
//   * local          : compute in-process (today's behavior). The Phase 0 golden
//                      vectors (oidc-claims.pairwise.test.ts) pin every family
//                      byte-exactly.
//   * shadow         : SERVE the local value (users see zero change); fire an
//                      async, non-blocking Signet call and log/metric any
//                      mismatch. Never blocks, never changes the served value.
//   * signet-fallback: SERVE the Signet value with a tight transport budget; on
//                      transport error/timeout compute LOCALLY and ALERT. Because
//                      the two paths are byte-identical (same key bytes, same
//                      tagged input), a fallback event is invisible to users/RPs.
//   * signet         : serve Signet only (used only after OIDC_PAIRWISE_SECRET is
//                      removed from Minister; the env conditional covers the
//                      missing-secret case at that stage).
//
// ── BYTE-IDENTICAL GUARANTEE ───────────────────────────────────────────────
// Signet's /prf/pairwise is a GENERIC keyed-HMAC-SHA256 oracle over an OPAQUE
// input string: it returns base64url(no-pad, HMAC-SHA256(imported secret,
// input.utf8Bytes)). Minister composes the SAME tagged input string it HMACs
// locally and base64url-encodes the result — so the local path and the Signet
// path are byte-for-byte identical for every family, provided:
//   (a) the tagged input string is composed in ONE place (the *Input builders
//       below), used by BOTH the local HMAC and the Signet request; and
//   (b) Signet's imported HMAC key equals the exact UTF-8 bytes Node's
//       createHmac consumes from OIDC_PAIRWISE_SECRET (the Phase 7 import
//       self-test, §4 Step 1).
// The four legacy encodings are FROZEN (guarded by the Phase 0b clientId charset
// guard and the golden vectors):
//   sub           : `${userId}:${clientId}`
//   jti           : `jti:${badgeId}:${clientId}`
//   sharelink sub : `sharelink:${userId}:${shareLinkId}`
//   sharelink jti : `jti:sharelink:${badgeId}:${shareLinkId}`
//
// ── §2.6 CONTRACT ──────────────────────────────────────────────────────────
// The shadow / signet-fallback / signet paths perform mTLS network I/O — NEVER
// call the async family functions inside an open prisma.$transaction. merge.ts
// pre-computes every donor sub through this seam BEFORE its transaction opens.
//
// Logging discipline: never log the derived pairwise values or the tagged input
// (a `sub` is a pseudonymous identifier and the input carries the internal
// userId/badgeId). The default observer records only the family + event.

export type SubBackend = "local" | "shadow" | "signet-fallback" | "signet";

export type PairwiseFamily = "sub" | "jti" | "sharelink-sub" | "sharelink-jti";

// HMAC-SHA256 → 32 bytes → base64url (no padding) = 43 chars.
const PAIRWISE_OUTPUT_LEN = 43;
// Signet caps /prf/pairwise input at 512 bytes (handlers.rs MAX_PAIRWISE_INPUT).
// Reject over-long inputs locally so the local and Signet paths agree on the
// admissible domain instead of diverging on a 400 at the backend flip. Real
// inputs (cuid userId/badgeId + `mc_`-prefixed clientId) are well under this.
const MAX_PAIRWISE_INPUT_BYTES = 512;
const DEFAULT_TIMEOUT_MS = 5_000;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

// ---------------------------------------------------------------------------
// Tagged-input builders — the SINGLE source of truth for the frozen encodings.
// Both the local HMAC and the Signet /prf/pairwise request compose their bytes
// from these, so the two paths can never drift.
// ---------------------------------------------------------------------------

export function pairwiseSubInput(userId: string, clientId: string): string {
  return `${userId}:${clientId}`;
}

export function pairwiseJtiInput(badgeId: string, clientId: string): string {
  return `jti:${badgeId}:${clientId}`;
}

export function shareLinkPairwiseSubInput(userId: string, shareLinkId: string): string {
  return `sharelink:${userId}:${shareLinkId}`;
}

export function shareLinkPairwiseJtiInput(badgeId: string, shareLinkId: string): string {
  return `jti:sharelink:${badgeId}:${shareLinkId}`;
}

// ---------------------------------------------------------------------------
// Local derivation (the frozen, golden-pinned byte truth)
// ---------------------------------------------------------------------------

function pairwiseSecret(): string {
  // No AUTH_SECRET fallback: a silent fallback would re-key every pairwise
  // value if OIDC_PAIRWISE_SECRET were ever unset. Fail fast (env.ts also
  // requires it at boot; read here directly so tests can inject it, like the
  // nullifier backends).
  const secret = process.env.OIDC_PAIRWISE_SECRET;
  if (!secret) {
    throw new Error("OIDC_PAIRWISE_SECRET must be set");
  }
  return secret;
}

// base64url(no-pad, HMAC-SHA256(secret, input.utf8Bytes)) — byte-identical to
// Signet's /prf/pairwise output for the same input. This IS the `local` path and
// the byte-identical fallback for `signet-fallback`.
export function deriveLocalPairwise(input: string): string {
  return createHmac("sha256", pairwiseSecret()).update(input).digest("base64url");
}

// ---------------------------------------------------------------------------
// Observer (telemetry seam) — mismatch / fallback signals, values never logged
// ---------------------------------------------------------------------------

export interface PairwiseObserver {
  // shadow: the async Signet value differed from the served local value. This is
  // the load-bearing pre-cutover signal — the equivalence proof (§4).
  onShadowMismatch(info: { family: PairwiseFamily }): void;
  // shadow: the async Signet call itself failed (not a value mismatch).
  onShadowError(info: { family: PairwiseFamily; error: string }): void;
  // signet-fallback: Signet errored/timed out; the byte-identical local value
  // was served instead. Must alert (§4 Step 3) even though it is invisible.
  onFallback(info: { family: PairwiseFamily; error: string }): void;
}

const defaultObserver: PairwiseObserver = {
  onShadowMismatch: ({ family }) =>
    console.error(
      `[pairwise] shadow MISMATCH for family ${family}: Signet output differs from the served local value`,
    ),
  onShadowError: ({ family, error }) =>
    console.warn(`[pairwise] shadow compare error for family ${family}: ${error}`),
  onFallback: ({ family, error }) =>
    console.error(
      `[pairwise] signet-fallback engaged for family ${family} (byte-identical local value served): ${error}`,
    ),
};

let observer: PairwiseObserver = defaultObserver;

// ---------------------------------------------------------------------------
// Backend selection (read per-call so tests can flip the flag)
// ---------------------------------------------------------------------------

function selectSubBackend(): SubBackend {
  const v = process.env.MINISTER_SUB_BACKEND ?? "local";
  if (v === "local" || v === "shadow" || v === "signet-fallback" || v === "signet") {
    return v;
  }
  throw new Error(`Unknown MINISTER_SUB_BACKEND: ${v}`);
}

// ---------------------------------------------------------------------------
// Signet transport (lazy; injectable for the offline unit suite)
// ---------------------------------------------------------------------------

let transportOverride: SignetTransport | null = null;
let realTransport: SignetTransport | null = null;

function pairwiseTransportConfig(): {
  baseUrl: string;
  clientCert: string;
  clientKey: string;
  caCert: string;
  requestTimeoutMs: number;
} {
  const need = (key: string): string => {
    const val = process.env[key];
    if (!val) {
      throw new Error(`pairwise: ${key} must be set (signet sub backend)`);
    }
    return val;
  };
  const baseUrl = need("MINISTER_SIGNET_URL");
  if (!baseUrl.startsWith("https://")) {
    throw new Error("pairwise: MINISTER_SIGNET_URL must be an https:// URL (mTLS-only)");
  }
  let requestTimeoutMs = DEFAULT_TIMEOUT_MS;
  const raw = process.env.MINISTER_SIGNET_TIMEOUT_MS;
  if (raw !== undefined && raw !== "") {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 100 || n > 15_000) {
      throw new Error(
        "pairwise: MINISTER_SIGNET_TIMEOUT_MS must be an integer between 100 and 15000",
      );
    }
    requestTimeoutMs = n;
  }
  return {
    baseUrl,
    clientCert: resolvePem(need("MINISTER_SIGNET_CLIENT_CERT"), "MINISTER_SIGNET_CLIENT_CERT"),
    clientKey: resolvePem(need("MINISTER_SIGNET_CLIENT_KEY"), "MINISTER_SIGNET_CLIENT_KEY"),
    caCert: resolvePem(need("MINISTER_SIGNET_CA_CERT"), "MINISTER_SIGNET_CA_CERT"),
    requestTimeoutMs,
  };
}

function transport(): SignetTransport {
  if (transportOverride) return transportOverride;
  if (!realTransport) {
    realTransport = createHttpsTransport(pairwiseTransportConfig());
  }
  return realTransport;
}

// One /prf/pairwise round trip → the validated 43-char base64url output.
async function signetPairwise(input: string): Promise<string> {
  const res: SignetResponse = await transport()("POST", "/prf/pairwise", { input });
  if (res.status !== 200) {
    throw new Error(`pairwise: signet /prf/pairwise returned ${res.status}`);
  }
  if (typeof res.json !== "object" || res.json === null) {
    throw new Error("pairwise: signet returned a non-object body");
  }
  const output = (res.json as Record<string, unknown>).output;
  if (typeof output !== "string") {
    throw new Error("pairwise: signet response lacks a string output field");
  }
  if (output.length !== PAIRWISE_OUTPUT_LEN || !B64URL_RE.test(output)) {
    throw new Error("pairwise: signet returned a malformed pairwise output");
  }
  return output;
}

// ---------------------------------------------------------------------------
// Shadow compare (fire-and-forget; awaitable in tests)
// ---------------------------------------------------------------------------

const inFlightShadow = new Set<Promise<void>>();

function startShadowCompare(family: PairwiseFamily, input: string, local: string): void {
  const run = (async () => {
    try {
      const remote = await signetPairwise(input);
      if (remote !== local) {
        observer.onShadowMismatch({ family });
      }
    } catch (err) {
      observer.onShadowError({
        family,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  })();
  const tracked = run.finally(() => {
    inFlightShadow.delete(tracked);
  });
  inFlightShadow.add(tracked);
}

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

function capInput(input: string): void {
  const len = Buffer.byteLength(input, "utf8");
  if (len === 0 || len > MAX_PAIRWISE_INPUT_BYTES) {
    throw new Error(
      `pairwise: tagged input length ${len} out of range (1..${MAX_PAIRWISE_INPUT_BYTES})`,
    );
  }
}

async function derivePairwise(family: PairwiseFamily, input: string): Promise<string> {
  capInput(input);
  const backend = selectSubBackend();

  if (backend === "local") {
    return deriveLocalPairwise(input);
  }

  if (backend === "shadow") {
    // SERVE local; compare against Signet asynchronously (never block, never
    // change the served value).
    const local = deriveLocalPairwise(input);
    startShadowCompare(family, input, local);
    return local;
  }

  if (backend === "signet-fallback") {
    try {
      return await signetPairwise(input);
    } catch (err) {
      // Byte-identical local fallback + ALERT: invisible to users/RPs.
      observer.onFallback({
        family,
        error: err instanceof Error ? err.message : String(err),
      });
      return deriveLocalPairwise(input);
    }
  }

  // signet: Signet only. The env conditional (Phase 7c) covers the removed
  // secret; here a Signet failure is a hard failure, by design (Tier-0).
  return signetPairwise(input);
}

export function derivePairwiseSub(userId: string, clientId: string): Promise<string> {
  return derivePairwise("sub", pairwiseSubInput(userId, clientId));
}

export function derivePairwiseJti(badgeId: string, clientId: string): Promise<string> {
  return derivePairwise("jti", pairwiseJtiInput(badgeId, clientId));
}

export function deriveShareLinkPairwiseSub(userId: string, shareLinkId: string): Promise<string> {
  return derivePairwise("sharelink-sub", shareLinkPairwiseSubInput(userId, shareLinkId));
}

export function deriveShareLinkPairwiseJti(badgeId: string, shareLinkId: string): Promise<string> {
  return derivePairwise("sharelink-jti", shareLinkPairwiseJtiInput(badgeId, shareLinkId));
}

// ---------------------------------------------------------------------------
// Test seams (offline; disabled in production)
// ---------------------------------------------------------------------------

export function _setPairwiseTransportForTests(t: SignetTransport | null): void {
  if (process.env.NODE_ENV === "production") {
    throw new Error("pairwise: _setPairwiseTransportForTests is disabled in production");
  }
  transportOverride = t;
  // Drop any real transport built from a prior config so the next call rebuilds.
  realTransport = null;
}

export function _setPairwiseObserverForTests(o: PairwiseObserver | null): void {
  if (process.env.NODE_ENV === "production") {
    throw new Error("pairwise: _setPairwiseObserverForTests is disabled in production");
  }
  observer = o ?? defaultObserver;
}

// Await every in-flight shadow compare — shadow fires-and-forgets, so a test
// that asserts on the mismatch/error signal must flush first.
export async function _flushPairwiseShadowForTests(): Promise<void> {
  await Promise.all([...inFlightShadow]);
}
