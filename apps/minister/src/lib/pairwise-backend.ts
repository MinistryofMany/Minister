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
// The pairwise seam runs on the HOT token-mint / userinfo / share-render path;
// build-plan §4 Step 3 mandates a TIGHT budget so a Signet brownout falls back
// (byte-identically) fast rather than stalling every mint up to the nullifier
// backend's multi-second budget. This deadline is DECOUPLED from the nullifier
// backend's MINISTER_SIGNET_TIMEOUT_MS (whose 15s cap is sized for the VOPRF
// advisory-lock lifetime arithmetic) so tuning one can never squeeze the other.
const DEFAULT_PAIRWISE_TIMEOUT_MS = 500;
const MIN_PAIRWISE_TIMEOUT_MS = 100;
const MAX_PAIRWISE_TIMEOUT_MS = 2_000;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
// Bound on concurrent in-flight shadow compares. Shadow compares are launched
// from partially attacker-drivable paths (an unauthenticated share-link render
// fires 1 sub + N jti compares; every token/userinfo mint fires more), so an
// uncapped fire-and-forget would open unbounded mTLS sockets and trip Signet's
// shared PRF rate bucket, turning the soak into error noise and adding pressure
// on real VOPRF issuance. Over the cap the compare is SKIPPED and counted, never
// blocking the served (local) value.
const MAX_INFLIGHT_SHADOW = 64;

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
  // shadow: the async Signet value MATCHED the served local value. A SUCCESS
  // count is required, not just the absence of mismatches: §4 Step 2's exit gate
  // is "successful compares == derivations across the matrix AND 0 mismatches".
  // Without it a shadow deploy whose every compare ERRORS (missing transport env,
  // PRF 403, rate-limit) reports zero mismatches and masquerades as a passed
  // equivalence proof — a silently vacuous soak.
  onShadowCompareOk(info: { family: PairwiseFamily }): void;
  // shadow: the async Signet call itself failed (not a value mismatch).
  onShadowError(info: { family: PairwiseFamily; error: string }): void;
  // shadow: the in-flight cap was reached, so this derivation's compare was
  // SKIPPED (never launched). Counted so a saturated shadow path is visible and
  // soak coverage stays measurable rather than a silent hole.
  onShadowSkipped(info: { family: PairwiseFamily }): void;
  // signet-fallback: Signet returned a well-formed value that DIFFERED from the
  // byte-identical local truth. /prf/pairwise carries no DLEQ, so this is the
  // ONLY drift detector this endpoint will ever have; because Signet is not yet
  // authoritative (pre-7c) and byte-stability is the cutover-reversibility
  // invariant, the LOCAL value is served and this fires.
  onServeMismatch(info: { family: PairwiseFamily }): void;
  // signet-fallback: Signet errored/timed out; the byte-identical local value
  // was served instead. Must alert (§4 Step 3) even though it is invisible.
  onFallback(info: { family: PairwiseFamily; error: string }): void;
}

const defaultObserver: PairwiseObserver = {
  onShadowMismatch: ({ family }) =>
    console.error(
      `[pairwise] shadow MISMATCH for family ${family}: Signet output differs from the served local value`,
    ),
  // Success is the common case; default to silent (metrics-only), the runbook
  // reads the count off a real observer during the soak.
  onShadowCompareOk: () => {},
  onShadowError: ({ family, error }) =>
    console.warn(`[pairwise] shadow compare error for family ${family}: ${error}`),
  onShadowSkipped: ({ family }) =>
    console.warn(
      `[pairwise] shadow compare SKIPPED for family ${family} (in-flight cap ${MAX_INFLIGHT_SHADOW} reached)`,
    ),
  onServeMismatch: ({ family }) =>
    console.error(
      `[pairwise] signet-fallback SERVE MISMATCH for family ${family}: Signet output differs from local; serving the byte-identical local value (Signet not authoritative pre-7c)`,
    ),
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
  // Own deadline knob (MINISTER_SIGNET_PAIRWISE_TIMEOUT_MS), NOT the nullifier
  // backend's MINISTER_SIGNET_TIMEOUT_MS: the hot pairwise path wants a tight
  // budget (default 500ms) and must be tunable without disturbing the VOPRF
  // path's 5-15s advisory-lock arithmetic.
  let requestTimeoutMs = DEFAULT_PAIRWISE_TIMEOUT_MS;
  const raw = process.env.MINISTER_SIGNET_PAIRWISE_TIMEOUT_MS;
  if (raw !== undefined && raw !== "") {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < MIN_PAIRWISE_TIMEOUT_MS || n > MAX_PAIRWISE_TIMEOUT_MS) {
      throw new Error(
        `pairwise: MINISTER_SIGNET_PAIRWISE_TIMEOUT_MS must be an integer between ${MIN_PAIRWISE_TIMEOUT_MS} and ${MAX_PAIRWISE_TIMEOUT_MS}`,
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
  // Fail-open on saturation: never queue or block the served value. A skipped
  // compare is counted (soak coverage stays measurable) and the local value the
  // caller already holds is returned unchanged by derivePairwise.
  if (inFlightShadow.size >= MAX_INFLIGHT_SHADOW) {
    observer.onShadowSkipped({ family });
    return;
  }
  const run = (async () => {
    try {
      const remote = await signetPairwise(input);
      if (remote !== local) {
        observer.onShadowMismatch({ family });
      } else {
        observer.onShadowCompareOk({ family });
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
    // Compute the local golden truth up front. The local secret is still present
    // in this mode (env.ts keeps OIDC_PAIRWISE_SECRET required until 7c), so this
    // is one cheap in-process HMAC — and it makes the mode measurable AND safe:
    //   * transport error/timeout → serve local + onFallback (byte-identical);
    //   * well-formed but DRIFTED Signet value → serve LOCAL + onServeMismatch.
    // /prf/pairwise has no DLEQ, so compare-to-local is the only drift detector
    // that can exist here; and since Signet is not authoritative pre-7c, serving
    // the local value on divergence is what preserves the byte-identical
    // guarantee the cutover reversibility depends on.
    const local = deriveLocalPairwise(input);
    try {
      const remote = await signetPairwise(input);
      if (remote !== local) {
        observer.onServeMismatch({ family });
        return local;
      }
      return remote;
    } catch (err) {
      observer.onFallback({
        family,
        error: err instanceof Error ? err.message : String(err),
      });
      return local;
    }
  }

  // signet: Signet only. The env conditional (Phase 7c) covers the removed
  // secret; here a Signet failure is a hard failure, by design (Tier-0).
  return signetPairwise(input);
}

export function derivePairwiseSub(userId: string, clientId: string): Promise<string> {
  return derivePairwise("sub", pairwiseSubInput(userId, clientId));
}

// A pairwise sub PERSISTED at account merge (SubjectOverride) is frozen forever:
// resolveSub's override short-circuit means no later shadow compare, token mint,
// or re-derivation ever recomputes it, so a wrong value can never self-heal the
// way an ordinary per-mint sub does. A transient/compromised Signet returning a
// well-formed-but-WRONG sub at merge time would therefore permanently re-key the
// donor's identity at that RP, invisibly. While the local secret is still
// present (pre-7c) a byte-equal crosscheck against the golden truth is free:
// derive through the seam, then — only if OIDC_PAIRWISE_SECRET is set — re-derive
// locally and THROW on any mismatch (the merge aborts fail-closed and is safe to
// retry). Post-7c the secret is gone; this degrades to the seam value with the
// documented Signet-trust residual. In shadow / signet-fallback / local modes
// the seam already returns the local value, so the crosscheck is a no-op; it
// only bites in pure `signet` mode, which is exactly the residual it closes.
export async function derivePairwiseSubForPersistence(
  userId: string,
  clientId: string,
): Promise<string> {
  const input = pairwiseSubInput(userId, clientId);
  const served = await derivePairwise("sub", input);
  if (process.env.OIDC_PAIRWISE_SECRET) {
    const local = deriveLocalPairwise(input);
    if (served !== local) {
      throw new Error(
        "pairwise: merge-time sub crosscheck failed — the backend-served sub diverges from the local golden value; aborting merge (safe to retry)",
      );
    }
  }
  return served;
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
