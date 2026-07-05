import { readFileSync } from "node:fs";
import { Agent, request as httpsRequest } from "node:https";

import { Evaluation, Oprf, VOPRFClient } from "@cloudflare/voprf-ts";
import { CryptoNoble } from "@cloudflare/voprf-ts/crypto-noble";

import type { Prisma } from "@/generated/prisma";

import { buildVoprfDedupInput, capClientId } from "./encoding";
import type { MinisterGatingNullifier, NullifierService, RegisterDedupResult } from "./index";
import { getLockClient } from "./lock-client";

// SIGNET Sybil-dedup backend (crypto-core Phase 3).
//
// Implements the FROZEN NullifierService interface over Signet's PRF/dedup
// surface (RFC 9497 VOPRF, mode 0x01, ristretto255-SHA512):
//
//   registerDedup : LP-encode the stage-1 input -> blind -> POST /prf/evaluate
//                   -> DLEQ-verify against the PINNED public key -> finalize
//                   N_dedup -> POST /dedup/register (owner_tag = the caller's
//                   User.dedupHandle). Signet never sees the raw anchor.
//   disclose      : POST /prf/disclose (owner-checked inside Signet) -> mnv1:…
//   release       : Minister-side serialized sibling-guarded delete (below).
//   reassignOwner : per-ref POST /dedup/reassign.
//
// Crypto stack, pinned EXACT: @cloudflare/voprf-ts 1.0.0 with the @noble
// CryptoProvider — the same client stack the Signet-side interop harness
// (Signet/interop/prf.mjs) proved byte-equal against the Rust `voprf` crate
// on the frozen ecosystem vectors (prf-vectors.json, committed to both repos).
//
// PINNED PUBLIC KEY (fail-closed, mirrors the ISSUER_KMS_PUBLIC_JWK pattern):
// MINISTER_SIGNET_DEDUP_PUBKEY holds pkS from `signet init-service-keys`. At
// BOOT (instrumentation.ts, when the signet backend is selected) and again on
// first use the backend fetches GET /prf/public-key and refuses to operate on
// any mismatch — a mis-pinned deploy dies at boot, not on the first user's
// mint. Independently, every finalize() DLEQ-verifies the evaluation against
// the PIN (never the fetched value), so a compromised or forked Signet cannot
// poison the permanent dedup namespace even mid-process.
//
// RELEASE ATOMICITY ACROSS THE SPLIT (build plan Phase 3 item 1): the interim
// backend closes the delete-vs-reissue dedup bypass with ONE atomic
// conditional DELETE — possible only because NullifierEntry and Badge share
// Minister's Postgres. Signet's /dedup/release is an unconditional
// owner-checked delete, so the sibling check (Minister) and the delete
// (Signet) are separated by a network round trip. This backend re-establishes
// equivalent atomicity with MINISTER-SIDE SERIALIZATION: a Postgres advisory
// lock keyed on the entryRef is held across BOTH critical sections —
//   * release: [fresh sibling check -> POST /dedup/release]   (here), and
//   * mint:    [badge INSERT -> mint-side re-validation probe] (wizard.ts via
//     serializeMintWindow -> withSignetEntryLock).
// The two sections are therefore totally ordered per entryRef: a release that
// runs after a mint sees the committed badge and SKIPS the delete; a release
// that runs before it deletes the entry, and the mint's probe then sees it
// gone and self-heals by re-registering. The Case-A ordering (a release
// firing after the probe returned true) is impossible under the lock. No
// Signet-side change is required for correctness; a Signet-side
// compare-and-release (refcount / generation token) remains a nice-to-have
// hardening if Minister ever scales beyond one Postgres.
//
// §2.6 CONTRACT: every method here performs network I/O — NEVER call any of
// them inside an open prisma.$transaction. The advisory-lock transaction used
// internally is a dedicated, self-contained serialization primitive, not an
// exception to the call-site rule — and it runs on its OWN PrismaClient with
// a small dedicated pool (lock-client.ts), so holding a lock across a Signet
// round trip can never pin a shared-pool connection (see lock-client.ts for
// the bulkhead rationale and sizing).
//
// LOCK-LIFETIME ARITHMETIC (why the guarded window cannot outlive the lock):
// pg_advisory_xact_lock dies with its transaction, so if the lock transaction
// were rolled back (timeout) while the guarded callback kept running, the
// critical section would continue WITHOUT mutual exclusion. Three bounds keep
// that window closed:
//   * lock acquisition is capped by `SET LOCAL lock_timeout = '20s'`, so a
//     queued contender can never silently consume the transaction budget;
//   * every Signet round trip has an ABSOLUTE transport deadline
//     (requestTimeoutMs, env-capped at MAX_TIMEOUT_MS — not an inactivity
//     timer, so a slow-dripping response cannot stretch it);
//   * the guarded code re-proves the lock transaction is alive (a SELECT 1 on
//     the lock tx, which throws once the tx is gone) immediately before the
//     unguarded Signet delete in release(), and after the mint-window probe
//     (wizard.ts) — so an evaporated lock aborts the operation fail-closed
//     instead of running the critical action outside mutual exclusion.
// Worst case: lock wait (20s) + sibling count + one capped round trip (≤15s)
// ≪ the 60s transaction timeout, with >20s of slack for DB stalls.
//
// Logging: never log anchors, blinded elements, evaluation outputs, disclosed
// nullifiers, or PEM material. Errors carry statuses and refs only (refs are
// opaque random handles).

const SUITE = Oprf.Suite.RISTRETTO255_SHA512;
const VOPRF_MODE = Oprf.Mode.VOPRF;

const ELEMENT_LEN = 32;
const PROOF_LEN = 64;
const DEDUP_VALUE_LEN = 64;
const PIN_B64URL_LEN = 43; // base64url(32 bytes), no padding

// Probe identity for entryExistsForOwner: /prf/disclose IS the owner-checked
// ref lookup on Signet's surface (200 = exists+owned, 404 = gone, 403 = owned
// by someone else); the derived probe nullifier is discarded. The colon makes
// this id impossible to collide with a real RP clientId (real ids are
// mc_ + base64url, charset-guarded — no colon can occur).
const PROBE_CLIENT_ID = "minister:mint-probe:v1";

// Absolute per-request deadline bounds. The cap matters for the lock-lifetime
// arithmetic above: a guarded window's Signet call must finish (or die) well
// inside the lock transaction's 60s budget. env.ts enforces the same range at
// boot; configFromEnv re-checks because tests inject process.env directly.
const DEFAULT_TIMEOUT_MS = 5_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 15_000;

// Largest legitimate Signet response is well under 1 KB; a compromised or
// broken Signet must not be able to stream unbounded data into the heap.
const MAX_RESPONSE_BYTES = 8 * 1024;

// The disclosed-value shape, checked fail-closed before anything trusts it.
const NULLIFIER_RE = /^mnv1:[A-Za-z0-9_-]{43}$/;

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export interface SignetBackendConfig {
  baseUrl: string;
  // PEM strings (already resolved — see resolvePem for the env layer).
  clientCert: string;
  clientKey: string;
  caCert: string;
  // pkS in the pin encoding (base64url no padding, 43 chars).
  pinnedPublicKey: string;
  requestTimeoutMs?: number;
}

export interface SignetResponse {
  status: number;
  json: unknown;
}

// The transport seam: one mTLS JSON round trip. Injectable so the offline
// unit suite can stand in a scripted Signet without any network.
export type SignetTransport = (
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) => Promise<SignetResponse>;

// Resolve a PEM value given either inline (starts with "-----BEGIN") or as a
// filesystem path (a compose mount). Mirrors FreedInk's signet config layer.
// A read error surfaces loudly — a misconfigured cert path must never
// silently degrade.
function resolvePem(value: string, name: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("-----BEGIN")) return value;
  try {
    return readFileSync(trimmed, "utf8");
  } catch (err) {
    throw new Error(
      `nullifier: ${name} is neither inline PEM nor a readable file path: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

// node:https mTLS transport (keep-alive Agent holding the client identity),
// lifted from the proven RemoteSigner shape in @ministryofmany/blind-token.
// rejectUnauthorized stays true so a future edit can't silently disable
// server-cert verification. Never logs request or response bodies.
function createHttpsTransport(cfg: {
  baseUrl: string;
  clientCert: string;
  clientKey: string;
  caCert: string;
  requestTimeoutMs: number;
}): SignetTransport {
  const agent = new Agent({
    cert: cfg.clientCert,
    key: cfg.clientKey,
    ca: cfg.caCert,
    keepAlive: true,
    rejectUnauthorized: true,
  });
  const base = cfg.baseUrl.replace(/\/$/, "");

  return (method, path, body) => {
    const url = new URL(base + path);
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    return new Promise<SignetResponse>((resolve, reject) => {
      const req = httpsRequest(
        {
          method,
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          agent,
          headers: {
            accept: "application/json",
            ...(payload
              ? { "content-type": "application/json", "content-length": String(payload.length) }
              : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let received = 0;
          res.on("data", (c: Buffer) => {
            received += c.length;
            if (received > MAX_RESPONSE_BYTES) {
              // Fail-closed size cap: destroy() surfaces this error via the
              // request's error handler below.
              req.destroy(
                new Error(`nullifier: signet response exceeded ${MAX_RESPONSE_BYTES} bytes`),
              );
              return;
            }
            chunks.push(c);
          });
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let parsed: unknown = null;
            if (text.length > 0) {
              try {
                parsed = JSON.parse(text);
              } catch {
                parsed = null; // non-JSON body; callers treat as failure
              }
            }
            resolve({ status: res.statusCode ?? 0, json: parsed });
          });
        },
      );
      // ABSOLUTE deadline, distinct from the inactivity timer below: a Signet
      // that drips one byte per second resets an inactivity timer forever but
      // cannot outlive this — essential while a mint window or release holds
      // the advisory lock (see the lock-lifetime arithmetic in the module
      // doc). Cleared on 'close', which fires on completion and on abort.
      const deadline = setTimeout(() => {
        req.destroy(new Error("nullifier: signet request exceeded the absolute deadline"));
      }, cfg.requestTimeoutMs);
      req.on("close", () => clearTimeout(deadline));
      req.on("error", reject);
      // A hung Signet must not wedge a request thread (or a mint window that
      // is holding the advisory lock) forever.
      req.setTimeout(cfg.requestTimeoutMs, () => {
        req.destroy(new Error("Signet request timed out"));
      });
      if (payload) req.write(payload);
      req.end();
    });
  };
}

// Read + validate the backend config from env. Read directly from
// process.env (like the interim backend's key resolution) so tests can
// inject values; env.ts additionally fail-fast-validates presence at boot
// when MINISTER_NULLIFIER_BACKEND=signet.
function configFromEnv(): SignetBackendConfig {
  const need = (key: string): string => {
    const v = process.env[key];
    if (!v) {
      throw new Error(`nullifier: ${key} must be set (signet backend)`);
    }
    return v;
  };
  const baseUrl = need("MINISTER_SIGNET_URL");
  if (!baseUrl.startsWith("https://")) {
    // The transport is hardwired to node:https (mTLS-only, no plaintext
    // fallback); reject a non-https URL with a legible error instead of an
    // opaque TLS handshake failure against a plaintext port.
    throw new Error("nullifier: MINISTER_SIGNET_URL must be an https:// URL (mTLS-only)");
  }
  let requestTimeoutMs: number | undefined;
  const rawTimeout = process.env.MINISTER_SIGNET_TIMEOUT_MS;
  if (rawTimeout !== undefined && rawTimeout !== "") {
    const n = Number(rawTimeout);
    // Bounded: 0/NaN would disable or corrupt the timers, and anything past
    // MAX_TIMEOUT_MS breaks the lock-lifetime arithmetic (module doc).
    if (!Number.isInteger(n) || n < MIN_TIMEOUT_MS || n > MAX_TIMEOUT_MS) {
      throw new Error(
        `nullifier: MINISTER_SIGNET_TIMEOUT_MS must be an integer between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
      );
    }
    requestTimeoutMs = n;
  }
  return {
    baseUrl,
    clientCert: resolvePem(need("MINISTER_SIGNET_CLIENT_CERT"), "MINISTER_SIGNET_CLIENT_CERT"),
    clientKey: resolvePem(need("MINISTER_SIGNET_CLIENT_KEY"), "MINISTER_SIGNET_CLIENT_KEY"),
    caCert: resolvePem(need("MINISTER_SIGNET_CA_CERT"), "MINISTER_SIGNET_CA_CERT"),
    pinnedPublicKey: need("MINISTER_SIGNET_DEDUP_PUBKEY"),
    requestTimeoutMs,
  };
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function b64urlDecode(value: string, name: string, expectedLen: number): Uint8Array {
  if (!B64URL_RE.test(value)) {
    throw new Error(`nullifier: signet returned a non-base64url ${name}`);
  }
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== expectedLen) {
    throw new Error(
      `nullifier: signet returned ${name} of ${raw.length} bytes (expected ${expectedLen})`,
    );
  }
  return new Uint8Array(raw);
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new Error("nullifier: signet returned a non-object body");
  }
  return value as Record<string, unknown>;
}

function stringField(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== "string") {
    throw new Error(`nullifier: signet response lacks string field ${key}`);
  }
  return v;
}

// Advisory-lock serialization for the mint window and the release critical
// section (see the module doc). Transaction-scoped (pg_advisory_xact_lock):
// the lock releases automatically on commit OR abort, so there is no unlock
// path to miss on a throw. Runs on the DEDICATED lock client (lock-client.ts)
// so a held lock never pins a shared-pool connection; the callback receives
// the lock transaction so it can (a) run reads whose ordering the lock must
// guarantee (release's sibling count) and (b) re-prove the lock is alive
// before an unguarded side effect (see the lock-lifetime arithmetic in the
// module doc). Advisory locks are global across the database, so a holder on
// one connection blocks an acquirer on any other.
//
// Sizing: the guarded windows are one badge INSERT + one Signet round trip
// (mint) or one sibling count + one Signet round trip (release); the Signet
// call is bounded by the ABSOLUTE transport deadline. lock_timeout (LOCK_WAIT)
// bounds how long a contender queues for the lock; timeout bounds the whole
// held window.
const LOCK_NAMESPACE = "minister:nullifier:entry:";

export async function withSignetEntryLock<T>(
  entryRef: string,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  const key = LOCK_NAMESPACE + entryRef;
  return getLockClient().$transaction(
    async (tx) => {
      try {
        // Cap the queue time so a contender cannot silently consume the
        // transaction budget while blocked on the lock (module doc).
        await tx.$executeRaw`SET LOCAL lock_timeout = '20s'`;
        // hashtextextended maps the ref to a stable bigint lock key; the
        // namespace prefix keeps this lock space disjoint from any other
        // advisory-lock user. Parameterized — never interpolated. The ::text
        // cast matters: the lock function returns `void`, which Prisma's
        // $queryRaw cannot deserialize (caught by the live fixture suite).
        await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))::text`;
      } catch (err) {
        // Nullifier-prefixed so the wizard maps it to a retryable user-facing
        // error. Refs are opaque; the underlying message carries no secrets.
        throw new Error(
          `nullifier: failed to acquire the signet entry lock (${
            err instanceof Error ? err.message.slice(0, 200) : String(err)
          })`,
        );
      }
      return fn(tx);
    },
    { maxWait: 10_000, timeout: 60_000 },
  );
}

export interface SignetNullifierBackend extends NullifierService {
  // Exposed for the live fixture suite (CI): the exact stage-1 path
  // registerDedup runs — blind -> evaluate -> DLEQ verify -> finalize —
  // returning the raw 64-byte N_dedup for byte-comparison against the frozen
  // ecosystem vectors. Never used by production callers (the value must not
  // land anywhere in Minister at rest).
  evaluateDedupValue(anchor: string, badgeType: string): Promise<Uint8Array>;
  // Boot/readiness hook: fetch GET /prf/public-key and verify it against the
  // pinned MINISTER_SIGNET_DEDUP_PUBKEY, fail-closed. Called from
  // instrumentation.ts when the signet backend is selected so a mis-pinned
  // deploy (or wrong URL / bad mTLS material) dies at boot instead of on the
  // first user's mint. Every operation re-runs the same check lazily (success
  // memoized, failure not), and every finalize independently DLEQ-verifies
  // against the pin — this hook is the ops-legible guard, not the only one.
  verifyPin(): Promise<void>;
}

export function createSignetBackend(
  configOverride?: SignetBackendConfig,
  transportOverride?: SignetTransport,
): SignetNullifierBackend {
  // All lazy: reading env / cert files / building the Agent happens on first
  // use, never at import (the module is imported unconditionally by the
  // backend selector while the default backend is interim).
  let cfg: SignetBackendConfig | null = configOverride ?? null;
  let transport: SignetTransport | null = transportOverride ?? null;
  let pinBytes: Uint8Array | null = null;
  let pinVerified = false;

  const config = (): SignetBackendConfig => {
    if (!cfg) cfg = configFromEnv();
    return cfg;
  };

  const pin = (): Uint8Array => {
    if (!pinBytes) {
      const p = config().pinnedPublicKey.trim();
      if (p.length !== PIN_B64URL_LEN || !B64URL_RE.test(p)) {
        throw new Error(
          "nullifier: MINISTER_SIGNET_DEDUP_PUBKEY is not a 43-char base64url pin (pkS)",
        );
      }
      pinBytes = b64urlDecode(p, "pinned public key", ELEMENT_LEN);
    }
    return pinBytes;
  };

  const send = (method: "GET" | "POST", path: string, body?: unknown): Promise<SignetResponse> => {
    if (!transport) {
      const c = config();
      transport = createHttpsTransport({
        baseUrl: c.baseUrl,
        clientCert: c.clientCert,
        clientKey: c.clientKey,
        caCert: c.caCert,
        requestTimeoutMs: c.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      });
    }
    return transport(method, path, body);
  };

  // Boot-time fetch-and-verify of the pinned public key, fail-closed —
  // the ISSUER_KMS_PUBLIC_JWK pattern. Success is memoized; a mismatch or a
  // fetch failure is NOT (a transient outage may recover; a mismatch keeps
  // refusing on every call). Every VOPRF finalize additionally verifies the
  // DLEQ proof against the PIN itself, so this check is the ops-legible
  // guard, not the only one.
  const ensurePinVerified = async (): Promise<void> => {
    if (pinVerified) return;
    const expected = config().pinnedPublicKey.trim();
    pin(); // validate the pin shape before trusting anything
    const res = await send("GET", "/prf/public-key");
    if (res.status !== 200) {
      throw new Error(`nullifier: signet /prf/public-key returned ${res.status} (fail closed)`);
    }
    const body = asRecord(res.json);
    const suite = stringField(body, "suite");
    const served = stringField(body, "public_key");
    if (suite !== "ristretto255-SHA512") {
      throw new Error(
        `nullifier: signet serves VOPRF suite ${suite}, expected ristretto255-SHA512`,
      );
    }
    if (served !== expected) {
      // Both values are public keys — safe to surface for ops.
      throw new Error(
        `nullifier: signet public key ${served} does not match the pinned ` +
          `MINISTER_SIGNET_DEDUP_PUBKEY ${expected}; refusing to operate (key-fork guard)`,
      );
    }
    pinVerified = true;
  };

  const evaluateDedupValue = async (anchor: string, badgeType: string): Promise<Uint8Array> => {
    // Cheap local validation (field caps) BEFORE any network round trip.
    const input = buildVoprfDedupInput(anchor, badgeType);
    await ensurePinVerified();
    // The client is constructed with the PINNED key: finalize() verifies the
    // server's DLEQ proof against it and throws on any mismatch, so an
    // evaluation under a different key can never become a persisted value.
    const client = new VOPRFClient(SUITE, pin(), CryptoNoble);
    const [finData, evalReq] = await client.blind([new Uint8Array(input)]);
    const blinded = evalReq.blinded[0];
    if (!blinded) {
      throw new Error("nullifier: VOPRF blind produced no element");
    }
    const res = await send("POST", "/prf/evaluate", {
      blinded_element: b64url(blinded.serialize()),
    });
    if (res.status !== 200) {
      throw new Error(`nullifier: signet /prf/evaluate returned ${res.status}`);
    }
    const body = asRecord(res.json);
    const evalElt = b64urlDecode(
      stringField(body, "evaluation_element"),
      "evaluation_element",
      ELEMENT_LEN,
    );
    const proof = b64urlDecode(stringField(body, "proof"), "proof", PROOF_LEN);
    // voprf-ts Evaluation wire: u16 element count || element || mode || proof.
    const wire = new Uint8Array(2 + ELEMENT_LEN + 1 + PROOF_LEN);
    wire.set([0, 1], 0);
    wire.set(evalElt, 2);
    wire[2 + ELEMENT_LEN] = VOPRF_MODE;
    wire.set(proof, 2 + ELEMENT_LEN + 1);
    const evaluation = Evaluation.deserialize(SUITE, wire, CryptoNoble);
    // Throws on DLEQ verification failure against the pinned key.
    const outputs = await client.finalize(finData, evaluation);
    const nDedup = outputs[0];
    if (!nDedup || nDedup.length !== DEDUP_VALUE_LEN) {
      throw new Error("nullifier: VOPRF finalize returned a malformed output");
    }
    return nDedup;
  };

  return {
    evaluateDedupValue,

    verifyPin: ensurePinVerified,

    async registerDedup({ anchor, badgeType, ownerHandle }): Promise<RegisterDedupResult> {
      const nDedup = await evaluateDedupValue(anchor, badgeType);
      const res = await send("POST", "/dedup/register", {
        value: b64url(nDedup),
        owner_handle: ownerHandle,
        badge_type: badgeType,
      });
      if (res.status === 409) {
        // AppError::DedupTaken — a different owner already holds the
        // credential; issuance must be refused.
        return { status: "taken" };
      }
      if (res.status !== 200) {
        throw new Error(`nullifier: signet /dedup/register returned ${res.status}`);
      }
      const body = asRecord(res.json);
      const status = stringField(body, "status");
      if (status !== "registered" && status !== "already_yours") {
        throw new Error(`nullifier: signet /dedup/register returned unknown status ${status}`);
      }
      const entryRef = stringField(body, "entry_ref");
      // 16 random bytes -> 22 base64url chars; validate before persisting.
      b64urlDecode(entryRef, "entry_ref", 16);
      return { status, entryRef };
    },

    async disclose({ entryRef, ownerHandle, clientId }): Promise<MinisterGatingNullifier> {
      capClientId(clientId);
      await ensurePinVerified();
      const res = await send("POST", "/prf/disclose", {
        entry_ref: entryRef,
        owner_handle: ownerHandle,
        client_id: clientId,
      });
      // Fail closed: a missing entry or an owner mismatch must never yield a
      // value (same contract as the interim backend).
      if (res.status === 404) {
        throw new Error(`nullifier: entry ${entryRef} not found`);
      }
      if (res.status === 403) {
        throw new Error(`nullifier: owner mismatch for entry ${entryRef}`);
      }
      if (res.status !== 200) {
        throw new Error(`nullifier: signet /prf/disclose returned ${res.status}`);
      }
      const value = stringField(asRecord(res.json), "nullifier");
      if (!NULLIFIER_RE.test(value)) {
        // Issuer drift — a malformed disclosed value is never surfaced.
        throw new Error("nullifier: signet returned a malformed disclosed nullifier");
      }
      return value as MinisterGatingNullifier;
    },

    async entryExistsForOwner({ entryRef, ownerHandle }): Promise<boolean> {
      await ensurePinVerified();
      // /prf/disclose doubles as the owner-checked existence probe (module
      // doc): the probe nullifier under the reserved probe clientId is
      // computed by Signet and immediately discarded here.
      const res = await send("POST", "/prf/disclose", {
        entry_ref: entryRef,
        owner_handle: ownerHandle,
        client_id: PROBE_CLIENT_ID,
      });
      if (res.status === 200) return true;
      // Gone (released) or owned by someone else: false, never a throw, so
      // the mint-side caller can self-heal by re-registering.
      if (res.status === 404 || res.status === 403) return false;
      // Transport-level / server-side failure: THROW (retryable), never
      // false — false would trigger a spurious self-heal re-registration.
      throw new Error(`nullifier: signet probe returned ${res.status}`);
    },

    async release({ entryRef, ownerHandle }): Promise<void> {
      await ensurePinVerified();
      await withSignetEntryLock(entryRef, async (tx) => {
        // FRESH sibling check under the lock (never a caller-side count):
        // any badge INSERT that committed before we acquired the lock is
        // visible here, and no mint window can commit one until we release
        // it. This is the split-ledger equivalent of the interim backend's
        // atomic `AND NOT EXISTS (SELECT 1 FROM "Badge" …)`. Run ON the lock
        // transaction (READ COMMITTED — each statement sees fresh committed
        // data), so the count doubles as a lock-liveness proof: if the lock
        // transaction has been rolled back, this throws instead of counting.
        const siblings = await tx.badge.count({ where: { nullifierRef: entryRef } });
        if (siblings > 0) {
          // A live badge still references the entry — the release no-ops and
          // the entry survives (exactly the interim conditional-DELETE
          // outcome in the Case-A ordering).
          return;
        }
        // Re-prove the lock immediately before the UNGUARDED network delete:
        // if the lock transaction died (timeout) after the count, a mint
        // window could already be running — firing the delete now would be
        // the exact Case-A bypass. A dead transaction throws here (P2028),
        // aborting fail-closed; runPostCommit retries take a fresh lock.
        await tx.$queryRaw`SELECT 1`;
        const res = await send("POST", "/dedup/release", {
          entry_ref: entryRef,
          owner_handle: ownerHandle,
        });
        if (res.status === 403) {
          throw new Error(`nullifier: owner mismatch releasing entry ${entryRef}`);
        }
        if (res.status !== 200) {
          throw new Error(`nullifier: signet /dedup/release returned ${res.status}`);
        }
        // status "released" | "already_released" — both fine (idempotent).
      });
    },

    async reassignOwner({ entryRefs, fromOwnerHandle, toOwnerHandle }): Promise<number> {
      if (entryRefs.length === 0) return 0;
      if (fromOwnerHandle === toOwnerHandle) return 0;
      await ensurePinVerified();
      // Per-ref, not batched: Signet's /dedup/reassign is all-or-nothing (an
      // unknown ref 404s and an alien-owned ref 403s the WHOLE batch), while
      // the frozen interface contract — set by the interim backend and relied
      // on by merge/reverse-merge retries — is per-ref skip semantics: a ref
      // that vanished (released) or moved is skipped, the rest still move,
      // and the count of rows actually moved is returned. Merge is rare and
      // ref lists are small, so N round trips is the simple correct shape.
      let moved = 0;
      for (const ref of entryRefs) {
        const res = await send("POST", "/dedup/reassign", {
          entry_refs: [ref],
          from_owner_handle: fromOwnerHandle,
          to_owner_handle: toOwnerHandle,
        });
        if (res.status === 404 || res.status === 403) continue;
        if (res.status !== 200) {
          throw new Error(`nullifier: signet /dedup/reassign returned ${res.status}`);
        }
        const body = asRecord(res.json);
        const n = body.reassigned;
        if (typeof n !== "number") {
          throw new Error("nullifier: signet /dedup/reassign response lacks reassigned count");
        }
        moved += n;
      }
      return moved;
    },
  };
}

// ---------------------------------------------------------------------------
// Default instance (what the backend selector wires up)
// ---------------------------------------------------------------------------

// Test seam for the DEFAULT instance: wizard-level tests select the signet
// backend via env (module-load time) and need to script its Signet without
// any network. Production never touches this; the real mTLS transport builds
// lazily on first use when no override is installed.
let defaultTransportOverride: SignetTransport | null = null;
let realTransport: SignetTransport | null = null;

export function _setSignetTransportForTests(t: SignetTransport | null): void {
  if (process.env.NODE_ENV === "production") {
    // Zero-cost guard: nothing in production may reroute Signet traffic
    // through an injected transport.
    throw new Error("nullifier: _setSignetTransportForTests is disabled in production");
  }
  defaultTransportOverride = t;
}

const defaultDelegatingTransport: SignetTransport = (method, path, body) => {
  if (defaultTransportOverride) return defaultTransportOverride(method, path, body);
  if (!realTransport) {
    const c = configFromEnv();
    realTransport = createHttpsTransport({
      baseUrl: c.baseUrl,
      clientCert: c.clientCert,
      clientKey: c.clientKey,
      caCert: c.caCert,
      requestTimeoutMs: c.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
  }
  return realTransport(method, path, body);
};

// The env-configured default instance. Lazy throughout: constructing it
// touches no env, no filesystem, no network.
export const signetBackend: SignetNullifierBackend = createSignetBackend(
  undefined,
  defaultDelegatingTransport,
);
