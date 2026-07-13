import { randomUUID } from "node:crypto";

import { base64url } from "jose";
import type { Issuer } from "@minister/vc";

import { Prisma } from "@/generated/prisma";
import { audit } from "@/lib/audit";
import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";

import { statusListUrl } from "./anchors";
import { encodeList, setBit } from "./bitstring";
import { HEARTBEAT_MS, KMS_RAW_SIGN_MAX_BYTES, LIST_TTL_MS, VALIDITY_WINDOW_MS } from "./constants";

// A distinct 64-bit advisory-lock key for the status-list publisher — separate
// from the stats (8273451906123n) and recovery-config (4823710192837n) locks so
// the three schedulers never contend. Held for the whole sweep so a second app
// instance's pass no-ops (single-writer, design §5.5).
export const PUBLISHER_ADVISORY_LOCK_KEY = 7194835260841n;

// Bounded optimistic-concurrency retries per list (C2b): a lost guarded write
// means a peer writer advanced the row between our read and write; re-read and
// retry a few times, then treat as raced (the winner covered the bits).
const PUBLISH_MAX_ATTEMPTS = 4;

// The scheduled sweep holds the advisory lock on one tx connection while signing
// happens on pooled connections. Generous ceiling (KMS is network I/O); maxWait
// bounds only pooled-connection acquisition. Mirrors stats-recompute.
const PUBLISH_TX_TIMEOUT_MS = 5 * 60_000;
const PUBLISH_TX_MAX_WAIT_MS = 10_000;

// The status-list PUBLISHER (§5.5). Single-writer: run from an interval worker or
// a scheduled script, never concurrently. Two duties folded into one pass:
//   1. epoch publication  — fold in every eligible revocation (revealAfter <= now,
//      bit not yet set), flip bits, bump version, sign, store;
//   2. heartbeat re-sign  — re-sign an unchanged live list on a fresh iat/exp so
//      max-age never forces a long fail-open/closed limbo (§5.6.2).
// The GET route serves the stored `signedJwt` verbatim — the hot path does zero
// crypto; all signing happens here.

const VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const PUBLISH_AUDIT_ACTION = "status.list_published";

export interface StatusListCredentialPayload {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  statusListVersion: number;
  vc: {
    "@context": string[];
    type: string[];
    credentialSubject: {
      id: string;
      type: "BitstringStatusList";
      statusPurpose: "revocation";
      encodedList: string;
    };
    ttl: number;
  };
}

// Build the unsigned BitstringStatusListCredential payload (§5.5). `sub` = the
// list URL binds the credential to its list (replay across lists impossible);
// `statusListVersion` is the monotonic rollback high-water mark; `exp` is the
// hard freshness bound the SDK enforces.
export function buildStatusListPayload(
  issuerDid: string,
  listId: string,
  bits: Uint8Array,
  version: number,
  nowMs: number,
): StatusListCredentialPayload {
  const url = statusListUrl(listId);
  const iat = Math.floor(nowMs / 1000);
  return {
    iss: issuerDid,
    sub: url,
    iat,
    exp: Math.floor((nowMs + VALIDITY_WINDOW_MS) / 1000),
    jti: randomUUID(),
    statusListVersion: version,
    vc: {
      "@context": [VC_CONTEXT],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      credentialSubject: {
        id: `${url}#list`,
        type: "BitstringStatusList",
        statusPurpose: "revocation",
        encodedList: encodeList(bits),
      },
      ttl: LIST_TTL_MS,
    },
  };
}

// Sign the payload with the badge key (#key-2), asserting the JWS signing input
// stays under the KMS RAW-sign ceiling BEFORE any signer call (§5.3, auditor #11).
// The failure is LOUD (throw) and refuses to publish — never a silent truncation
// or a fallback to the weaker #key-3 token key.
export async function signStatusListCredential(
  issuer: Issuer,
  payload: StatusListCredentialPayload,
): Promise<string> {
  const header = { alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" };
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const inputBytes = Buffer.byteLength(signingInput, "utf8");
  if (inputBytes > KMS_RAW_SIGN_MAX_BYTES) {
    throw new Error(
      `status-list: JWS signing input ${inputBytes} B exceeds the KMS RAW cap ${KMS_RAW_SIGN_MAX_BYTES} B — refusing to publish (${payload.sub})`,
    );
  }

  const signature = await issuer.signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64url.encode(signature)}`;
}

export interface PublishResult {
  listId: string;
  published: boolean;
  version?: number;
  changed?: boolean;
  revokedBits?: number;
}

// Publish one list if it needs it: dirty (a newly-eligible revocation flips a
// bit), never-yet-signed, or stale past the heartbeat interval. `force`
// republishes regardless (used by tests and a manual re-sign).
//
// C2b: the version bump is an OPTIMISTIC-concurrency read-modify-write. Each
// attempt reads the row, computes the new bits/version, signs, then writes ONLY
// if the row is still at the version it read (updateMany guarded on `version`). A
// concurrent writer that advanced the row invalidates our (stale-based) signature,
// so we re-read and retry rather than clobbering it — the version-uniqueness
// invariant the SDK high-water + route ETag rely on can never be violated by two
// overlapping passes. The scheduled sweep's advisory lock makes overlap rare; this
// also protects the manual `status:publish` script racing the interval.
export async function publishList(
  listId: string,
  opts: { now?: number; force?: boolean; issuer?: Issuer } = {},
): Promise<PublishResult> {
  const nowMs = opts.now ?? Date.now();

  for (let attempt = 0; attempt < PUBLISH_MAX_ATTEMPTS; attempt++) {
    const row = await prisma.statusList.findUnique({
      where: { id: listId },
      select: {
        id: true,
        clientId: true,
        version: true,
        bits: true,
        signedJwt: true,
        publishedAt: true,
      },
    });
    if (!row) return { listId, published: false };

    const bits = Uint8Array.from(row.bits);
    const eligible = await prisma.badgeStatusEntry.findMany({
      where: {
        listId,
        revokedAt: { not: null },
        // S5: a revoked entry publishes once its jitter floor elapses — OR was
        // never set. A revokedAt-set / revealAfter-null row (e.g. a born-revoked
        // W1 straggler, or any future revoke that skips jitter) must NOT silently
        // never publish; treat a null floor as "reveal now".
        OR: [{ revealAfter: { lte: new Date(nowMs) } }, { revealAfter: null }],
      },
      select: { bitIndex: true },
    });

    let changed = false;
    let revokedBits = 0;
    for (const entry of eligible) {
      if (setBit(bits, entry.bitIndex)) {
        changed = true;
        revokedBits += 1;
      }
    }

    const neverPublished = row.signedJwt === "";
    const stale = nowMs - row.publishedAt.getTime() >= HEARTBEAT_MS;
    if (!changed && !neverPublished && !stale && !opts.force) {
      return { listId, published: false };
    }

    const issuer = opts.issuer ?? (await getIssuer());
    // W4: version is a monotonic WALL CLOCK (epoch seconds), floored strictly above
    // the last version. Clock-derived => a Minister DB restore does NOT wedge
    // conforming RPs: the next publish still stamps ~now, staying >= any RP's
    // persisted high-water, so no version regression. The max() keeps it strictly
    // increasing (distinct ETag) even for two publishes within one second or under
    // clock skew. Epoch seconds fits Int4 until 2038 (widen to BigInt before then).
    const version = Math.max(row.version + 1, Math.floor(nowMs / 1000));
    const payload = buildStatusListPayload(issuer.did, listId, bits, version, nowMs);
    const signedJwt = await signStatusListCredential(issuer, payload);

    // Guarded write: commit ONLY if the row is still at the version we read.
    const updated = await prisma.statusList.updateMany({
      where: { id: listId, version: row.version },
      data: {
        ...(changed ? { bits: Buffer.from(bits) } : {}),
        version,
        signedJwt,
        publishedAt: new Date(nowMs),
      },
    });
    if (updated.count === 0) {
      // A concurrent writer advanced this list between our read and write; our
      // signature is over a stale base. Re-read and retry.
      continue;
    }

    // Distinct audit action so a systematic layer-2 (status) publish failure is not
    // buried in layer-1 mint-omission noise (auditor #15).
    await audit(null, PUBLISH_AUDIT_ACTION, { listId, version, changed, revokedBits });

    return { listId, published: true, version, changed, revokedBits };
  }

  // Exhausted attempts under sustained contention: a peer writer is publishing
  // this list. Its bits are covered by that winner's pass (or the next sweep) —
  // not a hard failure.
  return { listId, published: false };
}

export interface PublisherRunSummary {
  lists: number;
  published: number;
  changed: number;
  // Lists whose publish THREW this pass (e.g. a KMS blip on one shard). Collected
  // rather than propagated so one bad list can't strand every other RP's
  // revocations; the scheduled caller escalates these via lag detection.
  failed: Array<{ listId: string; error: string }>;
}

// One publisher pass over every list. Idempotent and safe to call on a timer
// (e.g. every EPOCH_MS): dirty lists republish at epoch cadence, quiet lists
// re-sign at heartbeat cadence. Per-list failures are caught and collected — the
// sweep always covers every OTHER list.
export async function runPublisherOnce(now?: number): Promise<PublisherRunSummary> {
  const nowMs = now ?? Date.now();
  const issuer = await getIssuer();
  const lists = await prisma.statusList.findMany({ select: { id: true } });

  let published = 0;
  let changed = 0;
  const failed: Array<{ listId: string; error: string }> = [];
  for (const { id } of lists) {
    try {
      const result = await publishList(id, { now: nowMs, issuer });
      if (result.published) published += 1;
      if (result.changed) changed += 1;
    } catch (err) {
      // One list's signing/DB failure must not abort the sweep and strand every
      // other RP's revocations (design: fail-open on the RP side means a stranded
      // list silently RETAINS a kicked member's access). Collect + continue.
      const message = err instanceof Error ? err.message : String(err);
      failed.push({ listId: id, error: message });
      console.error(`[status:publish] list ${id} failed (continuing sweep): ${message}`);
    }
  }
  return { lists: lists.length, published, changed, failed };
}

export type ScheduledPublishOutcome = "published" | "skipped-locked";

// A list is LAGGING (design §9.8 SECURITY control) if the publisher failed to keep
// it fresh: never signed past a short grace, or signed but its last publication is
// older than the validity window (its served credential has expired, so RPs see a
// stale list and — under the fail-open default — silently keep honoring a possibly
// -kicked member). Detected AFTER the sweep, so a lagging list means signing is
// actually failing, not merely due.
async function alertPublisherLagIfAny(
  client: Pick<Prisma.TransactionClient, "statusList">,
  nowMs: number,
  intervalMs: number,
  summary: PublisherRunSummary,
  sweepError: string | null,
): Promise<void> {
  // Grace for a brand-new (just-allocated, never-signed) list to get its first
  // signature on the very next sweep before we call it lag.
  const graceMs = 2 * intervalMs;
  const lagging = await client.statusList.findMany({
    where: {
      OR: [
        { signedJwt: "", publishedAt: { lt: new Date(nowMs - graceMs) } },
        { signedJwt: { not: "" }, publishedAt: { lt: new Date(nowMs - VALIDITY_WINDOW_MS) } },
      ],
    },
    select: { id: true, clientId: true },
  });

  if (lagging.length === 0 && summary.failed.length === 0 && sweepError === null) return;

  console.error(
    "[status:publish] PUBLISHER LAG (security control, design §9.8): " +
      `${lagging.length} list(s) unsigned/expired past threshold, ` +
      `${summary.failed.length} list(s) failed this pass` +
      (sweepError ? `, sweep aborted: ${sweepError}` : "") +
      `. lagging=[${lagging.map((l) => l.id).join(",")}] ` +
      `failed=[${summary.failed.map((f) => f.listId).join(",")}]`,
  );
  try {
    await audit(null, "status.publisher_lag", {
      lagging: lagging.map((l) => l.id),
      failed: summary.failed,
      sweepError,
    });
  } catch (auditErr) {
    // A degraded-DB audit-write failure must never break the interval.
    console.error(
      `[status:publish] failed to write publisher-lag audit: ${
        auditErr instanceof Error ? auditErr.message : String(auditErr)
      }`,
    );
  }
}

// The SCHEDULED entry point (instrumentation.ts interval). Single-writer across
// instances via a transaction-scoped advisory lock held for the whole sweep (a
// second instance's pg_try_advisory_xact_lock returns false -> skipped-locked).
// Runs the sweep, then lag detection — which fires even if the sweep threw
// globally (e.g. KMS down), so a total signing outage alerts rather than passing
// silently. Mirrors runScheduledStatsRecompute.
export async function runScheduledPublish(
  intervalMs: number,
  now?: number,
): Promise<ScheduledPublishOutcome> {
  const nowMs = now ?? Date.now();

  return prisma.$transaction(
    async (tx): Promise<ScheduledPublishOutcome> => {
      const lock = await tx.$queryRaw<Array<{ locked: boolean }>>(
        Prisma.sql`SELECT pg_try_advisory_xact_lock(${PUBLISHER_ADVISORY_LOCK_KEY}) AS locked`,
      );
      if (!lock[0]?.locked) return "skipped-locked";

      // The lock is held on THIS tx connection for the whole sweep; runPublisherOnce
      // signs/writes on pooled connections. Reads here (lag) see the sweep's
      // committed writes (READ COMMITTED).
      let summary: PublisherRunSummary = { lists: 0, published: 0, changed: 0, failed: [] };
      let sweepError: string | null = null;
      try {
        summary = await runPublisherOnce(nowMs);
      } catch (err) {
        // A GLOBAL failure (e.g. getIssuer/KMS unavailable) aborts the whole sweep;
        // lag detection below still runs so the outage is alerted.
        sweepError = err instanceof Error ? err.message : String(err);
      }

      await alertPublisherLagIfAny(tx, nowMs, intervalMs, summary, sweepError);
      return "published";
    },
    { timeout: PUBLISH_TX_TIMEOUT_MS, maxWait: PUBLISH_TX_MAX_WAIT_MS },
  );
}
