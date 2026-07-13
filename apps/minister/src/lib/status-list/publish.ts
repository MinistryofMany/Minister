import { randomUUID } from "node:crypto";

import { base64url } from "jose";
import type { Issuer } from "@minister/vc";

import { audit } from "@/lib/audit";
import { getIssuer } from "@/lib/issuer";
import { prisma } from "@/lib/prisma";

import { statusListUrl } from "./anchors";
import { encodeList, setBit } from "./bitstring";
import { HEARTBEAT_MS, KMS_RAW_SIGN_MAX_BYTES, LIST_TTL_MS, VALIDITY_WINDOW_MS } from "./constants";

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
export async function publishList(
  listId: string,
  opts: { now?: number; force?: boolean; issuer?: Issuer } = {},
): Promise<PublishResult> {
  const nowMs = opts.now ?? Date.now();
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
      revealAfter: { lte: new Date(nowMs) },
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
  const version = row.version + 1;
  const payload = buildStatusListPayload(issuer.did, listId, bits, version, nowMs);
  const signedJwt = await signStatusListCredential(issuer, payload);

  await prisma.statusList.update({
    where: { id: listId },
    data: {
      ...(changed ? { bits: Buffer.from(bits) } : {}),
      version,
      signedJwt,
      publishedAt: new Date(nowMs),
    },
  });

  // Distinct audit action so a systematic layer-2 (status) publish failure is not
  // buried in layer-1 mint-omission noise (auditor #15).
  await audit(null, PUBLISH_AUDIT_ACTION, { listId, version, changed, revokedBits });

  return { listId, published: true, version, changed, revokedBits };
}

export interface PublisherRunSummary {
  lists: number;
  published: number;
  changed: number;
}

// One publisher pass over every list. Idempotent and safe to call on a timer
// (e.g. every EPOCH_MS): dirty lists republish at epoch cadence, quiet lists
// re-sign at heartbeat cadence.
export async function runPublisherOnce(now?: number): Promise<PublisherRunSummary> {
  const nowMs = now ?? Date.now();
  const issuer = await getIssuer();
  const lists = await prisma.statusList.findMany({ select: { id: true } });

  let published = 0;
  let changed = 0;
  for (const { id } of lists) {
    const result = await publishList(id, { now: nowMs, issuer });
    if (result.published) published += 1;
    if (result.changed) changed += 1;
  }
  return { lists: lists.length, published, changed };
}
