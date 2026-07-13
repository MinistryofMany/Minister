import { prisma } from "@/lib/prisma";
import { HTTP_MAX_AGE_SECONDS } from "@/lib/status-list";

// GET /status/<listId> — serve a per-RP BitstringStatusListCredential
// (docs/groups-revocation-design.md §5.5). Returns the PRE-SIGNED `signedJwt`
// verbatim: the hot path does zero crypto (all signing happens in the publisher).
//
// Unauthenticated by design: Ministry-side herd privacy comes from whole-list
// fetches (the RP always pulls all of its shards), and a CDN in front blurs even
// which RP polled and when. The `listId` is an opaque cuid — a weak capability
// only Ministry and the owning RP know; an outsider holding it sees only opaque
// bit flips and counts, never an index -> user mapping. Uniform 404 for an
// unknown id (indistinguishable from not-found — no enumeration oracle, auditor
// #4); 503 for a shard that exists but the publisher has not signed yet (the SDK
// then fails open on last-known state).
//
// Freshness is governed by the SIGNED `exp`/`statusListVersion` inside the JWT,
// not these HTTP headers (IETF Token Status List discipline): Cache-Control is a
// short public max-age with ETag/304 so a poller's steady state is cheap 304s,
// but the token claims are authoritative for the SDK.

interface RouteContext {
  params: Promise<{ listId: string }>;
}

const APPLICATION_VC_JWT = "application/vc+jwt";

function baseHeaders(etag: string): HeadersInit {
  return {
    ETag: etag,
    "Cache-Control": `public, max-age=${HTTP_MAX_AGE_SECONDS}`,
    "X-Robots-Tag": "noindex",
  };
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  const { listId } = await context.params;

  const row = await prisma.statusList.findUnique({
    where: { id: listId },
    select: { version: true, signedJwt: true },
  });

  // Unknown id -> uniform 404 (no directory enumeration).
  if (!row) {
    return new Response("Not found", { status: 404 });
  }

  // Allocated but not yet signed by the publisher: tell the RP to retry; the SDK
  // treats an unfetchable list as stale and fails open on last-known state.
  if (row.signedJwt === "") {
    return new Response("Status list not yet published", {
      status: 503,
      headers: { "Retry-After": String(HTTP_MAX_AGE_SECONDS) },
    });
  }

  const etag = `"${row.version}"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: baseHeaders(etag) });
  }

  return new Response(row.signedJwt, {
    status: 200,
    headers: { ...baseHeaders(etag), "Content-Type": APPLICATION_VC_JWT },
  });
}
