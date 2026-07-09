import { isAllowedAvatarType } from "@/lib/avatar-image";
import { prisma } from "@/lib/prisma";

// Public GET for an uploaded avatar photo. Avatars render on the public profile
// (/u/[userId]) and are disclosed as the OIDC `picture` claim, so this route is
// intentionally unauthenticated. It is keyed on the avatar's OPAQUE `publicId`,
// NEVER the userId: serving under the userId would leak Minister's global
// account id to any relying party granted the avatar claim (it could dereference
// /u/<userId> and correlate the user across RPs), defeating the pairwise `sub`.
//
// Caching + read-amplification: the response is keyed on the ROW, not the `?v=`
// query. We first read only the row's metadata (contentType + updatedAt) and
// build a strong ETag from updatedAt. A conditional request whose `If-None-Match`
// matches gets a 304 WITHOUT ever reading the 512 KB blob out of Postgres — so a
// flood of requests (even with random `?v=` values) can't force a full-body DB
// stream per hit. Cache-Control is a MODERATE `public, max-age=3600,
// must-revalidate` (not a year of `immutable`), so a deleted or replaced photo
// stops being served within the hour rather than lingering in RP/edge/browser
// caches. The `?v=` remains only a cache-buster on the URL; it never controls
// whether we cache or whether we stream the body.
//
// Security headers:
//   - Content-Type is the STORED (sniffed) type, and only if it is still one of
//     the three allowed raster types (defense in depth against a poisoned row).
//   - X-Content-Type-Options: nosniff — the browser must not re-interpret the
//     bytes as anything executable.
//   - Content-Disposition: inline — render in place, never a drive-by download.
//   - Content-Security-Policy: default-src 'none'; sandbox — user-controlled
//     bytes served from our origin run in a locked-down, script-less sandbox.

const MODERATE_CACHE_CONTROL = "public, max-age=3600, must-revalidate";

interface RouteContext {
  params: Promise<{ publicId: string }>;
}

// The shared hardening headers on every 200/304 for a servable avatar. Kept in
// one place so the 304 (no body) and the 200 (with body) agree exactly.
function serveHeaders(contentType: string, etag: string): HeadersInit {
  return {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "Content-Disposition": "inline",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": MODERATE_CACHE_CONTROL,
    ETag: etag,
  };
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  const { publicId } = await context.params;

  // Step 1: metadata only — NO blob read. This is the cheap read that a
  // conditional (If-None-Match) request can be answered from with a 304, so a
  // validated cache never streams the 512 KB body.
  const meta = await prisma.userAvatar.findUnique({
    where: { publicId },
    select: { contentType: true, updatedAt: true },
  });

  // 404 when there is no such avatar (or the stored type is somehow not one of
  // the three we allow — treat a poisoned row as absent rather than serving
  // unknown bytes).
  if (!meta || !isAllowedAvatarType(meta.contentType)) {
    return new Response("Not found", { status: 404 });
  }

  // Strong ETag derived from the row's updatedAt: it changes on every replace,
  // so a stale cache's validator won't match and it re-fetches the new bytes.
  const etag = `"${meta.updatedAt.getTime()}"`;

  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: serveHeaders(meta.contentType, etag) });
  }

  // Step 2: the cache miss — now read the actual bytes.
  const blob = await prisma.userAvatar.findUnique({
    where: { publicId },
    select: { data: true },
  });
  // Vanished between the two reads (a concurrent switch-away deletes the row):
  // treat as absent rather than serving a half-torn response.
  if (!blob) {
    return new Response("Not found", { status: 404 });
  }

  // Prisma returns Bytes as a Buffer; hand a fresh Uint8Array to the Response so
  // the body is a plain BodyInit.
  return new Response(new Uint8Array(blob.data), {
    status: 200,
    headers: serveHeaders(meta.contentType, etag),
  });
}
