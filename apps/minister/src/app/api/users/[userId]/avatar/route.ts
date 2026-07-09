import { isAllowedAvatarType } from "@/lib/avatar-image";
import { prisma } from "@/lib/prisma";

// Public GET for a user's uploaded avatar photo. Avatars render on the public
// profile (/u/[userId]) and are disclosed as the OIDC `picture` claim, so this
// route is intentionally unauthenticated. It serves ONLY the avatar bytes for
// the requested userId — no other column, no other user — so there is no IDOR
// surface beyond the avatar that is already meant to be public.
//
// Security headers:
//   - Content-Type is the STORED (sniffed) type, and only if it is still one of
//     the three allowed raster types (defense in depth against a poisoned row).
//   - X-Content-Type-Options: nosniff — the browser must not re-interpret the
//     bytes as anything executable.
//   - Content-Disposition: inline — render in place, never a drive-by download.
//   - Cache-Control is keyed to the ?v= version: an exact match (the current
//     photo) is immutable and long-lived; a stale/absent version is not cached,
//     so a replaced photo is picked up promptly.

interface RouteContext {
  params: Promise<{ userId: string }>;
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  const { userId } = await context.params;

  const avatar = await prisma.userAvatar.findUnique({
    where: { userId },
    select: { data: true, contentType: true, updatedAt: true },
  });

  // 404 when the user has no uploaded avatar (or the stored type is somehow not
  // one of the three we allow — treat a poisoned row as absent rather than
  // serving unknown bytes).
  if (!avatar || !isAllowedAvatarType(avatar.contentType)) {
    return new Response("Not found", { status: 404 });
  }

  const version = avatar.updatedAt.getTime().toString();
  const requestedVersion = new URL(request.url).searchParams.get("v");
  const cacheControl =
    requestedVersion === version
      ? "public, max-age=31536000, immutable"
      : "public, max-age=0, must-revalidate";

  // Prisma returns Bytes as a Buffer; hand a fresh Uint8Array to the Response so
  // the body is a plain BodyInit.
  return new Response(new Uint8Array(avatar.data), {
    status: 200,
    headers: {
      "Content-Type": avatar.contentType,
      "X-Content-Type-Options": "nosniff",
      "Content-Disposition": "inline",
      "Cache-Control": cacheControl,
    },
  });
}
