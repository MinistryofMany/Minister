import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";

import { clientIpFrom, tlsnSubmitLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";
import { resumeViaPendingToken } from "@/server/wizard";

// Endpoint the Minister browser extension POSTs the finalized TLSNotary
// presentation to. CORS is permissive because the extension makes the
// request from its own origin (the chrome-extension:// scheme), not
// from a Minister page — but the user MUST be signed in to Minister for
// the cookie-based auth to identify them.
//
// Wire shape:
//   request : { sessionToken, presentation }
//   response: { ok: true, badgeIds: string[] }
//           | { ok: false, error: string }

const Body = z.object({
  sessionToken: z.string().min(8),
  presentation: z.string().min(1),
});

// Origins permitted to make a credentialed cross-origin request here. Real
// browser extensions have stable chrome-extension://<id> origins; the operator
// pins them via TLSN_SUBMIT_ALLOWED_ORIGINS (comma-separated). We FAIL CLOSED:
// a request that carries an Origin header is rejected unless that origin is
// explicitly allowlisted. Requests with no Origin (same-origin, server-to-
// server, tests) are not a CORS credential-reflection risk and pass this gate;
// they still must satisfy the cookie auth below. We never reflect an untrusted
// origin alongside Access-Control-Allow-Credentials.
function allowlistedOrigins(): string[] {
  return (
    process.env.TLSN_SUBMIT_ALLOWED_ORIGINS?.split(",")
      .map((s) => s.trim())
      .filter(Boolean) ?? []
  );
}

function isOriginAllowed(origin: string | null): boolean {
  if (origin === null) return true;
  return allowlistedOrigins().includes(origin);
}

function corsHeaders(origin: string | null): Record<string, string> {
  const base: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
  // Only grant a credentialed CORS response to an explicitly allowlisted
  // origin. Never echo an untrusted origin, and never pair "*" with
  // credentials (browsers reject that combination anyway).
  if (origin !== null && allowlistedOrigins().includes(origin)) {
    base["Access-Control-Allow-Origin"] = origin;
    base["Access-Control-Allow-Credentials"] = "true";
  }
  return base;
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin");
  return new NextResponse(null, {
    status: isOriginAllowed(origin) ? 204 : 403,
    headers: corsHeaders(origin),
  });
}

export async function POST(request: Request) {
  const origin = request.headers.get("origin");
  if (!isOriginAllowed(origin)) {
    return submitErr("origin_not_allowed", 403, origin);
  }

  const limit = tlsnSubmitLimiter.check(clientIpFrom(request.headers));
  if (!limit.allowed) {
    return submitErr("rate_limited", 429, origin);
  }

  const session = await getCurrentSession();
  if (!session?.user?.id) {
    return submitErr("not_signed_in", 401, origin);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return submitErr("invalid_json", 400, origin);
  }
  const parsed = Body.safeParse(body);
  if (!parsed.success) {
    return submitErr(parsed.error.issues[0]?.message ?? "invalid_body", 400, origin);
  }

  // Resolve the wizard session via sessionToken == pendingToken. The
  // helper also enforces that the token belongs to the currently
  // signed-in user — so a leaked sessionToken alone isn't enough to
  // claim a badge into someone else's account.
  const h = await headers();
  const ministerOrigin = `${h.get("x-forwarded-proto") ?? "http"}://${
    h.get("host") ?? "localhost:3000"
  }`;
  const result = await resumeViaPendingToken({
    token: parsed.data.sessionToken,
    userId: session.user.id,
    origin: ministerOrigin,
    input: { presentation: parsed.data.presentation },
  });

  if (result.kind === "complete") {
    return NextResponse.json(
      { ok: true, badgeIds: result.badgeIds },
      { headers: corsHeaders(origin) },
    );
  }
  if (result.kind === "continue") {
    // The plugin asked for another round trip. Tell the extension —
    // it doesn't know what to do here yet (no multi-step extension
    // flows in v1), but be explicit rather than silent.
    return submitErr(`plugin_wants_continuation:${result.pluginId}`, 409, origin);
  }
  return submitErr(result.message, 400, origin);
}

function submitErr(error: string, status: number, origin: string | null): NextResponse {
  return NextResponse.json(
    { ok: false, error },
    { status, headers: { ...corsHeaders(origin), "Cache-Control": "no-store" } },
  );
}
