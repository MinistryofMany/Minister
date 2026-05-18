import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";

import { getCurrentSession } from "@/lib/session";
import { resumeViaPendingToken } from "@/server/wizard";

// Endpoint the Tessera browser extension POSTs the finalized TLSNotary
// presentation to. CORS is permissive because the extension makes the
// request from its own origin (the chrome-extension:// scheme), not
// from a Tessera page — but the user MUST be signed in to Tessera for
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

// Allowlist of origins permitted to POST here. Real browser extensions
// have stable chrome-extension://<id> origins — we keep that to env so
// the operator can pin it. Empty list = allow any origin (dev only;
// the user is still authenticated).
function isOriginAllowed(origin: string | null): boolean {
  const allow = process.env.TLSN_SUBMIT_ALLOWED_ORIGINS?.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!allow || allow.length === 0) return true;
  return origin !== null && allow.includes(origin);
}

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin ?? "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
    Vary: "Origin",
  };
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
    return submitErr(
      parsed.error.issues[0]?.message ?? "invalid_body",
      400,
      origin,
    );
  }

  // Resolve the wizard session via sessionToken == pendingToken. The
  // helper also enforces that the token belongs to the currently
  // signed-in user — so a leaked sessionToken alone isn't enough to
  // claim a badge into someone else's account.
  const h = await headers();
  const tesseraOrigin = `${h.get("x-forwarded-proto") ?? "http"}://${
    h.get("host") ?? "localhost:3000"
  }`;
  const result = await resumeViaPendingToken({
    token: parsed.data.sessionToken,
    userId: session.user.id,
    origin: tesseraOrigin,
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
    return submitErr(
      `plugin_wants_continuation:${result.pluginId}`,
      409,
      origin,
    );
  }
  return submitErr(result.message, 400, origin);
}

function submitErr(
  error: string,
  status: number,
  origin: string | null,
): NextResponse {
  return NextResponse.json(
    { ok: false, error },
    { status, headers: { ...corsHeaders(origin), "Cache-Control": "no-store" } },
  );
}
