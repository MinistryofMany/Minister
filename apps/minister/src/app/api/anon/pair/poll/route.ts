import { NextResponse } from "next/server";
import { z } from "zod";

import { isValidSessionId } from "@minister/shared/pair-protocol";

import { env } from "@/env";
import { anonPairLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";
import { pollPairSession } from "@/server/anon-pair";

import { ipOrNull, jsonError, readContext } from "../_shared";

// POST /api/anon/pair/poll — returns the session state plus the OTHER device's
// connection facts (country/city + sameNetworkAsYou), used by the SCANNING
// device to judge "is this really my other device?". Only the sessionId (from
// the QR) is needed — never the creator secret, which the scanner does not hold.
// Requires a signed-in session (defense + the sameNetwork comparison needs the
// requester's IP).
//
// Response: { ok, state, expiresAt, peer } | { ok: false, error }
const Body = z.object({ sessionId: z.string().refine(isValidSessionId, "invalid sessionId") });

export async function POST(request: Request) {
  if (!env.ANON_IDENTITY_ENABLED) return jsonError("not_enabled", 404);

  const session = await getCurrentSession();
  if (!session?.user?.id) return jsonError("not_signed_in", 401);

  const ctx = readContext(request);
  if (!anonPairLimiter.check(ctx.ip).allowed) return jsonError("rate_limited", 429);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError("invalid_json", 400);
  }
  const parsed = Body.safeParse(body);
  if (!parsed.success) return jsonError("invalid_body", 400);

  const result = await pollPairSession({
    sessionId: parsed.data.sessionId,
    requesterIp: ipOrNull(ctx.ip),
    requesterCountry: ctx.country,
  });
  return NextResponse.json({ ok: true, ...result }, { headers: { "Cache-Control": "no-store" } });
}
