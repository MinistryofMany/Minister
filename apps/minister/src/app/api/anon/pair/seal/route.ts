import { NextResponse } from "next/server";
import { z } from "zod";

import { isValidSessionId, PAIR_RELAY_BODY_B64_LEN } from "@minister/shared/pair-protocol";

import { env } from "@/env";
import { anonPairLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";
import { sealPairSession } from "@/server/anon-pair";

import { ipOrNull, jsonError, readContext } from "../_shared";

// POST /api/anon/pair/seal — the SCANNING device (holding the root) deposits its
// HPKE-sealed payload. The account-checked atomic update lives in
// sealPairSession: it conditions on `userId = <this session's user>` (C2), the
// SOLE barrier against the remote phish.
//
// Response: { ok: true } | { ok: false, error, reason }
const Body = z.object({
  sessionId: z.string().refine(isValidSessionId, "invalid sessionId"),
  payload: z
    .string()
    .length(PAIR_RELAY_BODY_B64_LEN)
    .regex(/^[A-Za-z0-9_-]+$/, "payload must be base64url"),
});

export async function POST(request: Request) {
  if (!env.ANON_IDENTITY_ENABLED) return jsonError("not_enabled", 404);

  const session = await getCurrentSession();
  if (!session?.user?.id) return jsonError("not_signed_in", 401);

  const ctx = readContext(request);
  if (!anonPairLimiter.check(session.user.id).allowed) return jsonError("rate_limited", 429);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError("invalid_json", 400);
  }
  const parsed = Body.safeParse(body);
  if (!parsed.success) return jsonError("invalid_body", 400);

  const result = await sealPairSession({
    sessionId: parsed.data.sessionId,
    // C2: the sealer's OWN authenticated session user — NEVER a value read back
    // from the relay/poll. This is what the atomic update conditions on.
    sessionUserId: session.user.id,
    payload: parsed.data.payload,
    ip: ipOrNull(ctx.ip),
    ua: ctx.ua,
  });

  if (result.ok) {
    return NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  }
  // 403 for the cross-account case so the client renders the S3 attack warning.
  const status = result.reason === "cross_account" ? 403 : 409;
  return NextResponse.json(
    { ok: false, error: result.reason, reason: result.reason },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}
