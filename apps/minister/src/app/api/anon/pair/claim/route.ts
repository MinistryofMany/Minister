import { NextResponse } from "next/server";
import { z } from "zod";

import { isValidSessionId } from "@minister/shared/pair-protocol";

import { env } from "@/env";
import { anonPairLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";
import { claimPairSession } from "@/server/anon-pair";

import { jsonError } from "../_shared";

// POST /api/anon/pair/claim — the DISPLAYING device retrieves the sealed payload
// with its creator secret. The payload is NULLed in the same statement that
// hands it out (single-use). Polled by the display page until state === claimed.
//
// Response: { ok, state, payload? } | { ok: false, error }
const Body = z.object({
  sessionId: z.string().refine(isValidSessionId, "invalid sessionId"),
  // base64url, generous cap; the exact secret is compared by hash server-side.
  creatorSecret: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_-]+$/, "invalid creatorSecret"),
});

export async function POST(request: Request) {
  if (!env.ANON_IDENTITY_ENABLED) return jsonError("not_enabled", 404);

  const session = await getCurrentSession();
  if (!session?.user?.id) return jsonError("not_signed_in", 401);

  if (!anonPairLimiter.check(session.user.id).allowed) return jsonError("rate_limited", 429);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError("invalid_json", 400);
  }
  const parsed = Body.safeParse(body);
  if (!parsed.success) return jsonError("invalid_body", 400);

  const result = await claimPairSession({
    sessionId: parsed.data.sessionId,
    sessionUserId: session.user.id,
    creatorSecret: parsed.data.creatorSecret,
  });

  if (!result.ok) {
    const status = result.reason === "forbidden" ? 403 : result.reason === "bad_secret" ? 401 : 404;
    return jsonError(result.reason, status);
  }
  const payload = result.state === "claimed" ? result.payload : null;
  return NextResponse.json(
    { ok: true, state: result.state, payload },
    { headers: { "Cache-Control": "no-store" } },
  );
}
