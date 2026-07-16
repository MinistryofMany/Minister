import { NextResponse } from "next/server";

import { env } from "@/env";
import { anonPairLimiter } from "@/lib/rate-limit";
import { getCurrentSession } from "@/lib/session";
import { createPairSession } from "@/server/anon-pair";

import { ipOrNull, jsonError, readContext } from "../_shared";

// POST /api/anon/pair/create — the DISPLAYING device (which NEEDS the root) mints
// a relay session for its OWN authenticated account. The recipient public key is
// deliberately NOT sent: it exists only in the page's memory and the QR's pixels.
//
// Response: { ok, sessionId, creatorSecret, expiresAt } | { ok: false, error }
export async function POST(request: Request) {
  if (!env.ANON_IDENTITY_ENABLED) return jsonError("not_enabled", 404);

  const session = await getCurrentSession();
  if (!session?.user?.id) return jsonError("not_signed_in", 401);

  if (!anonPairLimiter.check(session.user.id).allowed) {
    return jsonError("rate_limited", 429);
  }

  const ctx = readContext(request);
  const result = await createPairSession({
    userId: session.user.id,
    ip: ipOrNull(ctx.ip),
    ua: ctx.ua,
    country: ctx.country,
    city: ctx.city,
  });

  return NextResponse.json({ ok: true, ...result }, { headers: { "Cache-Control": "no-store" } });
}
