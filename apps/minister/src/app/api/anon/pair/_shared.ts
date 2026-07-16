import { NextResponse } from "next/server";

import { clientIpFrom } from "@/lib/rate-limit";

// Shared helpers for the four QR device-pairing route handlers. Kept out of any
// `route.ts` so it is not mistaken for an endpoint. The routes are thin adapters
// over @/server/anon-pair; this only reads request context and shapes responses.

export interface RequestContext {
  /** Client IP resolved through the same trusted-header logic the limiters use;
   * "unknown" when it cannot be determined (never spoofable past that). */
  ip: string;
  ua: string | null;
  /** Best-effort geo from Cloudflare headers. City needs a managed transform and
   * is frequently absent — degrade to country-only, never invent a city. */
  country: string | null;
  city: string | null;
}

export function readContext(request: Request): RequestContext {
  const h = request.headers;
  const country = h.get("cf-ipcountry")?.trim() || null;
  const city = h.get("cf-ipcity")?.trim() || null;
  return {
    ip: clientIpFrom(h),
    ua: h.get("user-agent")?.slice(0, 512) || null,
    // "XX"/"T1" are Cloudflare's unknown/Tor placeholders — treat as absent.
    country: country && country !== "XX" && country !== "T1" ? country : null,
    city,
  };
}

/** Normalize "unknown" to null for the geo/network facts. */
export function ipOrNull(ip: string): string | null {
  return ip === "unknown" ? null : ip;
}

export function jsonError(error: string, status: number): NextResponse {
  return NextResponse.json(
    { ok: false, error },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}
