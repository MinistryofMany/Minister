// In-memory sliding-window rate limiter.
//
// Deliberately process-local: Tessera currently deploys as a single
// instance, and the Stage 9 plan upgrades this to Redis (Upstash) when
// horizontal scaling arrives. The interface is the part that should
// survive that swap.
//
// Edge-safe on purpose (no node: imports) — middleware uses it too.
// Note the Edge and Node runtimes each get their own module instance,
// which is fine: they guard disjoint endpoints.

export interface RateLimitVerdict {
  allowed: boolean;
  // Seconds until the oldest counted hit ages out — what belongs in a
  // Retry-After header. 0 when allowed.
  retryAfterSeconds: number;
}

export interface RateLimiter {
  check(key: string, now?: number): RateLimitVerdict;
}

// Above this many tracked keys, do a full sweep on the next check.
// Keeps a scanner cycling through spoofed X-Forwarded-For values from
// growing the map without bound.
const SWEEP_THRESHOLD = 10_000;

export function createRateLimiter(opts: {
  windowMs: number;
  max: number;
}): RateLimiter {
  const { windowMs, max } = opts;
  const hits = new Map<string, number[]>();

  function sweep(now: number) {
    for (const [key, list] of hits) {
      const live = list.filter((t) => t > now - windowMs);
      if (live.length === 0) hits.delete(key);
      else hits.set(key, live);
    }
  }

  return {
    check(key: string, now: number = Date.now()): RateLimitVerdict {
      if (hits.size > SWEEP_THRESHOLD) sweep(now);

      const cutoff = now - windowMs;
      const live = (hits.get(key) ?? []).filter((t) => t > cutoff);

      if (live.length >= max) {
        hits.set(key, live);
        const oldest = live[0] ?? now;
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)),
        };
      }

      live.push(now);
      hits.set(key, live);
      return { allowed: true, retryAfterSeconds: 0 };
    },
  };
}

// First hop of X-Forwarded-For, else X-Real-IP, else a fixed bucket.
// Behind the expected reverse proxy these are trustworthy enough for
// rate limiting; direct-to-node traffic all lands in one bucket, which
// fails safe (over-limits rather than under-limits).
export function clientIpFrom(headers: {
  get(name: string): string | null;
}): string {
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  return headers.get("x-real-ip") ?? "unknown";
}

// ---------------------------------------------------------------------------
// Shared limiter instances, one per guarded surface
// ---------------------------------------------------------------------------

const MINUTE = 60_000;

// Caps are env-overridable so the e2e suite (which drives these
// endpoints far harder than a human) can raise them without forking
// the code path. Windows stay fixed.
function envMax(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// Code exchange: a legitimate RP makes one call per sign-in.
export const oidcTokenLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("TESSERA_RL_TOKEN_MAX", 30),
});

// Claims fetch: one or two calls per RP session, but cheap to serve.
export const oidcUserinfoLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("TESSERA_RL_USERINFO_MAX", 60),
});

// Consent page render: one per sign-in attempt.
export const oidcAuthorizeLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("TESSERA_RL_AUTHORIZE_MAX", 30),
});

// Presentation submission: TLSNotary proofs take seconds to produce,
// so anything past a handful per minute is not a browser extension.
export const tlsnSubmitLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("TESSERA_RL_TLSN_MAX", 10),
});

// Magic-link sends: the abuse case is spamming someone's inbox, so the
// window is long and the cap low.
export const signInEmailLimiter = createRateLimiter({
  windowMs: 15 * MINUTE,
  max: envMax("TESSERA_RL_SIGNIN_MAX", 10),
});

// Share-link views: every render writes a ShareLinkView row, and the
// token space shouldn't be probeable at speed.
export const shareViewLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("TESSERA_RL_SHARE_MAX", 60),
});
