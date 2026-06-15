// In-memory sliding-window rate limiter.
//
// Deliberately process-local: Minister currently deploys as a single
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

export function createRateLimiter(opts: { windowMs: number; max: number }): RateLimiter {
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

// Resolve a *trustworthy* per-client bucket key for rate limiting.
//
// The threat: X-Forwarded-For is appended to by every hop, but the
// leftmost entries are fully attacker-controlled. Keying a limiter on the
// leftmost XFF entry lets a client rotate the header per request, land in
// a fresh bucket each time, and bypass every limiter (magic-link spam,
// share-token probing, /token, /authorize). We must only ever key on a
// value a *trusted* hop wrote, never on raw client input.
//
// Minister is plain Next.js (no custom server), so route handlers see
// request headers but not the socket peer address. Trust therefore has to
// be configured to match the deployment topology:
//
//   MINISTER_CLIENT_IP_HEADER (default "cf-connecting-ip")
//     Name of a single header that a trusted proxy sets to the real client
//     IP, *overwriting* anything the client sent. When this env is a
//     non-empty string and that header is present, its trimmed value is the
//     bucket key. Set it to "" to disable header trust entirely (forces the
//     reverse-proxy-hops or fail-safe paths below).
//
//   MINISTER_TRUSTED_PROXY_HOPS (default 0)
//     Generic reverse-proxy fallback for non-Cloudflare deployments. The
//     number of proxies *you* operate in front of the origin, each of which
//     appends one entry to X-Forwarded-For. XFF reads left-to-right as
//     [client, ...untrusted hops..., your hop N, ..., your hop 1], so your
//     proxies own the rightmost entries. With H trusted hops we trust the
//     entry at index (length - H) — the value written by your outermost
//     proxy, i.e. the first hop you actually control. Anything to its left
//     is client-forgeable and ignored. H = 0 means XFF is wholly untrusted.
//
//   Otherwise: a single fixed "unknown" bucket. This fails safe — all
//   untrusted traffic shares one limiter and over-limits, rather than each
//   request minting its own bucket and under-limiting.
//
// CRITICAL DEPLOYMENT REQUIREMENT — trusting CF-Connecting-IP (or any proxy
// header) is only safe if the origin CANNOT be reached directly, bypassing
// the proxy. If an attacker can hit the Node origin straight, they set
// CF-Connecting-IP themselves and every per-IP limit is defeated. Minister
// is intended to run behind Cloudflare; the origin MUST therefore be locked
// down by one of:
//   - Cloudflare Tunnel (cloudflared) so the origin has no public inbound
//     route at all, OR
//   - restricting the origin firewall to Cloudflare's published IP ranges,
//     OR
//   - Authenticated Origin Pulls (mTLS) so the origin only accepts TLS
//     connections bearing Cloudflare's client certificate.
// Without one of these, set MINISTER_CLIENT_IP_HEADER="" and configure
// MINISTER_TRUSTED_PROXY_HOPS to match whatever proxy chain you do control.
export function clientIpFrom(headers: { get(name: string): string | null }): string {
  const trustedHeader = process.env.MINISTER_CLIENT_IP_HEADER ?? "cf-connecting-ip";
  if (trustedHeader) {
    const value = headers.get(trustedHeader)?.trim();
    if (value) return value;
  }

  const hops = trustedProxyHops();
  if (hops > 0) {
    const xff = headers.get("x-forwarded-for");
    if (xff) {
      const parts = xff
        .split(",")
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      // The outermost proxy we control sits `hops` from the right end of the
      // list. Clamp so an over-large hop count (or a too-short list) just
      // grabs the leftmost present entry rather than reading out of bounds.
      const idx = Math.max(0, parts.length - hops);
      const trusted = parts[idx];
      if (trusted) return trusted;
    }
  }

  return "unknown";
}

function trustedProxyHops(): number {
  const raw = process.env.MINISTER_TRUSTED_PROXY_HOPS;
  if (!raw) return 0;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
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
  max: envMax("MINISTER_RL_TOKEN_MAX", 30),
});

// Claims fetch: one or two calls per RP session, but cheap to serve.
export const oidcUserinfoLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("MINISTER_RL_USERINFO_MAX", 60),
});

// Consent page render: one per sign-in attempt.
export const oidcAuthorizeLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("MINISTER_RL_AUTHORIZE_MAX", 30),
});

// Presentation submission: TLSNotary proofs take seconds to produce,
// so anything past a handful per minute is not a browser extension.
export const tlsnSubmitLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("MINISTER_RL_TLSN_MAX", 10),
});

// Magic-link sends: the abuse case is spamming someone's inbox, so the
// window is long and the cap low.
export const signInEmailLimiter = createRateLimiter({
  windowMs: 15 * MINUTE,
  max: envMax("MINISTER_RL_SIGNIN_MAX", 10),
});

// Share-link views: every render writes a ShareLinkView row, and the
// token space shouldn't be probeable at speed.
export const shareViewLimiter = createRateLimiter({
  windowMs: MINUTE,
  max: envMax("MINISTER_RL_SHARE_MAX", 60),
});
