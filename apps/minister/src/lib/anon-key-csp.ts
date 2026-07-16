import { NextResponse } from "next/server";

// Site-wide strict, nonce-based Content-Security-Policy (identity plan, Lane B).
// This used to be scoped to two seed-bearing routes because the root lived only
// in a page's JS memory. The root now lives in ministry.id's IndexedDB (Lane C),
// so EVERY page on the origin can read it: an XSS on any route — however boring —
// opens the database and takes the root for every visitor. The strict CSP is
// therefore a precondition of the root store, not a follow-up, and it applies to
// the whole origin (the middleware matcher, and the merge into its auth branch).
//
// Nonce + 'strict-dynamic' is the only strict script-src that survives Next 15
// hydration: Next injects its own inline bootstrap scripts and stamps them with
// the nonce it reads back off the request-side CSP header, so a naive
// `script-src 'self'` white-screens the page. 'strict-dynamic' makes CSP3
// browsers ignore the host allowlist and trust only nonce'd scripts plus what
// they load (Next's chunk loader). An injected inline XSS script carries no
// nonce, so it is blocked — the seed-read vector is shut.
//
// style-src keeps 'unsafe-inline' (inline style is not a script/seed-read vector;
// Next + Tailwind inline critical CSS). img-src allows https: because site-wide
// scope now covers /u/[userId] and profile pages that render user-curated
// external avatars (Gravatar, free-text https links); images are not a script
// vector. connect-src stays 'self' — CSP has no navigate-to, so it cannot stop
// `location.href = evil + root`, but it does stop scripted fetch/XHR/WS exfil.

export function buildAnonKeyCsp(nonce: string, isDev: boolean): string {
  const scriptExtra = isDev ? " 'unsafe-eval'" : "";
  const connectExtra = isDev ? " ws:" : "";
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${scriptExtra}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' https: data: blob:",
    `connect-src 'self'${connectExtra}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// Report-only rollout toggle. When MINISTER_CSP_REPORT_ONLY=true the policy is
// emitted as `Content-Security-Policy-Report-Only` — the browser logs violations
// but blocks nothing — so the site-wide policy can ship and be observed (e.g. the
// external-avatar and /transparency routes that never ran under it) before it is
// enforced. Unset/false -> the enforcing `Content-Security-Policy` header. Only
// the header NAME changes; body + nonce are identical. Read from process.env
// directly (not the zod-parsed `env`) so this stays edge-safe: the middleware
// graph must not pull the full env schema into the Edge bundle. Next reads the
// nonce from either header name, so report-only mode still nonces Next's scripts.
export function cspHeaderName(): string {
  return process.env.MINISTER_CSP_REPORT_ONLY === "true"
    ? "content-security-policy-report-only"
    : "content-security-policy";
}

export interface RequestCsp {
  nonce: string;
  csp: string;
  headerName: string;
}

/** Mint a fresh per-request nonce + policy + header name. */
export function buildRequestCsp(isDev: boolean): RequestCsp {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  return { nonce, csp: buildAnonKeyCsp(nonce, isDev), headerName: cspHeaderName() };
}

/**
 * The pass-through response carrying the nonce + CSP on BOTH the forwarded
 * request (so Next reads the nonce to stamp its inline bootstrap scripts) and the
 * outgoing response. Used for any request the auth gate lets through.
 */
export function cspPassThrough(
  requestHeaders: Headers,
  { nonce, csp, headerName }: RequestCsp,
): NextResponse {
  const forwarded = new Headers(requestHeaders);
  forwarded.set("x-nonce", nonce);
  forwarded.set(headerName, csp);

  const res = NextResponse.next({ request: { headers: forwarded } });
  res.headers.set(headerName, csp);
  return res;
}
