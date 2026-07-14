import { NextResponse } from "next/server";

// Two routes touch the client-side anonymous seed in JS memory, which makes them
// the pages where an at-use XSS could read the seed: /settings/private-identity
// (dogfood seed management) and /oidc/authorize (the consent page, which derives
// per-app anon identity for anon-enabled OIDC clients). This module builds a
// strict, nonce-based CSP scoped to those routes only (wired in middleware). The
// same nonce + strict-dynamic policy is used for both — it is the only strict
// script-src that survives Next 15 hydration, so it does not break the consent
// form. style-src keeps 'unsafe-inline' (not a seed-read vector).

export const ANON_KEY_PATH = "/settings/private-identity";
export const OIDC_AUTHORIZE_PATH = "/oidc/authorize";

export function isStrictCspPath(pathname: string): boolean {
  return (
    pathname === ANON_KEY_PATH ||
    pathname.startsWith(`${ANON_KEY_PATH}/`) ||
    pathname === OIDC_AUTHORIZE_PATH
  );
}

// Nonce-based is the only strict script-src that survives Next 15 hydration:
// Next injects its own inline bootstrap scripts and stamps them with the nonce
// it reads back off the request-side CSP header, so a naive `script-src 'self'`
// white-screens the page. `'strict-dynamic'` makes CSP3 browsers ignore the
// `'self'`/host allowlist in script-src and trust only the nonce'd scripts plus
// whatever they load — which is exactly Next's chunk loader. An injected inline
// XSS script carries no nonce, so it is blocked: the seed-read vector is shut.
//
// style-src keeps `'unsafe-inline'` on purpose — inline style is not a
// script-execution / seed-read vector, and Next + Tailwind inline critical CSS;
// tightening it buys nothing here and risks a white screen.
//
// ponytail: dev relaxes script `'unsafe-eval'` + `ws:` connect for Next's HMR;
// the strict path is what ships to the dogfood (prod build). Residual noted in
// the accompanying report — not validated against a running server tonight.
export function buildAnonKeyCsp(nonce: string, isDev: boolean): string {
  const scriptExtra = isDev ? " 'unsafe-eval'" : "";
  const connectExtra = isDev ? " ws:" : "";
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${scriptExtra}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    `connect-src 'self'${connectExtra}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// Returns a pass-through response carrying the strict CSP for a seed-bearing
// route, or null when the path is out of scope (the caller then continues its
// normal middleware flow). Next reads the nonce from the request-side CSP
// header to nonce its own inline scripts, so we set the header on BOTH the
// forwarded request and the outgoing response.
export function anonKeyCspResponse(
  pathname: string,
  requestHeaders: Headers,
  isDev: boolean,
): NextResponse | null {
  if (!isStrictCspPath(pathname)) return null;

  const nonce = crypto.randomUUID().replace(/-/g, "");
  const csp = buildAnonKeyCsp(nonce, isDev);

  const forwarded = new Headers(requestHeaders);
  forwarded.set("x-nonce", nonce);
  forwarded.set("content-security-policy", csp);

  const res = NextResponse.next({ request: { headers: forwarded } });
  res.headers.set("content-security-policy", csp);
  return res;
}
