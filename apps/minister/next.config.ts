import type { NextConfig } from "next";

// typedRoutes is intentionally OFF. It restricts redirect(url) to known
// internal route literals — which is fine inside Minister but blocks us
// from redirecting back to a relying party's redirect_uri at the OIDC
// boundary. The runtime accepts any URL; the TS restriction was the
// only thing in the way.
const config: NextConfig = {
  reactStrictMode: true,
  // Build-date stamp surfaced in the footer's "Beta" label. Resolved once at
  // build/start time (ISO date, no clock component) and inlined as a public env
  // var; the footer falls back to "dev" when it isn't set.
  env: {
    NEXT_PUBLIC_BUILD_DATE: new Date().toISOString().slice(0, 10),
  },
};

export default config;
