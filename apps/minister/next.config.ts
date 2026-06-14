import type { NextConfig } from "next";

// typedRoutes is intentionally OFF. It restricts redirect(url) to known
// internal route literals — which is fine inside Minister but blocks us
// from redirecting back to a relying party's redirect_uri at the OIDC
// boundary. The runtime accepts any URL; the TS restriction was the
// only thing in the way.
const config: NextConfig = {
  reactStrictMode: true,
};

export default config;
