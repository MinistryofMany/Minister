// Endpoint configuration for the prover. Defaults target the dev
// docker-compose stack as seen from the user's browser (host-published
// ports), and are overridable at bundle time via esbuild `define` of
// `process.env.MINISTER_*` (see build.mjs).

declare const process: { env: Record<string, string | undefined> };

function envOr(key: string, fallback: string): string {
  // `process.env.X` is statically replaced by esbuild define; the guard keeps
  // this safe if it is ever evaluated in a context without `process`.
  try {
    return process.env[key] ?? fallback;
  } catch {
    return fallback;
  }
}

export interface ProverEndpoints {
  // HTTP(S) URL of the TLSNotary notary-server. In dev compose it is
  // published on the host at :7047.
  notaryUrl: string;
  // WebSocket base URL of the ws-proxy relay. tlsn-js appends
  // `?token=<hostname>` itself, so this must NOT include a query string.
  websocketProxyUrl: string;
}

export const endpoints: ProverEndpoints = {
  notaryUrl: envOr("MINISTER_NOTARY_URL", "http://localhost:7047"),
  websocketProxyUrl: envOr("MINISTER_WS_PROXY_URL", "ws://localhost:55688"),
};
