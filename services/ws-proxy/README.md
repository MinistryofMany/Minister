# ws-proxy

A small WebSocket -> TCP relay so the Minister browser extension can reach external HTTPS servers (id.me, github.com, …) during a TLSNotary proof. A browser extension cannot open raw TCP sockets, so `tlsn-js` tunnels the TLS session through this proxy. Running our own lets us control the target allowlist, rate limits, and access logs — it is **not** an open proxy.

## Protocol

The extension's `tlsn-js` prover is configured with a `websocketProxyUrl`. The relay reads the target from the `token` query parameter, matching the convention used by the public PSE notary proxy (`wss://notary.pse.dev/proxy?token=<host>`):

```
ws://ws-proxy:55688/?token=<host>[:<port>]
```

- `token` host must be in the exact-match allowlist (`WS_PROXY_ALLOWED_HOSTS`). Subdomains of an allowed host are **not** allowed — only exact matches.
- `token` port defaults to `443` and must be in `WS_PROXY_ALLOWED_PORTS`.
- Frames are relayed verbatim as binary WebSocket messages in both directions. The proxy sees only ciphertext — TLS runs end-to-end between `tlsn-js` and the target, which is the whole point of TLSNotary.
- `GET /health` returns `200 ok`.

## Not an open proxy — the guards

1. **Exact-match host allowlist** (`WS_PROXY_ALLOWED_HOSTS`). Empty => the process refuses to start.
2. **Port allowlist** (`WS_PROXY_ALLOWED_PORTS`, default `443`).
3. **SSRF / DNS-rebind guard.** The target hostname is resolved and the proxy dials the resolved **IP** directly (closing the TOCTOU window). Loopback, private (RFC1918 / ULA), link-local, multicast, and unspecified addresses are refused even for an allowlisted host. Override only for local tests via `WS_PROXY_ALLOW_PRIVATE_TARGETS=true` (logs a warning).
4. **Per-IP rate limit** (`WS_PROXY_RATE_PER_MIN`, default 30 new conns/min) and **per-IP concurrency ceiling** (`WS_PROXY_MAX_CONN_PER_IP`, default 8).
5. **Per-connection caps:** max duration (`WS_PROXY_MAX_CONN_DURATION`, default 120s) and max bytes each direction (`WS_PROXY_MAX_BYTES_PER_DIRECTION`, default 16 MiB).

## Configuration

| Env                                | Default            | Meaning                                                 |
| ---------------------------------- | ------------------ | ------------------------------------------------------- |
| `WS_PROXY_LISTEN`                  | `:55688`           | listen address                                          |
| `WS_PROXY_ALLOWED_HOSTS`           | `id.me,github.com` | exact-match target host allowlist (required, non-empty) |
| `WS_PROXY_ALLOWED_PORTS`           | `443`              | target port allowlist                                   |
| `WS_PROXY_MAX_CONN_PER_IP`         | `8`                | concurrent connections per client IP                    |
| `WS_PROXY_RATE_PER_MIN`            | `30`               | new connections per client IP per minute                |
| `WS_PROXY_DIAL_TIMEOUT`            | `10s`              | upstream TCP dial timeout                               |
| `WS_PROXY_MAX_CONN_DURATION`       | `120s`             | max lifetime of one relayed connection                  |
| `WS_PROXY_MAX_BYTES_PER_DIRECTION` | `16777216`         | byte cap each direction (0 = unlimited)                 |
| `WS_PROXY_ALLOW_PRIVATE_TARGETS`   | `false`            | **test only** — disables the private-IP guard           |

Client IP for the limiter is the socket `RemoteAddr`. If the proxy is ever fronted by another reverse proxy, put the rate limiting there or extend this to trust a forwarded header.

## Run

```
cd services/ws-proxy
go test ./...           # unit + integration (loopback echo relay)
go run .                # starts on :55688 with the default allowlist
```

In docker-compose the `ws-proxy` service is enabled and exposes `55688`.

## Tests

`go test ./...` covers the allowlist (exact match, case-insensitivity, subdomain rejection), port gating, the SSRF/private-IP guard, the rate limiter (window rollover + concurrency ceiling + idempotent release), token parsing, and a full binary round-trip through the relay against a loopback echo server.
