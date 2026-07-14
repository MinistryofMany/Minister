# TLSNotary classic model — prod deploy (Lightsail box)

How to bring the Stage 6 TLSNotary stack up on the prod Lightsail box. The box
compose (`/home/ec2-user/ministry/docker-compose.lightsail.yml`, compose project
`ministry`) is edited **by hand** — merging to `main` only builds+pushes images,
it does not touch the box. Do the steps below over SSH.

All three components are pinned to `v0.1.0-alpha.11` and must move in lockstep
(notary image tag ↔ `tlsn-core` tag in `services/tlsn-verifier/Cargo.toml` ↔
`tlsn-js` version in `apps/extension/package.json`).

## What runs where

- **notary** — the upstream `ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11`
  image. **We do not build it.** Co-signs the TLS session for the extension.
- **ws-proxy** — our image, `ghcr.io/ministryofmany/ministry-ws-proxy:latest`.
  WS→TCP relay the browser extension tunnels its TLS session through. Built+pushed
  by `.github/workflows/build-tlsn-images.yml`.
- **tlsn-verifier** — our image,
  `ghcr.io/ministryofmany/ministry-tlsn-verifier:latest`. Rust HTTP sidecar
  Minister calls to verify the finalized presentation. Same workflow.

Minister talks **only** to `tlsn-verifier` (server-to-server, `TLSN_VERIFIER_URL`).
The extension (in the user's browser) talks to `notary` and `ws-proxy` via their
public URLs, baked in at extension build time — not runtime env on the box.

## 1. Pull the images

The two `ministry-*` images are built by GitHub Actions on any push under
`services/{ws-proxy,tlsn-verifier}/**`; the notary is pulled straight from
upstream. On the box:

```sh
cd /home/ec2-user/ministry
docker pull ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11
docker compose -f docker-compose.lightsail.yml pull ws-proxy tlsn-verifier
```

(If the `ministry-*` images are missing, trigger the workflow: Actions →
`build-tlsn-images` → Run workflow, or push a change under those service dirs.)

## 2. Get the notary's public key (required for real mode)

`tlsn-verifier` in `real` mode pins the notary key, so it trusts **only our**
notary's signatures and fails closed on anyone else's. Bring the notary up first,
then read its key:

```sh
docker compose -f docker-compose.lightsail.yml up -d notary
# the /info endpoint returns the notary's verifying key
curl -s http://localhost:7047/info
```

Take the hex public key (optional `0x` prefix is accepted) — that is
`TLSN_NOTARY_PUBLIC_KEY` below. If unset, `VERIFIER_MODE=real` **refuses to
start**.

## 3. Add the three services to the box compose

Append to `docker-compose.lightsail.yml` (compose project `ministry`). No host
port publishing is needed for `tlsn-verifier` (Minister reaches it on the compose
network); `notary` and `ws-proxy` are reached by browsers, so publish them behind
the existing Cloudflare tunnel (route `notary.ministry.id` → `notary:7047` and
`wsproxy.ministry.id` → `ws-proxy:55688`, or whatever hostnames the extension
build is pinned to).

```yaml
  notary:
    image: ghcr.io/tlsnotary/notary-server:v0.1.0-alpha.11
    restart: unless-stopped
    volumes:
      - notary_data:/data
    # exposed to browsers via the Cloudflare tunnel (7047)

  ws-proxy:
    image: ghcr.io/ministryofmany/ministry-ws-proxy:latest
    restart: unless-stopped
    environment:
      WS_PROXY_LISTEN: ":55688"
      # EXACT-match target allowlist (no subdomains). Only the hosts a
      # deployed plugin actually proves against. Empty => refuses to start.
      WS_PROXY_ALLOWED_HOSTS: "id.me,github.com"
      WS_PROXY_ALLOWED_PORTS: "443"
    # exposed to browsers via the Cloudflare tunnel (55688)

  tlsn-verifier:
    image: ghcr.io/ministryofmany/ministry-tlsn-verifier:latest
    restart: unless-stopped
    environment:
      # `real` is the binary's DEFAULT — this line is belt-and-suspenders, not
      # the thing standing between prod and a rubber-stamp. Passthrough now
      # requires a loud opt-in (VERIFIER_MODE=passthrough + ALLOW_INSECURE_PASSTHROUGH=1,
      # or TLSN_DEV=1), so a missing/mistyped VERIFIER_MODE fails closed to `real`.
      VERIFIER_MODE: "real"
      RUST_LOG: "info"
      TLSN_NOTARY_PUBLIC_KEY: "<hex from step 2>"
    # no ports: — Minister reaches it in-network as http://tlsn-verifier:7048

volumes:
  notary_data:
```

`real` mode (the default) is the whole point of the classic model: it runs
`tlsn-core`'s `Presentation::verify` (notary signature + server-identity/cert
chain + transcript proof), masks unrevealed bytes with `X`, binds the server name
to the plugin's `expectedDomain`, and returns `Err` on anything it can't
cryptographically verify. `passthrough` is dev-only and would trust a
client-supplied JSON transcript; it is unreachable without a deliberate
`VERIFIER_MODE=passthrough` **and** `ALLOW_INSECURE_PASSTHROUGH=1` (or `TLSN_DEV=1`)
— never set those in prod. Defense in depth: even if a keyless passthrough
sidecar were somehow in the loop, Minister rejects any transcript with an
absent/empty `notaryKey`, and (when `MINISTER_TLSN_EXPECTED_NOTARY_KEY` is set)
any transcript whose notary key doesn't match the pin — so no badge is issued.

## 4. Point Minister at the verifier

Add to the `minister` service env in the box compose, then recreate it:

```yaml
environment:
  # ... existing minister env ...
  TLSN_VERIFIER_URL: "http://tlsn-verifier:7048"
  # SSRF allowlist for the verifier host (silences the boot nag, enforces the host)
  MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS: "tlsn-verifier"
  # Optional defense-in-depth pin: require the verified transcript's notary key
  # to equal this exact hex (constant-time compare). Recommended — set it to the
  # same key as the verifier's TLSN_NOTARY_PUBLIC_KEY. A keyless (passthrough)
  # transcript is ALWAYS rejected regardless of this var.
  MINISTER_TLSN_EXPECTED_NOTARY_KEY: "<hex from step 2>"
  # Origins allowed to POST /api/tlsn/submit — the published extension's
  # chrome-extension://<id> origin(s), comma-separated. Fail-closed: an
  # unknown Origin is rejected.
  TLSN_SUBMIT_ALLOWED_ORIGINS: "chrome-extension://<published-extension-id>"
```

Minister already **fails closed** on the app side: `verifyPresentation` POSTs to
the sidecar and any rejection (non-2xx, `{ok:false}`, unreachable, bad shape)
throws, so the `tlsn-attestation` plugin returns `error` and **no badge is
issued**. There is no passthrough path inside Minister — the real-vs-passthrough
switch lives only on the sidecar (`VERIFIER_MODE`).

## 5. Bring the stack up

```sh
cd /home/ec2-user/ministry
docker compose -f docker-compose.lightsail.yml up -d notary ws-proxy tlsn-verifier
docker compose -f docker-compose.lightsail.yml up -d minister   # recreate with new env
```

Verify:

```sh
docker compose -f docker-compose.lightsail.yml logs --tail=20 tlsn-verifier   # must NOT say "refusing to start" (missing notary key)
curl -s http://localhost:7047/info                                            # notary up
# tlsn-verifier /health is on the compose network; exec into minister to hit it if needed
docker compose -f docker-compose.lightsail.yml exec minister wget -qO- http://tlsn-verifier:7048/health
```

## 6. Extension build (out of band, not on the box)

The extension is not a box service; users install it. Build it pinned at the
public notary + ws-proxy URLs (the box exposes them via the Cloudflare tunnel):

```sh
cd apps/extension
MINISTER_NOTARY_URL="https://notary.ministry.id" \
MINISTER_WS_PROXY_URL="wss://wsproxy.ministry.id" \
pnpm run build
```

`WS_PROXY_ALLOWED_HOSTS` on the box must include every host the extension proves
against, and `TLSN_SUBMIT_ALLOWED_ORIGINS` on Minister must include the published
extension's origin, or submissions are rejected.

## Re-pinning the tlsn version

Bump all three together: the notary image tag in `services/notary/Dockerfile`
(and this doc's `docker pull`), the `tlsn-core` git tag in
`services/tlsn-verifier/Cargo.toml` (+ `cargo update` → `Cargo.lock`), and
`tlsn-js` in `apps/extension/package.json`. Mismatched versions fail closed
(attestation/presentation formats won't match).
