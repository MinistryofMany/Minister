# Stage 6: WebSocket -> TCP relay between the browser extension and the
# target HTTPS server (e.g. id.me). The extension can't open raw TCP
# sockets, so tlsn-js tunnels the TLS session through this proxy.
FROM golang:1.26-alpine AS builder
WORKDIR /build

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
# CGO off for a static binary; strip symbols.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /ws-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /ws-proxy /ws-proxy
EXPOSE 55688
# Defaults live in config.go; override any WS_PROXY_* var via compose/env.
ENV WS_PROXY_LISTEN=:55688
ENTRYPOINT ["/ws-proxy"]
