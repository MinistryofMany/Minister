package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Proxy is an HTTP handler that upgrades a request to WebSocket and relays it,
// as a raw byte stream, to an allowlisted TCP target. The target is named in
// the `token` query parameter as `host` or `host:port` (default port 443),
// matching the convention tlsn-js uses for its websocket proxy URL.
type Proxy struct {
	cfg     *Config
	limiter *ipLimiter
	// resolve is the DNS resolver hook (overridable in tests).
	resolve func(ctx context.Context, host string) ([]net.IPAddr, error)
	// dial opens a TCP connection to an already-validated ip:port
	// (overridable in tests).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewProxy(cfg *Config) *Proxy {
	d := &net.Dialer{Timeout: cfg.DialTimeout}
	return &Proxy{
		cfg:     cfg,
		limiter: newIPLimiter(cfg.RatePerMinute, cfg.MaxConnPerIP),
		resolve: net.DefaultResolver.LookupIPAddr,
		dial:    d.DialContext,
	}
}

// parseToken extracts and splits the `token` query param into host and port,
// defaulting the port to 443.
func parseToken(raw string) (host string, port int, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("missing token query parameter")
	}
	if !strings.Contains(raw, ":") {
		return raw, 443, nil
	}
	h, p, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		return "", 0, errors.New("token is not a valid host:port")
	}
	n, convErr := strconv.Atoi(p)
	if convErr != nil {
		return "", 0, errors.New("token port is not a number")
	}
	return h, n, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		return
	}

	host, port, err := parseToken(r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.cfg.HostAllowed(host) {
		// Do not echo the host back verbatim beyond what the caller sent.
		http.Error(w, "target host not allowed", http.StatusForbidden)
		return
	}
	if !p.cfg.PortAllowed(port) {
		http.Error(w, "target port not allowed", http.StatusForbidden)
		return
	}

	ip := clientIP(r)
	release, ok := p.limiter.acquire(ip)
	if !ok {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer release()

	// Resolve and validate the target IP BEFORE the websocket upgrade, so a
	// rejected target gets a clean HTTP error rather than a socket close.
	addr, err := p.resolveAllowedAddr(r.Context(), host, port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// NOTE: in coder/websocket this flag skips the WebSocket *Origin*
		// header check only — it has nothing to do with TLS. This handler
		// terminates no TLS; the target's TLS runs end-to-end inside the
		// relayed bytes (that is what TLSNotary attests). The extension
		// connects from a chrome-extension:// origin, so the same-origin
		// model does not apply; access is gated by the host allowlist and
		// per-IP rate limiter above, not by Origin.
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("ws accept failed for %s: %v", ip, err)
		return
	}
	// 1 MiB is well above a single TLS record; caps a hostile huge frame.
	c.SetReadLimit(1 << 20)

	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.MaxConnDuration)
	defer cancel()

	tcp, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		log.Printf("dial %s failed: %v", addr, err)
		_ = c.Close(websocket.StatusTryAgainLater, "upstream dial failed")
		return
	}
	defer tcp.Close()

	log.Printf("relay open ip=%s target=%s", ip, net.JoinHostPort(host, strconv.Itoa(port)))
	p.relay(ctx, cancel, c, tcp)
	log.Printf("relay close ip=%s target=%s", ip, net.JoinHostPort(host, strconv.Itoa(port)))
}

// resolveAllowedAddr resolves host and returns the first IP that passes the
// SSRF guard, as an ip:port string. Dialing the resolved IP directly (rather
// than the hostname) closes the TOCTOU window between validation and dial.
func (p *Proxy) resolveAllowedAddr(ctx context.Context, host string, port int) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	ips, err := p.resolve(rctx, host)
	if err != nil {
		return "", errors.New("could not resolve target host")
	}
	for _, ipa := range ips {
		if p.cfg.AllowPrivateTargets || !isDisallowedIP(ipa.IP) {
			return net.JoinHostPort(ipa.IP.String(), strconv.Itoa(port)), nil
		}
	}
	return "", errors.New("target resolves only to disallowed addresses")
}

// relay pumps bytes in both directions until either side closes, an error
// occurs, a byte cap is hit, or the context deadline fires.
func (p *Proxy) relay(ctx context.Context, cancel context.CancelFunc, c *websocket.Conn, tcp net.Conn) {
	done := make(chan struct{}, 2)

	// WebSocket -> TCP
	go func() {
		defer func() { done <- struct{}{} }()
		var sent int64
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if typ != websocket.MessageBinary {
				// tlsn relays raw TLS bytes as binary frames; ignore others.
				continue
			}
			if p.cfg.MaxBytesPerDirection > 0 {
				sent += int64(len(data))
				if sent > p.cfg.MaxBytesPerDirection {
					return
				}
			}
			if _, err := tcp.Write(data); err != nil {
				return
			}
		}
	}()

	// TCP -> WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		var recv int64
		for {
			if p.cfg.MaxConnDuration > 0 {
				_ = tcp.SetReadDeadline(time.Now().Add(p.cfg.MaxConnDuration))
			}
			n, err := tcp.Read(buf)
			if n > 0 {
				if p.cfg.MaxBytesPerDirection > 0 {
					recv += int64(n)
					if recv > p.cfg.MaxBytesPerDirection {
						return
					}
				}
				if werr := c.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// First side to finish tears down the other.
	<-done
	cancel()
	_ = tcp.SetReadDeadline(time.Now())
	_ = c.Close(websocket.StatusNormalClosure, "relay closed")
	<-done
}
