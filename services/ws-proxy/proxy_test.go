package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// startEchoServer spins up a loopback TCP server that echoes bytes back. It
// returns the port and a cleanup func.
func startEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, func() { ln.Close() }
}

func testConfig(echoPort int) *Config {
	return &Config{
		Listen:               ":0",
		AllowedHosts:         parseHostSet("127.0.0.1"),
		AllowedPorts:         map[int]struct{}{echoPort: {}},
		MaxConnPerIP:         4,
		RatePerMinute:        10,
		DialTimeout:          5 * time.Second,
		MaxConnDuration:      10 * time.Second,
		MaxBytesPerDirection: 1 << 20,
		AllowPrivateTargets:  true, // loopback fixture
	}
}

func wsURL(httpURL, token string) string {
	u := strings.Replace(httpURL, "http://", "ws://", 1)
	return u + "/?token=" + token
}

func TestRelayEchoRoundTrip(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := "127.0.0.1:" + strconv.Itoa(echoPort)
	c, _, err := websocket.Dial(ctx, wsURL(srv.URL, token), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")

	payload := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	if err := c.Write(ctx, websocket.MessageBinary, payload); err != nil {
		t.Fatalf("ws write: %v", err)
	}

	// The echo server may return the bytes across one or more frames.
	got := make([]byte, 0, len(payload))
	for len(got) < len(payload) {
		typ, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("ws read: %v", err)
		}
		if typ != websocket.MessageBinary {
			t.Fatalf("expected binary frame, got %v", typ)
		}
		got = append(got, data...)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestRejectDisallowedHost(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	// 8.8.8.8 is not in the allowlist -> handshake must fail with 403.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL(srv.URL, "8.8.8.8:"+strconv.Itoa(echoPort)), nil)
	if err == nil {
		t.Fatal("expected dial against disallowed host to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", resp)
	}
}

func TestRejectDisallowedPort(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// port 22 is not in the allowlist.
	_, resp, err := websocket.Dial(ctx, wsURL(srv.URL, "127.0.0.1:22"), nil)
	if err == nil {
		t.Fatal("expected dial against disallowed port to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", resp)
	}
}

func TestPrivateIPGuardBlocksLoopbackByDefault(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	cfg.AllowPrivateTargets = false // the production default
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Host is allowlisted, but it resolves to loopback and the guard is on.
	_, resp, err := websocket.Dial(ctx, wsURL(srv.URL, "127.0.0.1:"+strconv.Itoa(echoPort)), nil)
	if err == nil {
		t.Fatal("expected loopback target to be blocked by the SSRF guard")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", resp)
	}
}

func TestMissingTokenIsBadRequest(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", resp.StatusCode)
	}
}

func TestHealthEndpoint(t *testing.T) {
	echoPort, stop := startEchoServer(t)
	defer stop()

	cfg := testConfig(echoPort)
	srv := httptest.NewServer(NewProxy(cfg))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /health, got %d", resp.StatusCode)
	}
}
