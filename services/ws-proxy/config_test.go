package main

import (
	"net"
	"testing"
)

func TestParsePortSet(t *testing.T) {
	ports, err := parsePortSet("443, 8443 ,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := ports[443]; !ok {
		t.Errorf("expected 443 in set")
	}
	if _, ok := ports[8443]; !ok {
		t.Errorf("expected 8443 in set")
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ports))
	}

	if _, err := parsePortSet("nope"); err == nil {
		t.Errorf("expected error on non-numeric port")
	}
	if _, err := parsePortSet("70000"); err == nil {
		t.Errorf("expected error on out-of-range port")
	}
}

func TestHostAndPortAllowed(t *testing.T) {
	cfg := &Config{
		AllowedHosts: parseHostSet("id.me, GitHub.com"),
		AllowedPorts: map[int]struct{}{443: {}},
	}
	if !cfg.HostAllowed("id.me") {
		t.Errorf("id.me should be allowed")
	}
	if !cfg.HostAllowed("GITHUB.COM") {
		t.Errorf("host match should be case-insensitive")
	}
	if cfg.HostAllowed("evil.id.me") {
		t.Errorf("subdomain of an allowed host must NOT be allowed (exact match only)")
	}
	if cfg.HostAllowed("attacker.com") {
		t.Errorf("unlisted host must not be allowed")
	}
	if !cfg.PortAllowed(443) {
		t.Errorf("443 should be allowed")
	}
	if cfg.PortAllowed(22) {
		t.Errorf("22 must not be allowed")
	}
}

func TestIsDisallowedIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":          false, // public
		"1.1.1.1":          false, // public
		"127.0.0.1":        true,  // loopback
		"10.0.0.5":         true,  // private
		"192.168.1.1":      true,  // private
		"172.16.0.1":       true,  // private
		"169.254.1.1":      true,  // link-local
		"0.0.0.0":          true,  // unspecified
		"::1":              true,  // loopback v6
		"fc00::1":          true,  // private v6 (ULA)
		"fe80::1":          true,  // link-local v6
		"2606:4700:4700::": false, // public v6
	}
	for ipStr, want := range cases {
		ip := net.ParseIP(ipStr)
		if got := isDisallowedIP(ip); got != want {
			t.Errorf("isDisallowedIP(%s) = %t, want %t", ipStr, got, want)
		}
	}
	if !isDisallowedIP(nil) {
		t.Errorf("nil IP must be disallowed")
	}
}

func TestParseToken(t *testing.T) {
	h, p, err := parseToken("id.me")
	if err != nil || h != "id.me" || p != 443 {
		t.Errorf("bare host: got (%q, %d, %v), want (id.me, 443, nil)", h, p, err)
	}
	h, p, err = parseToken("github.com:8443")
	if err != nil || h != "github.com" || p != 8443 {
		t.Errorf("host:port: got (%q, %d, %v)", h, p, err)
	}
	if _, _, err := parseToken(""); err == nil {
		t.Errorf("empty token must error")
	}
	if _, _, err := parseToken("host:notaport"); err == nil {
		t.Errorf("non-numeric port must error")
	}
}
