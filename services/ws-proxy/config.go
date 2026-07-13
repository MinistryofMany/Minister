package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration for the proxy, sourced from the
// environment. Every field has a safe default; the one field that widens
// the security posture (AllowPrivateTargets) defaults to false and is only
// meant for local integration tests.
type Config struct {
	Listen string

	// AllowedHosts is the exact-match allowlist of target hostnames. A
	// connection whose token host is not in this set is refused. This is
	// what keeps the relay from becoming an open proxy.
	AllowedHosts map[string]struct{}
	// AllowedPorts is the set of TCP ports the relay may dial.
	AllowedPorts map[int]struct{}

	MaxConnPerIP    int
	RatePerMinute   int
	DialTimeout     time.Duration
	MaxConnDuration time.Duration
	// MaxBytesPerDirection caps bytes relayed each way per connection. 0
	// disables the cap.
	MaxBytesPerDirection int64

	// AllowPrivateTargets disables the private/loopback/link-local IP guard.
	// DANGEROUS: only for local tests that dial a loopback fixture server.
	AllowPrivateTargets bool
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer: %w", key, v, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration: %w", key, v, err)
	}
	return d, nil
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseHostSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, h := range strings.Split(raw, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

func parsePortSet(raw string) (map[int]struct{}, error) {
	out := map[int]struct{}{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("port %q is not an integer: %w", p, err)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port %d out of range", n)
		}
		out[n] = struct{}{}
	}
	return out, nil
}

// LoadConfig reads configuration from the environment, applying defaults.
func LoadConfig() (*Config, error) {
	ports, err := parsePortSet(envStr("WS_PROXY_ALLOWED_PORTS", "443"))
	if err != nil {
		return nil, err
	}
	maxConnPerIP, err := envInt("WS_PROXY_MAX_CONN_PER_IP", 8)
	if err != nil {
		return nil, err
	}
	ratePerMin, err := envInt("WS_PROXY_RATE_PER_MIN", 30)
	if err != nil {
		return nil, err
	}
	dialTimeout, err := envDuration("WS_PROXY_DIAL_TIMEOUT", 10*time.Second)
	if err != nil {
		return nil, err
	}
	maxDur, err := envDuration("WS_PROXY_MAX_CONN_DURATION", 120*time.Second)
	if err != nil {
		return nil, err
	}
	maxBytes, err := envInt("WS_PROXY_MAX_BYTES_PER_DIRECTION", 16*1024*1024)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Listen:               envStr("WS_PROXY_LISTEN", ":55688"),
		AllowedHosts:         parseHostSet(envStr("WS_PROXY_ALLOWED_HOSTS", "id.me,github.com")),
		AllowedPorts:         ports,
		MaxConnPerIP:         maxConnPerIP,
		RatePerMinute:        ratePerMin,
		DialTimeout:          dialTimeout,
		MaxConnDuration:      maxDur,
		MaxBytesPerDirection: int64(maxBytes),
		AllowPrivateTargets:  envBool("WS_PROXY_ALLOW_PRIVATE_TARGETS", false),
	}
	if len(cfg.AllowedHosts) == 0 {
		return nil, fmt.Errorf("WS_PROXY_ALLOWED_HOSTS is empty: refusing to run as an open proxy")
	}
	if len(cfg.AllowedPorts) == 0 {
		return nil, fmt.Errorf("WS_PROXY_ALLOWED_PORTS is empty")
	}
	return cfg, nil
}

// HostAllowed reports whether host is in the exact-match allowlist.
func (c *Config) HostAllowed(host string) bool {
	_, ok := c.AllowedHosts[strings.ToLower(host)]
	return ok
}

// PortAllowed reports whether port is in the allowlist.
func (c *Config) PortAllowed(port int) bool {
	_, ok := c.AllowedPorts[port]
	return ok
}

// isDisallowedIP reports whether an IP must not be dialed. Blocks loopback,
// private, link-local, unspecified, and multicast ranges as SSRF defense in
// depth (the host allowlist is the primary guard; this catches a poisoned or
// rebinding DNS answer for an allowlisted host).
func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
