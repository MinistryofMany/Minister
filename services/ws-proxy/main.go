package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	healthCheck := flag.Bool("health-check", false, "probe the local /health endpoint and exit 0/1 (for the distroless container healthcheck)")
	flag.Parse()
	if *healthCheck {
		os.Exit(runHealthCheck())
	}

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	proxy := NewProxy(cfg)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf(
		"ws-proxy listening on %s; allowed hosts=[%s] ports=[%s] maxConnPerIP=%d ratePerMin=%d allowPrivate=%t",
		cfg.Listen,
		strings.Join(sortedHosts(cfg), ", "),
		sortedPorts(cfg),
		cfg.MaxConnPerIP,
		cfg.RatePerMinute,
		cfg.AllowPrivateTargets,
	)
	if cfg.AllowPrivateTargets {
		log.Printf("WARNING: WS_PROXY_ALLOW_PRIVATE_TARGETS is set — private/loopback targets are permitted. Do not use in production.")
	}

	idle := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
		close(idle)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen error: %v", err)
	}
	<-idle
	log.Printf("ws-proxy stopped")
}

// runHealthCheck probes the local /health endpoint. It reads the same
// WS_PROXY_LISTEN the server uses so it targets the right port. Returns a
// process exit code.
func runHealthCheck() int {
	listen := envStr("WS_PROXY_LISTEN", ":55688")
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		log.Printf("health-check: bad WS_PROXY_LISTEN %q: %v", listen, err)
		return 1
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/health")
	if err != nil {
		log.Printf("health-check: %v", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func sortedHosts(cfg *Config) []string {
	hosts := make([]string, 0, len(cfg.AllowedHosts))
	for h := range cfg.AllowedHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func sortedPorts(cfg *Config) string {
	ports := make([]int, 0, len(cfg.AllowedPorts))
	for p := range cfg.AllowedPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ", ")
}
