// Package server wires the listeners, the request pipeline, the admin
// endpoints and config hot reload together.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/smck83/phparmor/internal/config"
	"github.com/smck83/phparmor/internal/policy"
	"github.com/smck83/phparmor/internal/proxy"
	"github.com/smck83/phparmor/internal/spool"
	"github.com/smck83/phparmor/internal/telemetry"
)

// StopgapNotice must appear in the startup log, /version and the README
// (SPEC section 1).
const StopgapNotice = "PHParmor is a stopgap, not a fix: the only complete remediation for PHP2Shell " +
	"(CVE-2026-109618, CVE-2026-109619) is a patched PHP runtime."

// Options are the process-level inputs to the server.
type Options struct {
	Logger   *slog.Logger
	LogLevel *slog.LevelVar
	Version  string
	Commit   string
}

// Server is the PHParmor data plane and admin plane.
type Server struct {
	opts    Options
	log     *slog.Logger
	metrics *telemetry.Metrics
	budget  *spool.Budget
	proxy   *httputil.ReverseProxy
	health  health

	snap     atomic.Pointer[snapshot]
	inflight atomic.Int64
	// boot is the config the listeners and transport were built from;
	// settings in it that cannot change without a restart are compared on
	// reload.
	boot *config.Config
}

// snapshot is everything derived from one config version. Requests load it
// once and use it throughout, so a reload never mixes two configs.
type snapshot struct {
	cfg      *config.Config
	policy   *policy.Policy
	balancer *proxy.Balancer
	trusted  []netip.Prefix
}

func newSnapshot(cfg *config.Config) (*snapshot, error) {
	pol, err := policy.Compile(cfg)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	trusted, err := config.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trusted proxies: %w", err)
	}
	urls := make([]*url.URL, 0, len(cfg.Upstreams))
	for _, s := range cfg.Upstreams {
		u, err := config.ParseUpstream(s)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", s, err)
		}
		urls = append(urls, u)
	}
	return &snapshot{cfg: cfg, policy: pol, balancer: proxy.NewBalancer(urls), trusted: trusted}, nil
}

// New builds a server from a validated config.
func New(cfg *config.Config, opts Options) (*Server, error) {
	snap, err := newSnapshot(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:   opts,
		log:    opts.Logger,
		budget: spool.NewBudget(int64(cfg.Buffers.MemoryGlobal)),
		boot:   cfg,
	}
	s.metrics = telemetry.NewMetrics(func() float64 { return float64(s.budget.InFlight()) })
	s.proxy = proxy.New(proxy.Options{
		Transport: proxy.NewTransport(proxy.TransportOptions{
			DialTimeout:     cfg.Server.UpstreamDialTimeout,
			ResponseTimeout: cfg.Server.UpstreamResponseTimeout,
		}),
		Logger: s.log,
		OnUpstreamResponse: func(_ string, d time.Duration, ok bool) {
			s.metrics.UpstreamDuration.Observe(d.Seconds())
			if ok {
				s.health.markUpstreamOK()
			}
		},
	})
	s.snap.Store(snap)
	if opts.LogLevel != nil {
		_ = opts.LogLevel.UnmarshalText([]byte(cfg.LogLevel))
	}
	return s, nil
}

// Reload swaps in a new validated config. Settings that need a restart are
// reported in the log and keep their running values.
func (s *Server) Reload(cfg *config.Config) error {
	snap, err := newSnapshot(cfg)
	if err != nil {
		s.metrics.ConfigReloads.WithLabelValues("error").Inc()
		return err
	}
	for _, f := range restartOnlyChanges(s.boot, cfg) {
		s.log.Warn("config setting changed but needs a restart to apply", "setting", f)
	}
	s.snap.Store(snap)
	s.budget.SetLimit(int64(cfg.Buffers.MemoryGlobal))
	if s.opts.LogLevel != nil {
		_ = s.opts.LogLevel.UnmarshalText([]byte(cfg.LogLevel))
	}
	s.metrics.ConfigReloads.WithLabelValues("ok").Inc()
	return nil
}

// ReloadFile loads, validates and applies the config at path. On any error
// the running config is kept.
func (s *Server) ReloadFile(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		s.metrics.ConfigReloads.WithLabelValues("error").Inc()
		return err
	}
	return s.Reload(cfg)
}

func restartOnlyChanges(old, cur *config.Config) []string {
	var out []string
	add := func(changed bool, name string) {
		if changed {
			out = append(out, name)
		}
	}
	add(old.Listen != cur.Listen, "listen")
	add(old.AdminListen != cur.AdminListen, "admin_listen")
	add(old.Server.ReadHeaderTimeout != cur.Server.ReadHeaderTimeout, "server.read_header_timeout")
	add(old.Server.IdleTimeout != cur.Server.IdleTimeout, "server.idle_timeout")
	add(old.Server.MaxHeaderBytes != cur.Server.MaxHeaderBytes, "server.max_header_bytes")
	add(old.Server.UpstreamDialTimeout != cur.Server.UpstreamDialTimeout, "server.upstream_dial_timeout")
	add(old.Server.UpstreamResponseTimeout != cur.Server.UpstreamResponseTimeout, "server.upstream_response_timeout")
	add(old.Buffers.SpoolDir != cur.Buffers.SpoolDir, "buffers.spool_dir")
	add(old.State != cur.State, "state")
	return out
}

// Run starts the data and admin listeners and blocks until ctx is cancelled,
// then drains in-flight requests for up to shutdown_timeout.
func (s *Server) Run(ctx context.Context) error {
	cfg := s.boot
	if err := os.MkdirAll(cfg.Buffers.SpoolDir, 0o700); err != nil {
		return fmt.Errorf("create spool dir: %w", err)
	}

	dataLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("data listener: %w", err)
	}
	adminLn, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		_ = dataLn.Close()
		return fmt.Errorf("admin listener: %w", err)
	}

	errLog := slog.NewLogLogger(s.log.Handler(), slog.LevelWarn)
	data := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		ErrorLog:          errLog,
	}
	admin := &http.Server{
		Handler:           s.AdminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          errLog,
	}

	probeCtx, stopProbe := context.WithCancel(ctx)
	defer stopProbe()
	s.probeOnce(probeCtx)
	go s.probeLoop(probeCtx)

	errc := make(chan error, 2)
	go func() { errc <- data.Serve(dataLn) }()
	go func() { errc <- admin.Serve(adminLn) }()
	s.log.Info("listening", "data", dataLn.Addr().String(), "admin", adminLn.Addr().String())

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		runErr = fmt.Errorf("listener stopped: %w", err)
	}

	s.health.draining.Store(true)
	timeout := s.snap.Load().cfg.ShutdownTimeout
	s.log.Info("shutting down, draining in-flight requests", "timeout", timeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := data.Shutdown(sctx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("drain data listener: %w", err))
	}
	if err := admin.Shutdown(sctx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("stop admin listener: %w", err))
	}
	return runErr
}
