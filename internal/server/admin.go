package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// health tracks the inputs to /readyz.
type health struct {
	lastUpstreamOK atomic.Int64 // unix nanoseconds
	spoolOK        atomic.Bool
	draining       atomic.Bool
}

func (h *health) markUpstreamOK() { h.lastUpstreamOK.Store(time.Now().UnixNano()) }

// readiness returns the reasons the server is not ready, if any.
func (s *Server) readiness() []string {
	var reasons []string
	if s.health.draining.Load() {
		reasons = append(reasons, "draining")
	}
	if !s.health.spoolOK.Load() {
		reasons = append(reasons, "spool directory not writable")
	}
	window := s.snap.Load().cfg.Server.ReadyWindow
	last := s.health.lastUpstreamOK.Load()
	if last == 0 || time.Since(time.Unix(0, last)) > window {
		reasons = append(reasons, "no upstream reachable within "+window.String())
	}
	return reasons
}

func (s *Server) probeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.snap.Load().cfg.Server.UpstreamProbeInterval):
			s.probeOnce(ctx)
		}
	}
}

// probeOnce checks that each upstream accepts TCP connections and that the
// spool directory is writable.
func (s *Server) probeOnce(ctx context.Context) {
	snap := s.snap.Load()
	d := net.Dialer{Timeout: snap.cfg.Server.UpstreamDialTimeout}
	var wg sync.WaitGroup
	for _, u := range snap.balancer.URLs() {
		addr := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			addr = net.JoinHostPort(u.Hostname(), port)
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				s.log.Debug("upstream probe failed", "upstream", addr, "error", err.Error())
				return
			}
			_ = conn.Close()
			s.health.markUpstreamOK()
		}(addr)
	}
	wg.Wait()

	f, err := os.CreateTemp(s.boot.Buffers.SpoolDir, ".readyz-*")
	if err == nil {
		name := f.Name()
		_ = f.Close()
		err = os.Remove(name)
	}
	if err != nil && s.health.spoolOK.Load() {
		s.log.Warn("spool directory not writable", "error", err.Error())
	}
	s.health.spoolOK.Store(err == nil)
}

// AdminHandler serves /healthz, /readyz, /metrics and /version. It must never
// be exposed publicly.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if reasons := s.readiness(); len(reasons) > 0 {
			writeText(w, http.StatusServiceUnavailable, "not ready: "+strings.Join(reasons, "; ")+"\n")
			return
		}
		writeText(w, http.StatusOK, "ready\n")
	})
	mux.Handle("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name":    "phparmor",
			"version": s.opts.Version,
			"commit":  s.opts.Commit,
			"go":      runtime.Version(),
			"notice":  StopgapNotice,
		})
	})
	return mux
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
