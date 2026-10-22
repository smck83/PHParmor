package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/smck83/phparmor/internal/config"
	"github.com/smck83/phparmor/internal/inspect/framing"
	"github.com/smck83/phparmor/internal/inspect/headers"
	"github.com/smck83/phparmor/internal/inspect/query"
	"github.com/smck83/phparmor/internal/policy"
	"github.com/smck83/phparmor/internal/proxy"
	"github.com/smck83/phparmor/internal/telemetry"
)

const maxLoggedPath = 2048

// ServeHTTP runs the request pipeline (SPEC section 4): connection limits,
// host and route policy, PA-FRAME, PA-HDR, PA-COOKIE-STRIP, PA-QUERY, body
// buffering with an exact Content-Length, and forwarding. Body controls
// arrive in M3 and M4.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := s.snap.Load()
	cfg := snap.cfg

	id := r.Header.Get("X-Request-ID")
	if !telemetry.ValidRequestID(id) {
		id = telemetry.NewRequestID()
	}
	peer := proxy.PeerAddr(r.RemoteAddr)
	ri := &telemetry.RequestInfo{
		ID:        id,
		Start:     time.Now(),
		ClientIP:  proxy.ClientIP(peer, r.Header.Values("X-Forwarded-For"), snap.trusted).String(),
		HostLabel: policy.LabelUnknownHost,
		Route:     "-",
	}
	ctx := telemetry.WithInfo(r.Context(), ri)
	r = r.WithContext(ctx)
	rec := &recorder{ResponseWriter: w}
	rec.Header().Set("X-Request-ID", id)
	defer s.finish(rec, r, ri)

	// 1. Global concurrency cap.
	n := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	if n > cfg.Server.MaxConcurrentRequests {
		s.reject(rec, ri, http.StatusServiceUnavailable, "overloaded")
		return
	}

	// 3-4. Host and route policy.
	m, ok := snap.policy.Resolve(r.Host, r.Method, r.URL.Path)
	if !ok {
		s.reject(rec, ri, snap.policy.UnknownHostStatus(), "unknown_host")
		return
	}
	ri.HostLabel, ri.Route = m.Host.Label, m.Route.Label
	route, lim := m.Route, m.Route.Limits

	// 2. Framing. It runs after host and route resolution because hosts and
	// routes can override its mode; resolution reads no body.
	if s.control(rec, ri, route, config.CtlFrame, func() *policy.Violation {
		return framing.Check(r, lim.NoBodyMethods)
	}) {
		return
	}

	// 5. Headers and cookies.
	if s.control(rec, ri, route, config.CtlHdr, func() *policy.Violation {
		return headers.Check(r.Header, headers.Limits{
			MaxHeaders:     lim.MaxHeaders,
			MaxHeaderValue: int64(lim.MaxHeaderValue),
			MaxCookies:     lim.MaxCookies,
			MaxCookieBytes: int64(lim.MaxCookieBytes),
			MaxCookieSize:  int64(lim.MaxCookieSize),
			MaxNesting:     lim.MaxNesting,
			MaxKeyLength:   lim.MaxKeyLength,
		})
	}) {
		return
	}
	s.stripCookies(r, ri, route, m.Host.CookieStrip)

	// 6. Query string (validated, forwarded unchanged).
	if s.control(rec, ri, route, config.CtlQuery, func() *policy.Violation {
		_, v := query.Check(r.URL.RawQuery, query.Limits{
			MaxVars:      lim.MaxVars,
			MaxNesting:   lim.MaxNesting,
			MaxKeyLength: lim.MaxKeyLength,
			MaxLength:    int64(lim.MaxQueryLength),
		})
		return v
	}) {
		return
	}

	// 7. Body: spooled (and canonicalised if multipart) so it is forwarded
	// with an exact Content-Length.
	body, rejected := s.prepareBody(rec, r, ri, cfg, route)
	defer body.Close()
	if rejected {
		return
	}
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")

	// 9. Forward.
	t := &proxy.Target{
		Upstream:    snap.balancer.Next(),
		Peer:        peer,
		PeerTrusted: proxy.Trusted(peer, snap.trusted),
		RequestID:   id,
	}
	s.proxy.ServeHTTP(rec, r.WithContext(proxy.WithTarget(ctx, t)))
}

// control runs one check under the route's mode for that control and records
// the decision. It returns true when the request was rejected. The check is
// not run when the control is off.
func (s *Server) control(w http.ResponseWriter, ri *telemetry.RequestInfo, route *policy.Route, id string, check func() *policy.Violation) bool {
	mode := route.Mode(id)
	if mode == config.ModeOff {
		return false
	}
	v := check()
	d, block, _ := policy.Evaluate(id, mode, v)
	ri.AddDecision(d)
	if block {
		s.reject(w, ri, v.Status, v.Reason)
	}
	return block
}

// stripCookies applies PA-COOKIE-STRIP: in enforce mode the named cookies
// are removed before forwarding; in monitor mode they are only reported.
func (s *Server) stripCookies(r *http.Request, ri *telemetry.RequestInfo, route *policy.Route, names []string) {
	mode := route.Mode(config.CtlCookieStrip)
	if mode == config.ModeOff || len(names) == 0 {
		return
	}
	cookie := r.Header.Get("Cookie")
	out, n := headers.StripCookies(cookie, names)
	d := policy.Decision{Control: config.CtlCookieStrip, Mode: mode, Outcome: policy.Pass}
	switch {
	case n == 0:
	case mode == config.ModeMonitor:
		d.Outcome, d.Reason = policy.WouldBlock, "would_strip_cookie"
	default:
		d.Outcome, d.Reason = policy.Modify, "cookie_stripped"
		if out == "" {
			r.Header.Del("Cookie")
		} else {
			r.Header.Set("Cookie", out)
		}
	}
	ri.AddDecision(d)
}

func (s *Server) reject(w http.ResponseWriter, ri *telemetry.RequestInfo, status int, reason string) {
	ri.Reason = reason
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	proxy.WriteError(w, status, ri.ID)
}

// finish writes the access log line and request metrics.
func (s *Server) finish(rec *recorder, r *http.Request, ri *telemetry.RequestInfo) {
	total := time.Since(ri.Start)
	upstream, upDur := ri.Upstream()
	decisions := ri.Decisions()
	for _, d := range decisions {
		s.metrics.Decisions.WithLabelValues(d.Control, string(d.Outcome)).Inc()
	}
	status := strconv.Itoa(rec.status)
	s.metrics.Requests.WithLabelValues(ri.HostLabel, ri.Route, status).Inc()
	s.metrics.RequestDuration.Observe(total.Seconds())

	path := r.URL.Path
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath]
	}
	attrs := []slog.Attr{
		slog.String("request_id", ri.ID),
		slog.String("host", ri.HostLabel),
		slog.String("route", ri.Route),
		slog.String("method", r.Method),
		slog.String("path", path),
		slog.Int("status", rec.status),
		slog.Int64("bytes_in", ri.BytesIn),
		slog.Int64("bytes_out", rec.bytes),
		slog.String("client_ip", ri.ClientIP),
		slog.Float64("total_ms", float64(total.Microseconds())/1000),
		slog.Any("decisions", decisions),
	}
	if upstream != "" {
		attrs = append(attrs,
			slog.String("upstream", upstream),
			slog.Float64("upstream_ms", float64(upDur.Microseconds())/1000))
	}
	if ri.Reason != "" {
		attrs = append(attrs, slog.String("reason", ri.Reason))
	}
	s.log.LogAttrs(r.Context(), slog.LevelInfo, "access", attrs...)
}

// recorder captures the final status and bytes written for the access log.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && code >= 200 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
