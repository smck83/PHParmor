// Package telemetry provides JSON logging, Prometheus metrics and per-request
// context (request ID, client IP, decisions) for the access log.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/smck83/phparmor/internal/policy"
)

// NewLogger returns a JSON slog logger at the given level ("debug", "info",
// "warn" or "error").
func NewLogger(w io.Writer, level string) (*slog.Logger, *slog.LevelVar) {
	lv := &slog.LevelVar{}
	_ = lv.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})), lv
}

// RequestInfo accumulates what the access log line reports about a request.
// It is created once per request and shared through the request context.
type RequestInfo struct {
	ID        string
	Start     time.Time
	ClientIP  string
	HostLabel string
	Route     string
	BytesIn   int64
	// Reason is a short, fixed reason for a rejection that is not tied to a
	// control (for example "unknown_host" or "overloaded").
	Reason string

	mu          sync.Mutex
	decisions   []policy.Decision
	upstreamDur time.Duration
	upstream    string
}

// AddDecision records a control decision.
func (ri *RequestInfo) AddDecision(d policy.Decision) {
	ri.mu.Lock()
	ri.decisions = append(ri.decisions, d)
	ri.mu.Unlock()
}

// Decisions returns a copy of the recorded decisions.
func (ri *RequestInfo) Decisions() []policy.Decision {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	return append([]policy.Decision{}, ri.decisions...)
}

// SetUpstream records which upstream served the request and how long it took.
func (ri *RequestInfo) SetUpstream(target string, d time.Duration) {
	ri.mu.Lock()
	ri.upstream, ri.upstreamDur = target, d
	ri.mu.Unlock()
}

// Upstream returns the upstream target and latency, if any.
func (ri *RequestInfo) Upstream() (string, time.Duration) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	return ri.upstream, ri.upstreamDur
}

type ctxKey struct{}

// WithInfo attaches ri to ctx.
func WithInfo(ctx context.Context, ri *RequestInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, ri)
}

// Info returns the RequestInfo attached to ctx, or nil.
func Info(ctx context.Context) *RequestInfo {
	ri, _ := ctx.Value(ctxKey{}).(*RequestInfo)
	return ri
}

// NewRequestID returns a random 32-character hex ID.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ValidRequestID reports whether an inbound X-Request-ID is safe to
// propagate: 1 to 128 characters from [A-Za-z0-9._-].
func ValidRequestID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
