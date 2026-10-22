// Package proxy forwards inspected requests to the upstream web server using
// httputil.ReverseProxy with Rewrite.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/smck83/phparmor/internal/telemetry"
)

// Target is the per-request forwarding information set by the server before
// handing the request to the proxy.
type Target struct {
	Upstream    *url.URL
	Peer        netip.Addr
	PeerTrusted bool
	RequestID   string
}

type targetKey struct{}

// WithTarget attaches t to ctx.
func WithTarget(ctx context.Context, t *Target) context.Context {
	return context.WithValue(ctx, targetKey{}, t)
}

func targetFrom(ctx context.Context) *Target {
	t, _ := ctx.Value(targetKey{}).(*Target)
	return t
}

// Balancer picks upstreams round robin.
type Balancer struct {
	urls []*url.URL
	next atomic.Uint64
}

// NewBalancer returns a balancer over urls, which must not be empty.
func NewBalancer(urls []*url.URL) *Balancer { return &Balancer{urls: urls} }

// Next returns the next upstream.
func (b *Balancer) Next() *url.URL {
	n := b.next.Add(1) - 1
	return b.urls[n%uint64(len(b.urls))]
}

// URLs returns all upstreams.
func (b *Balancer) URLs() []*url.URL { return b.urls }

// TransportOptions configures the upstream transport.
type TransportOptions struct {
	DialTimeout     time.Duration
	ResponseTimeout time.Duration
}

// NewTransport returns the upstream transport. Compression is disabled so the
// response passes through byte for byte, and environment proxies are ignored.
func NewTransport(o TransportOptions) *http.Transport {
	d := &net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   o.DialTimeout,
		ResponseHeaderTimeout: o.ResponseTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

// Options configures the reverse proxy.
type Options struct {
	Transport http.RoundTripper
	Logger    *slog.Logger
	// OnUpstreamResponse is called after every upstream round trip with the
	// upstream host, the time to response headers and whether it succeeded.
	OnUpstreamResponse func(upstream string, d time.Duration, ok bool)
}

// New returns a ReverseProxy that forwards to the Target in each request's
// context. The request body must already be buffered with an exact
// Content-Length.
func New(o Options) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:      rewrite,
		Transport:    &timedTransport{next: o.Transport, observe: o.OnUpstreamResponse},
		ErrorHandler: errorHandler(o.Logger),
		ErrorLog:     slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn),
	}
}

func rewrite(pr *httputil.ProxyRequest) {
	t := targetFrom(pr.In.Context())
	pr.SetURL(t.Upstream)
	// Keep the client's Host so nginx/Apache virtual hosts still match.
	pr.Out.Host = pr.In.Host

	// Never send Transfer-Encoding upstream; the server has already
	// buffered the body and set ContentLength.
	pr.Out.TransferEncoding = nil
	pr.Out.Header.Del("Transfer-Encoding")

	peer := t.Peer.String()
	if prior := pr.In.Header.Values("X-Forwarded-For"); t.PeerTrusted && len(prior) > 0 {
		pr.Out.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+peer)
	} else {
		pr.Out.Header.Set("X-Forwarded-For", peer)
	}
	proto := "http"
	if t.PeerTrusted {
		if p := pr.In.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
			proto = p
		}
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	if !t.PeerTrusted {
		// Client-supplied forwarding headers are spoofable.
		pr.Out.Header.Del("Forwarded")
		pr.Out.Header.Del("X-Real-IP")
	}
	pr.Out.Header.Set("X-Request-ID", t.RequestID)
}

func errorHandler(logger *slog.Logger) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		id := ""
		if ri := telemetry.Info(r.Context()); ri != nil {
			id = ri.ID
			ri.Reason = "upstream_error"
		}
		// url.Error includes the full URL (with query values); log only the
		// operation and the underlying error.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		logger.Warn("upstream error", "request_id", id, "error", err.Error())
		WriteError(w, http.StatusBadGateway, id)
	}
}

// WriteError writes a short plain-text error carrying only the request ID
// (SPEC section 4.1).
func WriteError(w http.ResponseWriter, status int, requestID string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(http.StatusText(status) + ". Request ID: " + requestID + "\n"))
}

type timedTransport struct {
	next    http.RoundTripper
	observe func(upstream string, d time.Duration, ok bool)
}

func (t *timedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	d := time.Since(start)
	if ri := telemetry.Info(req.Context()); ri != nil {
		ri.SetUpstream(req.URL.Host, d)
	}
	if t.observe != nil {
		t.observe(req.URL.Host, d, err == nil)
	}
	return resp, err
}
