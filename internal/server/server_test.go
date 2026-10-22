package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smck83/phparmor/internal/config"
)

// seen is what the test upstream observed about a forwarded request.
type seen struct {
	Method           string
	Path             string
	RawQuery         string
	Host             string
	ContentLength    int64
	TransferEncoding []string
	Header           http.Header
	Body             string
}

func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		_ = json.NewEncoder(w).Encode(seen{
			Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Host: r.Host,
			ContentLength: r.ContentLength, TransferEncoding: r.TransferEncoding,
			Header: r.Header, Body: string(body),
		})
	}))
	t.Cleanup(up.Close)
	return up
}

type harness struct {
	srv   *Server
	front *httptest.Server
	logs  *syncBuffer
}

func newHarness(t *testing.T, upstream string, mod func(*config.Config)) *harness {
	t.Helper()
	cfg := testConfig(t, upstream, mod)
	logs := &syncBuffer{}
	srv, err := New(cfg, Options{Logger: slog.New(slog.NewJSONHandler(logs, nil)), Version: "test", Commit: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(srv)
	t.Cleanup(front.Close)
	return &harness{srv: srv, front: front, logs: logs}
}

func testConfig(t *testing.T, upstream string, mod func(*config.Config)) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Upstreams = []string{upstream}
	cfg.Buffers.SpoolDir = t.TempDir()
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (h *harness) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func decode(t *testing.T, body string) seen {
	t.Helper()
	var s seen
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("upstream response %q: %v", body, err)
	}
	return s
}

func TestPassThrough(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	req, _ := http.NewRequest("POST", h.front.URL+"/a/b.php?x=1&y[]=2", strings.NewReader("k=v&k2=v2"))
	req.Host = "app.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=6.6.6.6")
	req.Header.Set("X-Real-IP", "6.6.6.6")

	resp, body := h.do(t, req)
	if resp.StatusCode != 200 || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	s := decode(t, body)
	if s.Method != "POST" || s.Path != "/a/b.php" || s.RawQuery != "x=1&y[]=2" || s.Body != "k=v&k2=v2" {
		t.Errorf("request altered: %+v", s)
	}
	if s.Host != "app.example.com" {
		t.Errorf("Host = %q, want client Host preserved", s.Host)
	}
	if s.ContentLength != 9 || len(s.TransferEncoding) != 0 {
		t.Errorf("framing: CL=%d TE=%v", s.ContentLength, s.TransferEncoding)
	}
	// The test client is an untrusted peer: its forwarding headers are dropped.
	if got := s.Header.Get("X-Forwarded-For"); got != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q", got)
	}
	if got := s.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q", got)
	}
	if s.Header.Get("Forwarded") != "" || s.Header.Get("X-Real-IP") != "" {
		t.Errorf("spoofable headers forwarded: %v", s.Header)
	}
	id := resp.Header.Get("X-Request-ID")
	if len(id) != 32 || s.Header.Get("X-Request-ID") != id {
		t.Errorf("request ID: response %q upstream %q", id, s.Header.Get("X-Request-ID"))
	}
}

func TestTrustedPeerForwardingHeaders(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
	})
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Request-ID", "abc-123")
	_, body := h.do(t, req)
	s := decode(t, body)
	if got := s.Header.Get("X-Forwarded-For"); got != "198.51.100.7, 127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q", got)
	}
	if got := s.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q", got)
	}
	if got := s.Header.Get("X-Request-ID"); got != "abc-123" {
		t.Errorf("X-Request-ID = %q", got)
	}
	if !strings.Contains(h.logs.String(), `"client_ip":"198.51.100.7"`) {
		t.Errorf("access log missing resolved client IP: %s", h.logs.String())
	}
}

func TestInvalidRequestIDReplaced(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	req.Header.Set("X-Request-ID", "bad id\"with{junk}")
	resp, _ := h.do(t, req)
	if id := resp.Header.Get("X-Request-ID"); len(id) != 32 {
		t.Errorf("X-Request-ID = %q, want a generated ID", id)
	}
}

func TestChunkedBodyForwardedWithContentLength(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	payload := strings.Repeat("z", 100<<10)
	req, _ := http.NewRequest("POST", h.front.URL+"/upload", io.NopCloser(strings.NewReader(payload)))
	req.ContentLength = -1 // forces chunked from the client
	resp, body := h.do(t, req)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	s := decode(t, body)
	if s.ContentLength != int64(len(payload)) || len(s.TransferEncoding) != 0 || s.Header.Get("Transfer-Encoding") != "" {
		t.Errorf("upstream saw CL=%d TE=%v", s.ContentLength, s.TransferEncoding)
	}
	if s.Body != payload {
		t.Errorf("body altered (%d bytes)", len(s.Body))
	}
}

func TestBodyTooLarge(t *testing.T) {
	up := echoUpstream(t)
	h := newHarness(t, up.URL, func(c *config.Config) { c.Limits.MaxBody = 1024 })
	for _, chunked := range []bool{false, true} {
		req, _ := http.NewRequest("POST", h.front.URL+"/", strings.NewReader(strings.Repeat("a", 2048)))
		if chunked {
			req.Body = io.NopCloser(req.Body)
			req.ContentLength = -1
		}
		resp, body := h.do(t, req)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("chunked=%v: status %d", chunked, resp.StatusCode)
		}
		if !strings.Contains(body, resp.Header.Get("X-Request-ID")) || strings.Contains(body, "1024") {
			t.Errorf("block body must carry only the request ID: %q", body)
		}
	}
	if h.srv.budget.InFlight() != 0 {
		t.Errorf("budget leaked: %d", h.srv.budget.InFlight())
	}
}

func TestRouteMaxBodyOverride(t *testing.T) {
	big := config.ByteSize(4096)
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxBody = 1024
		c.Hosts = []config.Host{{
			Names: []string{"app.test"},
			Routes: []config.Route{{
				Match:  config.Match{Methods: []string{"POST"}, PathPrefix: "/upload"},
				Limits: config.LimitOverrides{MaxBody: &big},
			}},
		}}
	})
	req, _ := http.NewRequest("POST", h.front.URL+"/upload", strings.NewReader(strings.Repeat("a", 2048)))
	req.Host = "app.test"
	if resp, _ := h.do(t, req); resp.StatusCode != 200 {
		t.Errorf("route override: status %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", h.front.URL+"/other", strings.NewReader(strings.Repeat("a", 2048)))
	req.Host = "app.test"
	if resp, _ := h.do(t, req); resp.StatusCode != 413 {
		t.Errorf("default route: status %d", resp.StatusCode)
	}
}

func TestUnknownHost(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Hosts = []config.Host{{Names: []string{"app.test"}}}
	})
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	req.Host = "evil.test"
	resp, _ := h.do(t, req)
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status %d", resp.StatusCode)
	}
	if !strings.Contains(h.logs.String(), `"reason":"unknown_host"`) {
		t.Errorf("log missing reason: %s", h.logs.String())
	}
	req.Host = "APP.test:80"
	if resp, _ := h.do(t, req); resp.StatusCode != 200 {
		t.Errorf("known host: status %d", resp.StatusCode)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			<-release
		}
	}))
	defer up.Close()
	h := newHarness(t, up.URL, func(c *config.Config) { c.Server.MaxConcurrentRequests = 1 })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest("GET", h.front.URL+"/slow", nil)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-entered
	req, _ := http.NewRequest("GET", h.front.URL+"/fast", nil)
	resp, _ := h.do(t, req)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("status %d Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	close(release)
	wg.Wait()
	if resp, _ := h.do(t, req); resp.StatusCode != 200 {
		t.Errorf("after release: status %d", resp.StatusCode)
	}
}

func TestBufferBudgetOverload(t *testing.T) {
	up := echoUpstream(t)
	h := newHarness(t, up.URL, func(c *config.Config) {
		c.Buffers.MemoryPerRequest = 1024
		c.Buffers.MemoryGlobal = 1024
	})
	req, _ := http.NewRequest("POST", h.front.URL+"/", strings.NewReader(strings.Repeat("a", 4096)))
	resp, _ := h.do(t, req)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("reject: status %d", resp.StatusCode)
	}

	h = newHarness(t, up.URL, func(c *config.Config) {
		c.Buffers.MemoryPerRequest = 1024
		c.Buffers.MemoryGlobal = 1024
		c.Buffers.OnOverload = "bypass"
	})
	req, _ = http.NewRequest("POST", h.front.URL+"/", strings.NewReader(strings.Repeat("a", 4096)))
	if resp, _ := h.do(t, req); resp.StatusCode != 200 {
		t.Errorf("bypass: status %d", resp.StatusCode)
	}
}

func TestUpstreamDown(t *testing.T) {
	up := httptest.NewServer(http.NotFoundHandler())
	addr := up.URL
	up.Close()
	h := newHarness(t, addr, nil)
	req, _ := http.NewRequest("GET", h.front.URL+"/x?secret=hunter2", nil)
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, resp.Header.Get("X-Request-ID")) {
		t.Errorf("status %d body %q", resp.StatusCode, body)
	}
	if strings.Contains(h.logs.String(), "hunter2") {
		t.Errorf("query value leaked into logs: %s", h.logs.String())
	}
}

func TestAccessLogLine(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	req, _ := http.NewRequest("POST", h.front.URL+"/p?token=s3cret", strings.NewReader("body-s3cret"))
	req.Header.Set("Cookie", "PHPSESSID=cookie-s3cret")
	h.do(t, req)

	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		if strings.Contains(l, `"msg":"access"`) {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatal(err)
			}
		}
	}
	if line == nil {
		t.Fatalf("no access line: %s", h.logs.String())
	}
	for _, k := range []string{"request_id", "host", "route", "method", "path", "status", "bytes_in", "bytes_out", "client_ip", "total_ms", "decisions", "upstream", "upstream_ms"} {
		if _, ok := line[k]; !ok {
			t.Errorf("access line missing %q: %v", k, line)
		}
	}
	if line["path"] != "/p" || line["host"] != "_any" || line["status"] != float64(200) || line["bytes_in"] != float64(11) {
		t.Errorf("unexpected access line: %v", line)
	}
	if strings.Contains(h.logs.String(), "s3cret") {
		t.Errorf("query, cookie or body value leaked into logs: %s", h.logs.String())
	}
}

func TestAdminEndpoints(t *testing.T) {
	up := echoUpstream(t)
	h := newHarness(t, up.URL, nil)
	admin := httptest.NewServer(h.srv.AdminHandler())
	defer admin.Close()

	get := func(path string) (int, string) {
		resp, err := http.Get(admin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := get("/healthz"); code != 200 {
		t.Errorf("/healthz %d", code)
	}
	if code, body := get("/readyz"); code != 503 || !strings.Contains(body, "upstream") {
		t.Errorf("/readyz before probe: %d %q", code, body)
	}
	h.srv.probeOnce(context.Background())
	if code, body := get("/readyz"); code != 200 {
		t.Errorf("/readyz after probe: %d %q", code, body)
	}
	h.srv.health.draining.Store(true)
	if code, body := get("/readyz"); code != 503 || !strings.Contains(body, "draining") {
		t.Errorf("/readyz draining: %d %q", code, body)
	}
	h.srv.health.draining.Store(false)

	code, body := get("/version")
	if code != 200 || !strings.Contains(body, "stopgap, not a fix") || !strings.Contains(body, `"version":"test"`) {
		t.Errorf("/version %d %q", code, body)
	}

	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	h.do(t, req)
	code, body = get("/metrics")
	for _, m := range []string{
		`phparmor_requests_total{host="_any",route="_default",status="200"} 1`,
		"phparmor_request_duration_seconds_count 1",
		"phparmor_upstream_duration_seconds_count 1",
		"phparmor_buffer_bytes_inflight 0",
	} {
		if !strings.Contains(body, m) {
			t.Errorf("/metrics missing %q", m)
		}
	}
	if code != 200 {
		t.Errorf("/metrics %d", code)
	}
}

func TestSpoolNotWritableFailsReadiness(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	h.srv.boot.Buffers.SpoolDir = filepath.Join(t.TempDir(), "missing", "dir")
	h.srv.probeOnce(context.Background())
	if r := strings.Join(h.srv.readiness(), ";"); !strings.Contains(r, "spool") {
		t.Errorf("readiness = %q", r)
	}
}

func TestReload(t *testing.T) {
	up := echoUpstream(t)
	h := newHarness(t, up.URL, nil)
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := "upstreams: [\"" + up.URL + "\"]\nbuffers: { spool_dir: \"" + filepath.ToSlash(t.TempDir()) + "\" }\n"

	write(base + "hosts: [ { names: [app.test] } ]\n")
	if err := h.srv.ReloadFile(path); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	if resp, _ := h.do(t, req); resp.StatusCode != 421 {
		t.Errorf("after reload: status %d, want 421", resp.StatusCode)
	}

	write(base + "limits: { max_body: nonsense }\n")
	if err := h.srv.ReloadFile(path); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if resp, _ := h.do(t, req); resp.StatusCode != 421 {
		t.Errorf("invalid reload changed behaviour: status %d", resp.StatusCode)
	}

	write(base + "listen: \":1234\"\n")
	if err := h.srv.ReloadFile(path); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.logs.String(), "needs a restart") || !strings.Contains(h.logs.String(), `"setting":"listen"`) {
		t.Errorf("restart-only change not reported: %s", h.logs.String())
	}
	if resp, _ := h.do(t, req); resp.StatusCode != 200 {
		t.Errorf("after third reload: status %d", resp.StatusCode)
	}
}

func TestRunAndGracefulShutdown(t *testing.T) {
	up := echoUpstream(t)
	cfg := testConfig(t, up.URL, func(c *config.Config) {
		c.Listen = "127.0.0.1:0"
		c.AdminListen = "127.0.0.1:0"
		c.ShutdownTimeout = 5 * time.Second
	})
	logs := &syncBuffer{}
	srv, err := New(cfg, Options{Logger: slog.New(slog.NewJSONHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), `"msg":"listening"`) {
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if !srv.health.draining.Load() {
		t.Error("draining not set on shutdown")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
