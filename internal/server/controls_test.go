package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smck83/phparmor/internal/config"
)

// accessDecisions returns the decisions array of the last access log line.
func accessDecisions(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var last map[string]any
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		if strings.Contains(l, `"msg":"access"`) {
			last = nil
			if err := json.Unmarshal([]byte(l), &last); err != nil {
				t.Fatal(err)
			}
		}
	}
	if last == nil {
		t.Fatalf("no access line in %s", logs)
	}
	var out []map[string]any
	for _, d := range last["decisions"].([]any) {
		out = append(out, d.(map[string]any))
	}
	return out
}

func decisionFor(ds []map[string]any, control string) map[string]any {
	for _, d := range ds {
		if d["control"] == control {
			return d
		}
	}
	return nil
}

func TestControlsEnforce(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxCookies = 2
	})
	tests := []struct {
		name    string
		req     func() *http.Request
		status  int
		control string
		reason  string
	}{
		{"GET with body", func() *http.Request {
			return mustReq("GET", h.front.URL+"/", strings.NewReader("x"))
		}, 400, config.CtlFrame, "body_not_allowed"},
		{"gzip body", func() *http.Request {
			r := mustReq("POST", h.front.URL+"/", strings.NewReader("x"))
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}, 415, config.CtlFrame, "content_encoding"},
		{"too many cookies", func() *http.Request {
			r := mustReq("GET", h.front.URL+"/", nil)
			r.Header.Set("Cookie", "a=1; b=2; c=3")
			return r
		}, 431, config.CtlHdr, "too_many_cookies"},
		{"cookie name nesting", func() *http.Request {
			r := mustReq("GET", h.front.URL+"/", nil)
			r.Header.Set("Cookie", "a"+strings.Repeat("[x]", 9)+"=1")
			return r
		}, 400, config.CtlHdr, "cookie_nesting_too_deep"},
		{"query nesting", func() *http.Request {
			return mustReq("GET", h.front.URL+"/?a"+strings.Repeat("[x]", 9)+"=1", nil)
		}, 400, config.CtlQuery, "nesting_too_deep"},
		{"query too long", func() *http.Request {
			return mustReq("GET", h.front.URL+"/?a="+strings.Repeat("x", 9000), nil)
		}, 414, config.CtlQuery, "query_too_long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := h.do(t, tt.req())
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
			if strings.Contains(body, tt.control) || strings.Contains(body, tt.reason) {
				t.Errorf("client response leaks control details: %q", body)
			}
			d := decisionFor(accessDecisions(t, h.logs.String()), tt.control)
			if d == nil || d["outcome"] != "block" || d["reason"] != tt.reason || d["mode"] != "enforce" {
				t.Errorf("decision = %v", d)
			}
		})
	}
}

func TestControlsPassRecordsDecisions(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, nil)
	resp, _ := h.do(t, mustReq("GET", h.front.URL+"/?a[b]=1", nil))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ds := accessDecisions(t, h.logs.String())
	for _, c := range []string{config.CtlFrame, config.CtlHdr, config.CtlQuery} {
		if d := decisionFor(ds, c); d == nil || d["outcome"] != "pass" {
			t.Errorf("%s decision = %v", c, d)
		}
	}
	// PA-COOKIE-STRIP is off by default: no decision.
	if d := decisionFor(ds, config.CtlCookieStrip); d != nil {
		t.Errorf("off control recorded %v", d)
	}
}

func TestControlsMonitorForwards(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Controls[config.CtlFrame] = config.ModeMonitor
		c.Controls[config.CtlQuery] = config.ModeMonitor
	})
	resp, body := h.do(t, mustReq("GET", h.front.URL+"/?a"+strings.Repeat("[x]", 9)+"=1", strings.NewReader("x")))
	if resp.StatusCode != 200 {
		t.Fatalf("monitor mode blocked: %d", resp.StatusCode)
	}
	if s := decode(t, body); s.Body != "x" {
		t.Errorf("body not forwarded: %+v", s)
	}
	ds := accessDecisions(t, h.logs.String())
	for c, reason := range map[string]string{config.CtlFrame: "body_not_allowed", config.CtlQuery: "nesting_too_deep"} {
		if d := decisionFor(ds, c); d == nil || d["outcome"] != "would_block" || d["reason"] != reason || d["mode"] != "monitor" {
			t.Errorf("%s decision = %v", c, d)
		}
	}

	admin := httptest.NewServer(h.srv.AdminHandler())
	defer admin.Close()
	mresp, err := http.Get(admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer mresp.Body.Close()
	metrics, _ := io.ReadAll(mresp.Body)
	if !strings.Contains(string(metrics), `phparmor_decisions_total{control="PA-QUERY",outcome="would_block"} 1`) {
		t.Errorf("decision metric missing")
	}
}

func TestControlsOff(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Controls[config.CtlQuery] = config.ModeOff
	})
	resp, _ := h.do(t, mustReq("GET", h.front.URL+"/?a"+strings.Repeat("[x]", 9)+"=1", nil))
	if resp.StatusCode != 200 {
		t.Fatalf("off control blocked: %d", resp.StatusCode)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlQuery); d != nil {
		t.Errorf("off control recorded %v", d)
	}
}

func TestRouteOverridesControlMode(t *testing.T) {
	h := newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
		c.Hosts = []config.Host{{
			Names: []string{"app.test"},
			Routes: []config.Route{{
				Match:    config.Match{PathPrefix: "/legacy"},
				Controls: map[string]config.Mode{config.CtlQuery: config.ModeMonitor},
			}},
		}}
	})
	deep := "?a" + strings.Repeat("[x]", 9) + "=1"
	r := mustReq("GET", h.front.URL+"/legacy"+deep, nil)
	r.Host = "app.test"
	if resp, _ := h.do(t, r); resp.StatusCode != 200 {
		t.Errorf("route monitor: status %d", resp.StatusCode)
	}
	r = mustReq("GET", h.front.URL+"/other"+deep, nil)
	r.Host = "app.test"
	if resp, _ := h.do(t, r); resp.StatusCode != 400 {
		t.Errorf("host default: status %d", resp.StatusCode)
	}
}

func TestCookieStrip(t *testing.T) {
	setup := func(mode config.Mode) *harness {
		return newHarness(t, echoUpstream(t).URL, func(c *config.Config) {
			c.Hosts = []config.Host{{
				Names:       []string{"app.test"},
				CookieStrip: []string{"PHPSESSID"},
				Controls:    map[string]config.Mode{config.CtlCookieStrip: mode},
			}}
		})
	}
	send := func(h *harness, cookie string) seen {
		r := mustReq("GET", h.front.URL+"/", nil)
		r.Host = "app.test"
		r.Header.Set("Cookie", cookie)
		_, body := h.do(t, r)
		return decode(t, body)
	}

	h := setup(config.ModeEnforce)
	if got := send(h, "a=1; PHP%53ESSID=evil; b=2").Header.Get("Cookie"); got != "a=1; b=2" {
		t.Errorf("enforce: upstream Cookie = %q", got)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlCookieStrip); d == nil || d["outcome"] != "modify" {
		t.Errorf("enforce decision = %v", d)
	}
	if got := send(h, "PHPSESSID=x"); got.Header.Get("Cookie") != "" || len(got.Header.Values("Cookie")) != 0 {
		t.Errorf("enforce: emptied Cookie header still sent: %v", got.Header["Cookie"])
	}
	if got := send(h, "a=1").Header.Get("Cookie"); got != "a=1" {
		t.Errorf("enforce: unrelated cookie altered: %q", got)
	}

	h = setup(config.ModeMonitor)
	if got := send(h, "a=1; PHPSESSID=x").Header.Get("Cookie"); got != "a=1; PHPSESSID=x" {
		t.Errorf("monitor: upstream Cookie = %q", got)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlCookieStrip); d == nil || d["outcome"] != "would_block" {
		t.Errorf("monitor decision = %v", d)
	}
	if strings.Contains(h.logs.String(), "PHPSESSID=x") {
		t.Errorf("cookie value logged")
	}
}

func mustReq(method, url string, body io.Reader) *http.Request {
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	return r
}

// TestWireFraming pins how net/http handles malformed framing on the wire
// (see internal/inspect/framing). Rejected cases must never reach the
// upstream; normalised cases must reach it with clean framing.
func TestWireFraming(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(seen{
			ContentLength: r.ContentLength, TransferEncoding: r.TransferEncoding,
			Header: r.Header, Body: string(b),
		})
	}))
	defer up.Close()
	h := newHarness(t, up.URL, nil)
	addr := strings.TrimPrefix(h.front.URL, "http://")

	rejected := []struct{ name, raw string }{
		{"differing Content-Length", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"},
		{"Content-Length list", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\nx"},
		{"signed Content-Length", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\nx"},
		{"TE gzip, chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"},
		{"TE identity", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\nContent-Length: 1\r\n\r\nx"},
		{"TE repeated", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"invalid header name", "GET / HTTP/1.1\r\nHost: a\r\nX(A): b\r\n\r\n"},
		{"space before colon", "GET / HTTP/1.1\r\nHost: a\r\nX-A : b\r\n\r\n"},
		{"NUL in value", "GET / HTTP/1.1\r\nHost: a\r\nX-A: b\x00c\r\n\r\n"},
		{"bare CR in value", "GET / HTTP/1.1\r\nHost: a\r\nX-A: b\rc\r\n\r\n"},
	}
	for _, tt := range rejected {
		t.Run("rejected/"+tt.name, func(t *testing.T) {
			before := hits.Load()
			status, _ := rawRequest(t, addr, tt.raw)
			if status < 400 {
				t.Errorf("status %d, want 4xx/5xx", status)
			}
			if hits.Load() != before {
				t.Errorf("reached upstream")
			}
		})
	}

	normalised := []struct {
		name, raw string
		check     func(t *testing.T, s seen)
	}{
		{"Content-Length with Transfer-Encoding is re-framed",
			"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n",
			func(t *testing.T, s seen) {
				if s.ContentLength != 6 || len(s.TransferEncoding) != 0 || s.Body != "abcdef" {
					t.Errorf("upstream saw %+v", s)
				}
			}},
		{"identical Content-Length merged",
			"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
			func(t *testing.T, s seen) {
				if s.ContentLength != 1 || len(s.Header.Values("Content-Length")) != 1 {
					t.Errorf("upstream saw %+v", s)
				}
			}},
		{"obs-fold joined",
			"GET / HTTP/1.1\r\nHost: a\r\nX-A: b\r\n c\r\nConnection: close\r\n\r\n",
			func(t *testing.T, s seen) {
				if got := s.Header.Values("X-A"); len(got) != 1 || got[0] != "b c" {
					t.Errorf("upstream X-A = %q", got)
				}
			}},
		{"bare LF accepted",
			"GET / HTTP/1.1\nHost: a\nX-A: b\nConnection: close\n\n",
			func(t *testing.T, s seen) {
				if got := s.Header.Get("X-A"); got != "b" {
					t.Errorf("upstream X-A = %q", got)
				}
			}},
	}
	for _, tt := range normalised {
		t.Run("normalised/"+tt.name, func(t *testing.T) {
			status, body := rawRequest(t, addr, tt.raw)
			if status != 200 {
				t.Fatalf("status %d", status)
			}
			tt.check(t, decode(t, body))
		})
	}
}

// rawRequest writes raw bytes to addr and returns the response status and
// body. It always uses a fresh connection with a deadline.
func rawRequest(t *testing.T, addr, raw string) (int, string) {
	t.Helper()
	status, body, _ := rawRequestFull(t, addr, raw)
	return status, body
}

// rawRequestFull is rawRequest that also returns the final response's
// headers, skipping any 1xx interim responses (Expect: 100-continue).
func rawRequestFull(t *testing.T, addr, raw string) (int, string, http.Header) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			continue
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
}
