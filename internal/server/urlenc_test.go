package server

import (
	"strings"
	"testing"

	"github.com/smck83/phparmor/internal/config"
)

func postForm(t *testing.T, h *harness, path, ct, body string) (int, rawSeen) {
	t.Helper()
	r := mustReq("POST", h.front.URL+path, strings.NewReader(body))
	if ct == "" {
		ct = "application/x-www-form-urlencoded"
	}
	r.Header.Set("Content-Type", ct)
	resp, out := h.do(t, r)
	var s rawSeen
	if resp.StatusCode == 200 {
		s = decodeRaw(t, out)
	}
	return resp.StatusCode, s
}

func TestURLEncEnforce(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxVars = 5
		c.Limits.MaxFieldValue = 16
	})
	deep := "a" + strings.Repeat("[x]", 9) + "=1"
	tests := []struct {
		name, path, ct, body string
		status               int
		control, reason      string
	}{
		{"too many vars", "/", "", "a&b&c&d&e&f", 413, config.CtlURLEnc, "too_many_vars"},
		{"combined with query", "/?a&b&c&d", "", "e&f", 413, config.CtlURLEnc, "too_many_vars"},
		{"deep nesting", "/", "", deep, 400, config.CtlURLEnc, "nesting_too_deep"},
		{"encoded nesting", "/", "", "a" + strings.Repeat("%5Bx%5D", 9) + "=1", 400, config.CtlURLEnc, "nesting_too_deep"},
		{"long key", "/", "", strings.Repeat("k", 257) + "=1", 400, config.CtlURLEnc, "key_too_long"},
		{"value too large", "/", "", "a=" + strings.Repeat("v", 17), 413, config.CtlURLEnc, "value_too_large"},
		{"invalid percent", "/", "", "a=%zz", 400, config.CtlURLEnc, "invalid_percent_encoding"},
		{"upload progress key", "/", "", "PHP%5FSESSION%5FUPLOAD%5FPROGRESS=1", 403, config.CtlUProg, "upload_progress_field"},
		{"PHP media type with comma", "/", "application/x-www-form-urlencoded,x", "a=%zz", 400, config.CtlURLEnc, "invalid_percent_encoding"},
		{"charset parameter", "/", "application/x-www-form-urlencoded; charset=UTF-8", "a=%zz", 400, config.CtlURLEnc, "invalid_percent_encoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := postForm(t, h, tt.path, tt.ct, tt.body)
			if status != tt.status {
				t.Fatalf("status %d, want %d", status, tt.status)
			}
			d := decisionFor(accessDecisions(t, h.logs.String()), tt.control)
			if d == nil || d["outcome"] != "block" || d["reason"] != tt.reason {
				t.Errorf("decision = %v", d)
			}
			assertCleanSpool(t, h)
		})
	}

	// Within limits: forwarded byte for byte, with a pass decision.
	body := "a=1&b%5B%5D=2&c=+x+&d="
	status, s := postForm(t, h, "/", "", body)
	if status != 200 || s.Body != body || s.ContentLength != int64(len(body)) {
		t.Fatalf("status %d upstream %+v", status, s)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlURLEnc); d == nil || d["outcome"] != "pass" {
		t.Errorf("decision = %v", d)
	}
}

func TestURLEncMonitorAndOff(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Controls[config.CtlURLEnc] = config.ModeMonitor })
	status, s := postForm(t, h, "/", "", "a=%zz")
	if status != 200 || s.Body != "a=%zz" {
		t.Fatalf("monitor: status %d body %q", status, s.Body)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlURLEnc); d == nil || d["outcome"] != "would_block" {
		t.Errorf("monitor decision = %v", d)
	}
	// The limited scan stops at the bad escape; PA-UPROG still finds the
	// field after it.
	if status, _ := postForm(t, h, "/", "", "a=%zz&PHP_SESSION_UPLOAD_PROGRESS=1"); status != 403 {
		t.Errorf("upload progress after violation: status %d", status)
	}

	h = newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Controls[config.CtlURLEnc] = config.ModeOff
		c.Controls[config.CtlUProg] = config.ModeOff
	})
	if status, _ := postForm(t, h, "/", "", "a=%zz&PHP_SESSION_UPLOAD_PROGRESS=1"); status != 200 {
		t.Errorf("off: status %d", status)
	}
	ds := accessDecisions(t, h.logs.String())
	if decisionFor(ds, config.CtlURLEnc) != nil || decisionFor(ds, config.CtlUProg) != nil {
		t.Errorf("off controls recorded %v", ds)
	}
}

func TestURLEncQueryCountedWhenQueryControlOff(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxVars = 3
		c.Controls[config.CtlQuery] = config.ModeOff
	})
	if status, _ := postForm(t, h, "/?a&b&c", "", "d=1"); status != 413 {
		t.Errorf("status %d, want 413", status)
	}
}

func TestArgSeparatorInput(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxVars = 3
		c.PHP.ArgSeparatorInput = "&;"
	})
	if status, _ := postForm(t, h, "/", "", "a=1;b=2;c=3;d=4"); status != 413 {
		t.Errorf("body: status %d, want 413 (';' separates)", status)
	}
	r := mustReq("GET", h.front.URL+"/?a=1;b=2;c=3;d=4", nil)
	if resp, _ := h.do(t, r); resp.StatusCode != 400 {
		t.Errorf("query: status %d, want 400", resp.StatusCode)
	}

	def := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Limits.MaxVars = 3 })
	if status, _ := postForm(t, def, "/", "", "a=1;b=2;c=3;d=4"); status != 200 {
		t.Errorf("default '&': status %d, want 200 (one variable)", status)
	}
}

func TestURLEncLargeBodySpills(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Buffers.MemoryPerRequest = 64 << 10 })
	body := strings.Repeat("field=value&", 300) + "big=" + strings.Repeat("x", 512<<10)
	status, s := postForm(t, h, "/", "", body)
	if status != 200 || len(s.Body) != len(body) {
		t.Fatalf("status %d, %d bytes", status, len(s.Body))
	}
	assertCleanSpool(t, h)
}
