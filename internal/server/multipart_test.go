package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/smck83/phparmor/internal/config"
)

// rawSeen is what a raw-echo upstream observed.
type rawSeen struct {
	ContentType      string
	ContentLength    int64
	TransferEncoding []string
	Body             string
}

// rawWire carries the body as []byte (base64 in JSON) so binary data
// survives the echo exactly.
type rawWire struct {
	ContentType      string
	ContentLength    int64
	TransferEncoding []string
	Body             []byte
}

func rawUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(rawWire{r.Header.Get("Content-Type"), r.ContentLength, r.TransferEncoding, b})
	}))
	t.Cleanup(up.Close)
	return up
}

const tb = "TestBoundary42"

func mpField(name, value string) string {
	return "--" + tb + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n"
}

func mpFile(name, filename, data string) string {
	return "--" + tb + "\r\nContent-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + data + "\r\n"
}

const mpEnd = "--" + tb + "--\r\n"

func postMultipart(t *testing.T, h *harness, path, ct, body string, chunked bool) (*http.Response, string) {
	t.Helper()
	r := mustReq("POST", h.front.URL+path, strings.NewReader(body))
	if chunked {
		r.Body = io.NopCloser(r.Body)
		r.ContentLength = -1
	}
	if ct == "" {
		ct = "multipart/form-data; boundary=" + tb
	}
	r.Header.Set("Content-Type", ct)
	return h.do(t, r)
}

func decodeRaw(t *testing.T, body string) rawSeen {
	t.Helper()
	var w rawWire
	if err := json.Unmarshal([]byte(body), &w); err != nil {
		t.Fatalf("upstream response %q: %v", body, err)
	}
	return rawSeen{w.ContentType, w.ContentLength, w.TransferEncoding, string(w.Body)}
}

func assertCleanSpool(t *testing.T, h *harness) {
	t.Helper()
	if m, d := h.srv.pool.MemoryInFlight(), h.srv.pool.DiskInFlight(); m != 0 || d != 0 {
		t.Errorf("budget leaked: memory=%d disk=%d", m, d)
	}
	es, err := os.ReadDir(h.srv.boot.Buffers.SpoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 0 {
		t.Errorf("spool files left behind: %d", len(es))
	}
}

func TestMultipartCanonicalised(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chunked bool
		perReq  config.ByteSize
	}{
		{"in memory", false, 1 << 20},
		{"chunked", true, 1 << 20},
		{"spilled to disk", false, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Buffers.MemoryPerRequest = tc.perReq })
			body := "preamble\r\n" + mpField("a[b]", "1") + mpFile("up", "x.bin", strings.Repeat("\x00\xff", 500)) + mpEnd + "epilogue"
			resp, out := postMultipart(t, h, "/upload", "", body, tc.chunked)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			s := decodeRaw(t, out)
			if !strings.HasPrefix(s.ContentType, "multipart/form-data; boundary=phparmor-") {
				t.Fatalf("Content-Type = %q", s.ContentType)
			}
			if s.ContentLength != int64(len(s.Body)) || len(s.TransferEncoding) != 0 {
				t.Errorf("framing: CL=%d len=%d TE=%v", s.ContentLength, len(s.Body), s.TransferEncoding)
			}
			if strings.Contains(s.Body, "preamble") || strings.Contains(s.Body, "epilogue") || strings.Contains(s.Body, tb) {
				t.Errorf("original framing leaked into canonical body")
			}
			nb := strings.TrimPrefix(s.ContentType, "multipart/form-data; boundary=")
			mr := multipart.NewReader(strings.NewReader(s.Body), nb)
			var got []string
			for {
				p, err := mr.NextRawPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(p)
				got = append(got, p.FormName()+"|"+p.FileName()+"|"+string(data))
			}
			want := []string{"a[b]||1", "up|x.bin|" + strings.Repeat("\x00\xff", 500)}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("parts = %q", got)
			}
			if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlMPart); d == nil || d["outcome"] != "pass" {
				t.Errorf("PA-MPART decision = %v", d)
			}
			assertCleanSpool(t, h)
		})
	}
}

func TestMultipartEnforceRejects(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Limits.MaxParts = 4
		c.Buffers.MemoryPerRequest = 128
	})
	deep := "a" + strings.Repeat("[x]", 9)
	tests := []struct {
		name, ct, body string
		chunked        bool
		status         int
		control        string
		reason         string
	}{
		{"upload progress field", "", mpField("PHP_SESSION_UPLOAD_PROGRESS", "x") + mpFile("f", "a", "b") + mpEnd, false, 403, config.CtlUProg, "upload_progress_field"},
		{"too many parts", "", strings.Repeat(mpField("a", "1"), 5) + mpEnd, false, 413, config.CtlMPart, "too_many_parts"},
		{"too many parts chunked", "", strings.Repeat(mpField("a", "1"), 5) + mpEnd, true, 413, config.CtlMPart, "too_many_parts"},
		{"deep nesting", "", mpField(deep, "1") + mpEnd, false, 400, config.CtlMPart, "nesting_too_deep"},
		{"filename*", "", "--" + tb + "\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''x\r\n\r\nd\r\n" + mpEnd, false, 400, config.CtlMPart, "filename_ext"},
		{"content-transfer-encoding", "", "--" + tb + "\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Transfer-Encoding: base64\r\n\r\neA==\r\n" + mpEnd, false, 400, config.CtlMPart, "part_transfer_encoding"},
		{"oversized part header", "", "--" + tb + "\r\nContent-Disposition: form-data; name=\"f\"\r\nX-Pad: " + strings.Repeat("p", 4000) + "\r\n\r\nd\r\n" + mpEnd, false, 400, config.CtlMPart, "disallowed_part_header"},
		{"missing final boundary", "", mpField("a", "1"), false, 400, config.CtlMPart, "malformed_multipart"},
		{"quote in name", "", "--" + tb + "\r\nContent-Disposition: form-data; name=\"a\"b\"\r\n\r\nd\r\n" + mpEnd, false, 400, config.CtlMPart, "bad_disposition"},
		{"duplicate boundary param", "multipart/form-data; boundary=" + tb + "; boundary=other", mpField("a", "1") + mpEnd, false, 400, config.CtlMPart, "duplicate_param"},
		{"PHP media type with comma", "multipart/form-data,x; boundary=" + tb, mpField("a", "1") + mpEnd, false, 400, config.CtlMPart, "bad_content_type"},
		{"no boundary", "multipart/form-data", mpField("a", "1") + mpEnd, false, 400, config.CtlMPart, "bad_boundary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := postMultipart(t, h, "/", tt.ct, tt.body, tt.chunked)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d (%s)", resp.StatusCode, tt.status, body)
			}
			d := decisionFor(accessDecisions(t, h.logs.String()), tt.control)
			if d == nil || d["outcome"] != "block" || d["reason"] != tt.reason {
				t.Errorf("decision = %v", d)
			}
			assertCleanSpool(t, h)
		})
	}
}

func TestMultipartCombinedVarCount(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Limits.MaxVars = 5 })
	q := "?a=1&b=2&c=3&d=4"
	if resp, _ := postMultipart(t, h, "/"+q, "", mpField("e", "1")+mpEnd, false); resp.StatusCode != 200 {
		t.Errorf("4 query + 1 field: status %d", resp.StatusCode)
	}
	if resp, _ := postMultipart(t, h, "/"+q, "", mpField("e", "1")+mpField("f", "1")+mpEnd, false); resp.StatusCode != 413 {
		t.Errorf("4 query + 2 fields: status %d", resp.StatusCode)
	}
	// Files do not count as variables.
	if resp, _ := postMultipart(t, h, "/"+q, "", mpField("e", "1")+mpFile("f", "x", "d")+mpEnd, false); resp.StatusCode != 200 {
		t.Errorf("4 query + 1 field + 1 file: status %d", resp.StatusCode)
	}
}

func TestMultipartMonitorForwardsOriginal(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Controls[config.CtlMPart] = config.ModeMonitor })
	body := "--" + tb + "\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''x\r\n\r\nd\r\n" + mpEnd
	resp, out := postMultipart(t, h, "/", "", body, true)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	s := decodeRaw(t, out)
	if s.Body != body || s.ContentType != "multipart/form-data; boundary="+tb || s.ContentLength != int64(len(body)) {
		t.Errorf("original not forwarded unchanged: %+v", s)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlMPart); d == nil || d["outcome"] != "would_block" || d["reason"] != "filename_ext" {
		t.Errorf("decision = %v", d)
	}
	assertCleanSpool(t, h)
}

func TestUploadProgressWhenNotCanonicalising(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeMonitor, config.ModeOff} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Controls[config.CtlMPart] = mode })

			// Parsable body with the field.
			resp, _ := postMultipart(t, h, "/", "", mpField("PHP_SESSION_UPLOAD_PROGRESS", "x")+mpEnd, false)
			if resp.StatusCode != 403 {
				t.Errorf("parsable: status %d", resp.StatusCode)
			}
			// Unparsable body: fail closed if the name appears anywhere.
			resp, _ = postMultipart(t, h, "/", "", "junk\r\n"+mpField("PHP_SESSION_UPLOAD_PROGRESS", "x"), false)
			if resp.StatusCode != 403 {
				t.Errorf("unparsable: status %d", resp.StatusCode)
			}
			// Unparsable body without the field is forwarded.
			resp, _ = postMultipart(t, h, "/", "", mpField("a", "1"), false)
			if resp.StatusCode != 200 {
				t.Errorf("unparsable benign: status %d", resp.StatusCode)
			}
			if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlMPart); (mode == config.ModeOff) != (d == nil) {
				t.Errorf("PA-MPART decision in %s mode = %v", mode, d)
			}
			assertCleanSpool(t, h)
		})
	}
}

func TestUploadProgressMonitor(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Controls[config.CtlUProg] = config.ModeMonitor })
	resp, out := postMultipart(t, h, "/", "", mpField("PHP_SESSION_UPLOAD_PROGRESS", "x")+mpEnd, false)
	if resp.StatusCode != 200 || !strings.Contains(decodeRaw(t, out).Body, "PHP_SESSION_UPLOAD_PROGRESS") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlUProg); d == nil || d["outcome"] != "would_block" {
		t.Errorf("decision = %v", d)
	}
}

func TestMultipartAllOffForwardsRaw(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Controls[config.CtlMPart] = config.ModeOff
		c.Controls[config.CtlUProg] = config.ModeOff
	})
	body := "anything at all"
	resp, out := postMultipart(t, h, "/", "", body, false)
	if resp.StatusCode != 200 || decodeRaw(t, out).Body != body {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ds := accessDecisions(t, h.logs.String())
	if decisionFor(ds, config.CtlMPart) != nil || decisionFor(ds, config.CtlUProg) != nil {
		t.Errorf("off controls recorded decisions: %v", ds)
	}
}

func TestRouteMultipartDeny(t *testing.T) {
	setup := func(mode config.Mode) *harness {
		return newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
			c.Controls[config.CtlRouteMPart] = mode
			c.Hosts = []config.Host{{
				Names: []string{"app.test"},
				Routes: []config.Route{
					{Match: config.Match{PathPrefix: "/upload"}, Multipart: "allow"},
					{Match: config.Match{PathPrefix: "/"}, Multipart: "deny"},
				},
			}}
		})
	}
	send := func(h *harness, path string) int {
		r := mustReq("POST", h.front.URL+path, strings.NewReader(mpField("a", "1")+mpEnd))
		r.Host = "app.test"
		r.Header.Set("Content-Type", "multipart/form-data; boundary="+tb)
		resp, _ := h.do(t, r)
		return resp.StatusCode
	}

	h := setup(config.ModeEnforce)
	if got := send(h, "/upload"); got != 200 {
		t.Errorf("allowed route: %d", got)
	}
	if got := send(h, "/login"); got != 403 {
		t.Errorf("denied route: %d", got)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlRouteMPart); d == nil || d["outcome"] != "block" {
		t.Errorf("decision = %v", d)
	}

	h = setup(config.ModeMonitor) // the default
	if got := send(h, "/login"); got != 200 {
		t.Errorf("monitor: %d", got)
	}
	if d := decisionFor(accessDecisions(t, h.logs.String()), config.CtlRouteMPart); d == nil || d["outcome"] != "would_block" {
		t.Errorf("monitor decision = %v", d)
	}
}

func TestSpoolQuotaExhausted(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) {
		c.Buffers.MemoryPerRequest = 64
		c.Buffers.SpoolQuota = 1024
	})
	resp, _ := postMultipart(t, h, "/", "", mpFile("f", "x", strings.Repeat("d", 4096))+mpEnd, false)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("status %d", resp.StatusCode)
	}
	assertCleanSpool(t, h)
}

func TestNonMultipartBodySpills(t *testing.T) {
	h := newHarness(t, rawUpstream(t).URL, func(c *config.Config) { c.Buffers.MemoryPerRequest = 64 })
	payload := bytes.Repeat([]byte(`{"k":"v"},`), 1000)
	r := mustReq("POST", h.front.URL+"/api", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	resp, out := h.do(t, r)
	if s := decodeRaw(t, out); resp.StatusCode != 200 || s.Body != string(payload) {
		t.Fatalf("status %d, body %d bytes", resp.StatusCode, len(s.Body))
	}
	assertCleanSpool(t, h)
}
