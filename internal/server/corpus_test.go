package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/smck83/phparmor/internal/inspect/ctype"
	pamultipart "github.com/smck83/phparmor/internal/inspect/multipart"
)

var updateCorpus = flag.Bool("update-corpus", false, "rewrite test/corpus/negative from the cases in corpus_test.go")

const corpusDir = "../../test/corpus"

// summarise describes a request body the way PHP would consume it: the
// ordered multipart parts (name, filename, content type, SHA-256 of data),
// or the SHA-256 of any other body.
func summarise(contentType string, body []byte) (string, error) {
	if ctype.PHPMediaType(contentType) != ctype.Multipart {
		sum := sha256.Sum256(body)
		return "raw:" + hex.EncodeToString(sum[:]), nil
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var parts []string
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return strings.Join(parts, "\n"), nil
		}
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		// Name and filename as PHP reads them: the plain parameters only
		// (Go's FileName prefers filename*, which PHP ignores).
		d, why := pamultipart.ParseDisposition(p.Header.Get("Content-Disposition"))
		if why != "" {
			return "", fmt.Errorf("disposition: %s", why)
		}
		parts = append(parts, fmt.Sprintf("%q %q %q %x", d.Name, d.Filename, p.Header.Get("Content-Type"), sum))
	}
}

// summaryUpstream answers every request with the summary of what it got.
func summaryUpstream(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		s, err := summarise(r.Header.Get("Content-Type"), body)
		if err != nil {
			s = "upstream parse error: " + err.Error()
		}
		w.Header().Set("X-Upstream-CL", strconv.FormatInt(r.ContentLength, 10))
		w.Header().Set("X-Upstream-TE", strings.Join(r.TransferEncoding, ","))
		_, _ = io.WriteString(w, s)
	}))
	t.Cleanup(up.Close)
	return up
}

func TestBenignCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(corpusDir, "benign", "*.http"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no benign captures")
	}
	var hits atomic.Int64
	h := newHarness(t, summaryUpstream(t, &hits).URL, nil)
	addr := strings.TrimPrefix(h.front.URL, "http://")

	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".http")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			orig, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
			if err != nil {
				t.Fatalf("capture does not parse: %v", err)
			}
			origBody, err := io.ReadAll(orig.Body)
			if err != nil {
				t.Fatal(err)
			}
			want, err := summarise(orig.Header.Get("Content-Type"), origBody)
			if err != nil {
				t.Fatalf("original body does not parse in Go: %v", err)
			}

			status, got, hdr := rawRequestFull(t, addr, string(raw))
			if status != 200 {
				t.Fatalf("status %d: %s", status, got)
			}
			if got != want {
				t.Errorf("upstream saw a different body:\n got %s\nwant %s", got, want)
			}
			if hdr.Get("X-Upstream-TE") != "" {
				t.Errorf("upstream got Transfer-Encoding %q", hdr.Get("X-Upstream-TE"))
			}
			for _, d := range accessDecisions(t, h.logs.String()) {
				if d["outcome"] != "pass" {
					t.Errorf("benign request produced decision %v", d)
				}
			}
		})
	}
}

// negativeCase is one structural negative-corpus request (SPEC 12.5). No
// exploit content: each case only exercises a parsing or limit rule.
type negativeCase struct {
	Status          int    `json:"status"`
	ReachesUpstream bool   `json:"reaches_upstream"`
	Note            string `json:"note"`
	raw             string
}

func negReq(method, ct, extra, body string) string {
	h := method + " /upload HTTP/1.1\r\nHost: corpus.test\r\nConnection: close\r\n"
	if ct != "" {
		h += "Content-Type: " + ct + "\r\n"
	}
	return h + extra + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func chunk(body string) string {
	return strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
}

func negativeCases() map[string]negativeCase {
	const b = "NegBoundary"
	ct := "multipart/form-data; boundary=" + b
	f := func(name, v string) string {
		return "--" + b + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + v + "\r\n"
	}
	end := "--" + b + "--\r\n"
	partWith := func(headers ...string) string {
		return "--" + b + "\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\nx\r\n"
	}
	ok := f("a", "1") + end
	const form = "application/x-www-form-urlencoded"
	return map[string]negativeCase{
		"upload-progress-field": {Status: 403, Note: "session upload-progress field in multipart (PA-UPROG)",
			raw: negReq("POST", ct, "", f("PHP_SESSION_UPLOAD_PROGRESS", "x")+f("a", "1")+end)},
		"parts-5000": {Status: 413, Note: "5000 parts, over max_parts (256)",
			raw: negReq("POST", ct, "", strings.Repeat("--"+b+"\r\nContent-Disposition: form-data; name=a\r\n\r\n\r\n", 5000)+end)},
		"deep-nesting": {Status: 400, Note: "field name nested 20 levels, over max_nesting (8)",
			raw: negReq("POST", ct, "", f("a"+strings.Repeat("[x]", 20), "1")+end)},
		"oversized-part-headers": {Status: 400, Note: "8 KiB of extra part headers",
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a"`, "X-Pad: "+strings.Repeat("p", 8192))+end)},
		"filename-ext": {Status: 400, Note: "RFC 5987 filename*",
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a"; filename*=UTF-8''x.txt`)+end)},
		"content-transfer-encoding": {Status: 400, Note: "Content-Transfer-Encoding part header",
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a"`, "Content-Transfer-Encoding: base64")+end)},
		"missing-final-boundary": {Status: 400, Note: "body ends without the closing boundary",
			raw: negReq("POST", ct, "", f("a", "1"))},
		"quote-in-name": {Status: 400, Note: `unescaped '"' in the field name`,
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a"b"`)+end)},
		"backslash-in-name": {Status: 400, Note: `'\' in the field name`,
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a\b"`)+end)},
		"backslash-in-filename": {Status: 400, Note: `'\' in the filename`,
			raw: negReq("POST", ct, "", partWith(`Content-Disposition: form-data; name="a"; filename="c:\x.txt"`)+end)},
		"duplicate-boundary-param": {Status: 400, Note: "two boundary parameters",
			raw: negReq("POST", ct+"; boundary=other", "", ok)},
		"comma-media-type": {Status: 400, Note: "PHP reads this as multipart/form-data; it must not bypass inspection",
			raw: negReq("POST", "multipart/form-data,x; boundary="+b, "", ok)},
		"multiple-content-type": {Status: 400, Note: "two Content-Type headers",
			raw: negReq("POST", ct, "Content-Type: text/plain\r\n", ok)},
		"gzip-multipart": {Status: 415, Note: "compressed request body cannot be inspected",
			raw: negReq("POST", ct, "Content-Encoding: gzip\r\n", ok)},
		"multipart-on-get": {Status: 400, Note: "body on GET",
			raw: negReq("GET", ct, "", ok)},
		"chunked-multipart": {Status: 200, ReachesUpstream: true, Note: "accepted; forwarded canonical with Content-Length",
			raw: "POST /upload HTTP/1.1\r\nHost: corpus.test\r\nConnection: close\r\nContent-Type: " + ct + "\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk(ok)},
		"cl-and-te": {Status: 200, ReachesUpstream: true, Note: "Content-Length with Transfer-Encoding: Go treats it as chunked; forwarded re-framed",
			raw: "POST /upload HTTP/1.1\r\nHost: corpus.test\r\nConnection: close\r\nContent-Type: " + ct + "\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk(ok)},

		// urlencoded bodies (PA-URLENC, M4).
		"urlenc-upload-progress": {Status: 403, Note: "percent-encoded upload-progress key in a urlencoded body (PA-UPROG)",
			raw: negReq("POST", form, "", "a=1&PHP%5FSESSION%5FUPLOAD%5FPROGRESS=x")},
		"urlenc-vars-1001": {Status: 413, Note: "1001 variables, over max_vars (1000)",
			raw: negReq("POST", form, "", strings.TrimSuffix(strings.Repeat("v=1&", 1001), "&"))},
		"urlenc-query-plus-body": {Status: 413, Note: "600 query variables plus 401 body variables: one combined max_vars",
			raw: strings.Replace(negReq("POST", form, "", strings.TrimSuffix(strings.Repeat("b=1&", 401), "&")),
				"/upload ", "/upload?"+strings.TrimSuffix(strings.Repeat("q=1&", 600), "&")+" ", 1)},
		"urlenc-deep-nesting": {Status: 400, Note: "key nested 20 levels",
			raw: negReq("POST", form, "", "a"+strings.Repeat("%5Bx%5D", 20)+"=1")},
		"urlenc-long-key": {Status: 400, Note: "key over max_key_length (256)",
			raw: negReq("POST", form, "", strings.Repeat("k", 300)+"=1")},
		"urlenc-invalid-percent": {Status: 400, Note: "invalid percent-encoding",
			raw: negReq("POST", form, "", "a=1&b=%zz")},
		"urlenc-comma-media-type": {Status: 400, Note: "PHP reads this as urlencoded; it must not bypass inspection",
			raw: negReq("POST", form+",x", "", "a=%zz")},
	}
}

func TestNegativeCorpus(t *testing.T) {
	dir := filepath.Join(corpusDir, "negative")
	cases := negativeCases()
	if *updateCorpus {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, c := range cases {
			if err := os.WriteFile(filepath.Join(dir, name+".http"), []byte(c.raw), 0o644); err != nil { // #nosec G306 -- fixtures
				t.Fatal(err)
			}
		}
		manifest, _ := json.MarshalIndent(cases, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(manifest, '\n'), 0o644); err != nil { // #nosec G306
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest (run with -update-corpus to create it): %v", err)
	}
	var manifest map[string]negativeCase
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != len(cases) {
		t.Errorf("manifest has %d cases, code has %d: run with -update-corpus", len(manifest), len(cases))
	}

	var hits atomic.Int64
	h := newHarness(t, summaryUpstream(t, &hits).URL, nil)
	addr := strings.TrimPrefix(h.front.URL, "http://")
	names := make([]string, 0, len(manifest))
	for n := range manifest {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want := manifest[name]
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name+".http"))
			if err != nil {
				t.Fatal(err)
			}
			if c, ok := cases[name]; !ok || c.raw != string(raw) {
				t.Errorf("file differs from the case in code: run with -update-corpus")
			}
			before := hits.Load()
			status, _, hdr := rawRequestFull(t, addr, string(raw))
			if status != want.Status {
				t.Errorf("status %d, want %d (%s)", status, want.Status, want.Note)
			}
			reached := hits.Load() != before
			if reached != want.ReachesUpstream {
				t.Errorf("reached upstream = %v, want %v", reached, want.ReachesUpstream)
			}
			if reached && (hdr.Get("X-Upstream-TE") != "" || hdr.Get("X-Upstream-CL") == "-1") {
				t.Errorf("upstream framing CL=%s TE=%s", hdr.Get("X-Upstream-CL"), hdr.Get("X-Upstream-TE"))
			}
			assertCleanSpool(t, h)
		})
	}
}
