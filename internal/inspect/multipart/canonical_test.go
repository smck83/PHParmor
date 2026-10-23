package multipart

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"strings"
	"testing"
	"testing/iotest"
)

const bnd = "XyZ"

var testLimits = Limits{
	MaxParts: 5, MaxFiles: 2, MaxFields: 3, MaxNesting: 2, MaxFieldValue: 16,
	AllowedHeaders:      []string{"Content-Disposition", "Content-Type"},
	UploadProgressField: "PHP_SESSION_UPLOAD_PROGRESS",
}

// part renders one raw part with the given header lines.
func part(headers []string, data string) string {
	return "--" + bnd + "\r\n" + strings.Join(headers, "\r\n") + "\r\n\r\n" + data + "\r\n"
}

func field(name, data string) string {
	return part([]string{`Content-Disposition: form-data; name="` + name + `"`}, data)
}

func file(name, filename, ct, data string) string {
	h := []string{`Content-Disposition: form-data; name="` + name + `"; filename="` + filename + `"`}
	if ct != "" {
		h = append(h, "Content-Type: "+ct)
	}
	return part(h, data)
}

const end = "--" + bnd + "--\r\n"

func run(t *testing.T, body string, l Limits) (string, Result, string) {
	t.Helper()
	var out bytes.Buffer
	res, v, err := Canonicalize(strings.NewReader(body), bnd, "NEW", &out, l)
	if err != nil {
		if av := AsViolation(err); av != nil {
			return "", res, av.Reason
		}
		t.Fatalf("io error: %v", err)
	}
	if v != nil {
		return "", res, v.Reason
	}
	return out.String(), res, ""
}

func TestCanonicalOutput(t *testing.T) {
	body := "preamble junk\r\n" +
		field("a", "1") +
		file("up[]", "x y.txt", "text/plain", "hello\r\nworld") +
		file("empty", "", "", "") +
		end + "epilogue junk"
	got, res, reason := run(t, body, testLimits)
	if reason != "" {
		t.Fatalf("rejected: %s", reason)
	}
	want := "--NEW\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n" +
		"--NEW\r\nContent-Disposition: form-data; name=\"up[]\"; filename=\"x y.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\nworld\r\n" +
		"--NEW\r\nContent-Disposition: form-data; name=\"empty\"; filename=\"\"\r\n\r\n\r\n" +
		"--NEW--\r\n"
	if got != want {
		t.Errorf("canonical output:\n%q\nwant:\n%q", got, want)
	}
	if res.Parts != 3 || res.Files != 2 || res.Fields != 1 || res.UploadProgress {
		t.Errorf("result = %+v", res)
	}
}

func TestCanonicalLFOnlyInput(t *testing.T) {
	body := "--" + bnd + "\nContent-Disposition: form-data; name=\"a\"\n\n1\n--" + bnd + "--\n"
	got, _, reason := run(t, body, testLimits)
	if reason != "" || got != "--NEW\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--NEW--\r\n" {
		t.Errorf("got %q, %q", got, reason)
	}
}

func TestCanonicalZeroParts(t *testing.T) {
	got, _, reason := run(t, end, testLimits)
	if reason != "" || got != "--NEW--\r\n" {
		t.Errorf("got %q, %q", got, reason)
	}
}

func TestCanonicalRejects(t *testing.T) {
	tests := []struct {
		name, body, reason string
	}{
		{"missing final boundary", field("a", "1"), ReasonMalformed},
		{"truncated part", "--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1", ReasonMalformed},
		{"no boundary at all", "just some bytes", ReasonMalformed},
		{"empty body", "", ReasonMalformed},
		{"no disposition", part([]string{"Content-Type: text/plain"}, "x") + end, ReasonBadDisposition},
		{"extra part header", part([]string{`Content-Disposition: form-data; name="a"`, "X-Pad: 1"}, "x") + end, ReasonPartHeader},
		{"content-transfer-encoding", part([]string{`Content-Disposition: form-data; name="a"`, "Content-Transfer-Encoding: base64"}, "eA==") + end, ReasonTransferEncoding},
		{"duplicate disposition header", part([]string{`Content-Disposition: form-data; name="a"`, `Content-Disposition: form-data; name="b"`}, "x") + end, ReasonDuplicateHdr},
		{"duplicate content-type header", part([]string{`Content-Disposition: form-data; name="a"; filename="f"`, "Content-Type: a/b", "Content-Type: c/d"}, "x") + end, ReasonDuplicateHdr},
		{"not form-data", part([]string{`Content-Disposition: attachment; name="a"`}, "x") + end, ReasonBadDisposition},
		{"empty name", field("", "x") + end, ReasonBadName},
		{"long name", field(strings.Repeat("n", 257), "x") + end, ReasonBadName},
		{"long filename", file("a", strings.Repeat("f", 256), "", "x") + end, ReasonBadFilename},
		{"filename*", part([]string{`Content-Disposition: form-data; name="a"; filename*=UTF-8''x`}, "x") + end, ReasonFilenameExt},
		{"quote in name", part([]string{`Content-Disposition: form-data; name="a"b"`}, "x") + end, ReasonBadDisposition},
		{"backslash in name", part([]string{`Content-Disposition: form-data; name="a\b"`}, "x") + end, ReasonBadDisposition},
		// Go's MIME header reader rejects control characters before the
		// disposition parser sees them (covered there by params_test).
		{"control char in filename", file("a", "x\x01y", "", "x") + end, ReasonMalformed},
		{"duplicate param", part([]string{`Content-Disposition: form-data; name="a"; name="b"`}, "x") + end, ReasonDuplicateParam},
		{"nesting too deep", field("a[1][2][3]", "x") + end, ReasonTooDeep},
		{"bad part content type", file("a", "f", "not a type", "x") + end, ReasonBadPartType},
		{"long part content type", file("a", "f", "a/"+strings.Repeat("b", 127), "x") + end, ReasonBadPartType},
		{"too many parts", strings.Repeat(file("f", "x", "", ""), 2) + strings.Repeat(field("a", ""), 3) + field("b", "") + end, ReasonTooManyParts},
		{"too many files", strings.Repeat(file("f", "x", "", ""), 3) + end, ReasonTooManyFiles},
		{"too many fields", strings.Repeat(field("a", ""), 4) + end, ReasonTooManyVars},
		{"field too large", field("a", strings.Repeat("v", 17)) + end, ReasonFieldTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, reason := run(t, tt.body, testLimits)
			if reason != tt.reason {
				t.Fatalf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

func TestCanonicalLengthAndIdentityEncoding(t *testing.T) {
	l := testLimits
	l.AllowedHeaders = []string{"Content-Type", "Content-Length", "Content-Transfer-Encoding"}
	cd := `Content-Disposition: form-data; name="a"`
	tests := []struct {
		name    string
		headers []string
		data    string
		reason  string
	}{
		{"matching Content-Length", []string{cd, "Content-Length: 5"}, "hello", ""},
		{"zero Content-Length", []string{cd, "Content-Length: 0"}, "", ""},
		{"Content-Length mismatch", []string{cd, "Content-Length: 4"}, "hello", ReasonPartLength},
		{"Content-Length not numeric", []string{cd, "Content-Length: +5"}, "hello", ReasonPartLength},
		{"two Content-Length", []string{cd, "Content-Length: 5", "Content-Length: 5"}, "hello", ReasonDuplicateHdr},
		{"8bit", []string{cd, "Content-Transfer-Encoding: 8bit"}, "x", ""},
		{"BINARY", []string{cd, "Content-Transfer-Encoding: BINARY"}, "x", ""},
		{"7bit", []string{cd, "Content-Transfer-Encoding: 7bit"}, "x", ""},
		{"base64", []string{cd, "Content-Transfer-Encoding: base64"}, "eA==", ReasonTransferEncoding},
		{"quoted-printable", []string{cd, "Content-Transfer-Encoding: quoted-printable"}, "x", ReasonTransferEncoding},
		{"two encodings", []string{cd, "Content-Transfer-Encoding: 8bit", "Content-Transfer-Encoding: binary"}, "x", ReasonTransferEncoding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, reason := run(t, part(tt.headers, tt.data)+end, l)
			if reason != tt.reason {
				t.Fatalf("reason = %q, want %q", reason, tt.reason)
			}
			if reason == "" && (strings.Contains(out, "Content-Length") || strings.Contains(out, "Content-Transfer-Encoding")) {
				t.Errorf("accepted header forwarded: %q", out)
			}
		})
	}
	// Not in the allowlist: rejected whatever the value.
	if _, _, reason := run(t, part([]string{cd, "Content-Transfer-Encoding: 8bit"}, "x")+end, testLimits); reason != ReasonTransferEncoding {
		t.Errorf("CTE not allowlisted: %q", reason)
	}
	if _, _, reason := run(t, part([]string{cd, "Content-Length: 1"}, "x")+end, testLimits); reason != ReasonPartHeader {
		t.Errorf("Content-Length not allowlisted: %q", reason)
	}
}

func TestCanonicalFileSizeOnlyLimitedByBody(t *testing.T) {
	big := strings.Repeat("d", 100) // over MaxFieldValue, but files are not fields
	if _, _, reason := run(t, file("a", "f", "", big)+end, testLimits); reason != "" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestUploadProgressDetection(t *testing.T) {
	for _, name := range []string{"PHP_SESSION_UPLOAD_PROGRESS", "PHP.SESSION.UPLOAD.PROGRESS", "PHP_SESSION_UPLOAD_PROGRESS[x]"} {
		_, res, reason := run(t, field(name, "x")+end, testLimits)
		if reason != "" || !res.UploadProgress {
			t.Errorf("%q: reason=%q uploadProgress=%v", name, reason, res.UploadProgress)
		}
	}
	_, res, _ := run(t, field("PHP_SESSION_UPLOAD", "x")+end, testLimits)
	if res.UploadProgress {
		t.Error("prefix matched")
	}
	if v := UploadProgressViolation(); v.Status != 403 || v.Reason != ReasonUploadProgress {
		t.Errorf("violation = %+v", v)
	}
}

func TestCanonicalIOErrors(t *testing.T) {
	body := field("a", "1") + end
	_, _, err := Canonicalize(io.MultiReader(strings.NewReader(body[:20]), iotest.ErrReader(errors.New("client gone"))), bnd, "NEW", io.Discard, testLimits)
	var ioErr *IOError
	if !errors.As(err, &ioErr) || AsViolation(err) != nil {
		t.Errorf("source error: %v", err)
	}
	_, _, err = Canonicalize(strings.NewReader(body), bnd, "NEW", failWriter{}, testLimits)
	if !errors.As(err, &ioErr) || AsViolation(err) != nil {
		t.Errorf("destination error: %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestNewBoundary(t *testing.T) {
	a, b := NewBoundary(), NewBoundary()
	if a == b || len(a) != len("phparmor-")+32 || !strings.HasPrefix(a, "phparmor-") {
		t.Errorf("boundaries %q %q", a, b)
	}
	if got, why := Boundary(ContentType(a)); got != a || why != "" {
		t.Errorf("canonical boundary does not round-trip: %q %q", got, why)
	}
}

func TestContainsBytes(t *testing.T) {
	needle := []byte("PHP_SESSION_UPLOAD_PROGRESS")
	for _, split := range []int{0, 1, 10, 26, 27} {
		data := append(bytes.Repeat([]byte("x"), 32<<10-split), append(needle, 'y')...)
		ok, err := ContainsBytes(iotest.OneByteReader(bytes.NewReader(data)), needle)
		if err != nil || !ok {
			t.Errorf("split %d: %v %v", split, ok, err)
		}
		ok, _ = ContainsBytes(bytes.NewReader(data), needle)
		if !ok {
			t.Errorf("split %d (bulk): not found", split)
		}
	}
	if ok, _ := ContainsBytes(strings.NewReader("PHP_SESSION_UPLOAD"), needle); ok {
		t.Error("false positive")
	}
}

type partSummary struct {
	name, filename, ctype string
	sum                   [32]byte
}

// goParse parses a body with Go's reader the way the invariant needs.
func goParse(body []byte, boundary string) ([]partSummary, error) {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []partSummary
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		d, why := ParseDisposition(p.Header.Get("Content-Disposition"))
		if why != "" {
			return nil, fmt.Errorf("disposition: %s", why)
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		out = append(out, partSummary{d.Name, d.Filename, p.Header.Get("Content-Type"), sha256.Sum256(data)})
	}
}

func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(field("a", "1")+file("f", "x.txt", "text/plain", "data")+end), bnd)
	f.Add([]byte("pre\r\n"+field("a[b][c]", "")+end+"post"), bnd)
	f.Add([]byte(field("a", "1")), bnd)
	f.Add([]byte("--b\nContent-Disposition: form-data; name=x\n\nv\n--b--"), "b")
	f.Fuzz(func(t *testing.T, body []byte, boundary string) {
		if _, why := Boundary(ContentType(boundary)); why != "" {
			return
		}
		l := Limits{MaxParts: 64, MaxFiles: 16, MaxFields: 64, MaxNesting: 8, MaxFieldValue: 1 << 16,
			AllowedHeaders: []string{"Content-Type"}, UploadProgressField: "PHP_SESSION_UPLOAD_PROGRESS"}
		var out bytes.Buffer
		nb := NewBoundary()
		res, v, err := Canonicalize(bytes.NewReader(body), boundary, nb, &out, l)
		if err != nil && AsViolation(err) == nil {
			t.Fatalf("unexpected io error: %v", err)
		}
		if err != nil || v != nil {
			return
		}
		// Bounded: the output only adds a fixed overhead per part.
		if out.Len() > len(body)+(res.Parts+1)*(len(nb)+700) {
			t.Fatalf("output %d bytes for input %d", out.Len(), len(body))
		}
		in, err := goParse(body, boundary)
		if err != nil {
			t.Fatalf("accepted input Go cannot parse: %v", err)
		}
		got, err := goParse(out.Bytes(), nb)
		if err != nil {
			t.Fatalf("canonical output does not parse: %v\n%q", err, out.Bytes())
		}
		if fmt.Sprint(in) != fmt.Sprint(got) {
			t.Fatalf("round trip mismatch:\n in %v\nout %v", in, got)
		}
		if !bytes.HasSuffix(out.Bytes(), []byte("--"+nb+"--\r\n")) || bytes.Contains(out.Bytes(), []byte("\n\n")) && !bytes.Contains(body, []byte("\n\n")) {
			t.Fatalf("output not canonical: %q", out.Bytes())
		}
	})
}
