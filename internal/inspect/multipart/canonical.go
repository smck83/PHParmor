// Package multipart implements PA-MPART multipart canonicalisation and the
// multipart side of PA-UPROG (SPEC section 6).
//
// The body is streamed with mime/multipart's NextRawPart (no
// quoted-printable decoding, never ReadForm), every part is checked, and a
// canonical body is written with a fresh boundary: CRLF only, no preamble or
// epilogue, and only name, filename and Content-Type per part. PHP therefore
// only ever sees the structure PHParmor parsed, in a narrow format both
// parsers agree on.
package multipart

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/smck83/phparmor/internal/inspect/query"
	"github.com/smck83/phparmor/internal/policy"
)

// Violation reasons from canonicalisation.
const (
	ReasonMalformed      = "malformed_multipart"
	ReasonDuplicateHdr   = "duplicate_part_header"
	ReasonPartLength     = "bad_part_length"
	ReasonTooManyParts   = "too_many_parts"
	ReasonTooManyFiles   = "too_many_files"
	ReasonTooManyVars    = "too_many_vars"
	ReasonTooDeep        = "nesting_too_deep"
	ReasonFieldTooLarge  = "field_too_large"
	ReasonUploadProgress = "upload_progress_field"
)

// Limits apply to one multipart body (SPEC 6.2 and 6.3).
type Limits struct {
	MaxParts int
	MaxFiles int
	// MaxFields is the number of non-file fields allowed: max_vars minus
	// the query string's variables (PHP counts them together here).
	MaxFields     int
	MaxNesting    int
	MaxFieldValue int64
	// AllowedHeaders are the part headers that are accepted (and dropped
	// from the output unless they are Content-Disposition or Content-Type).
	AllowedHeaders []string
	// UploadProgressField is php.upload_progress_field.
	UploadProgressField string
}

// Result describes an accepted (or partially read) body.
type Result struct {
	Parts  int
	Files  int
	Fields int
	// UploadProgress is set when a field named like the session upload
	// progress field was seen. The caller applies PA-UPROG.
	UploadProgress bool
}

// IOError wraps a read error from the request body or a write error to the
// destination, as opposed to a multipart syntax problem.
type IOError struct{ Err error }

func (e *IOError) Error() string { return "multipart: io: " + e.Err.Error() }
func (e *IOError) Unwrap() error { return e.Err }

// NewBoundary returns a random canonical boundary (SPEC 6.4).
func NewBoundary() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "phparmor-" + hex.EncodeToString(b[:])
}

// ContentType returns the request Content-Type for a canonical body.
func ContentType(boundary string) string { return "multipart/form-data; boundary=" + boundary }

func malformed(reason string) *policy.Violation {
	return &policy.Violation{Reason: reason, Status: http.StatusBadRequest}
}

func overCap(reason string) *policy.Violation {
	return &policy.Violation{Reason: reason, Status: http.StatusRequestEntityTooLarge}
}

// Canonicalize reads a multipart body from src and writes its canonical form
// with newBoundary to dst (io.Discard to validate only). It stops at the
// first violation. err is non-nil only for I/O errors (*IOError); the
// caller must then discard dst.
func Canonicalize(src io.Reader, boundary, newBoundary string, dst io.Writer, l Limits) (Result, *policy.Violation, error) {
	var res Result
	sr := &srcReader{r: src}
	mr := multipart.NewReader(sr, boundary)
	w := &dstWriter{w: dst}
	classify := func(err error) error {
		if sr.err != nil {
			return sr.err
		}
		return classifyErr(err)
	}

	allowed := map[string]bool{"Content-Disposition": true}
	for _, h := range l.AllowedHeaders {
		allowed[textproto.CanonicalMIMEHeaderKey(h)] = true
	}
	progressBase := ""
	if v, ok := query.Register(l.UploadProgressField); ok {
		progressBase = v.Base
	}

	for {
		p, err := mr.NextRawPart()
		// The reader returns the bare io.EOF sentinel only after the final
		// boundary; a body that ends without one yields a wrapped EOF.
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, nil, classify(err)
		}
		res.Parts++
		if res.Parts > l.MaxParts {
			return res, overCap(ReasonTooManyParts), nil
		}

		declaredLen := int64(-1)
		for k, vs := range p.Header {
			switch {
			case k == "Content-Transfer-Encoding" && (!allowed[k] || len(vs) != 1 || !identityEncoding(vs[0])):
				// Only identity codings are accepted: some parsers decode
				// base64/quoted-printable parts and PHP does not.
				return res, malformed(ReasonTransferEncoding), nil
			case !allowed[k]:
				return res, malformed(ReasonPartHeader), nil
			case len(vs) != 1:
				return res, malformed(ReasonDuplicateHdr), nil
			case k == "Content-Length":
				n, ok := parseLength(vs[0])
				if !ok {
					return res, malformed(ReasonPartLength), nil
				}
				declaredLen = n
			}
		}
		d, why := ParseDisposition(p.Header.Get("Content-Disposition"))
		if why != "" {
			return res, malformed(why), nil
		}
		v, registered := query.Register(d.Name)
		if l.UploadProgressField != "" && (d.Name == l.UploadProgressField || registered && v.Base == progressBase) {
			res.UploadProgress = true
		}
		if registered && v.Depth > l.MaxNesting {
			return res, malformed(ReasonTooDeep), nil
		}
		ct := p.Header.Get("Content-Type")
		if _, has := p.Header["Content-Type"]; has && !validPartType(ct) {
			return res, malformed(ReasonBadPartType), nil
		}
		if d.HasFilename {
			res.Files++
			if res.Files > l.MaxFiles {
				return res, overCap(ReasonTooManyFiles), nil
			}
		} else {
			res.Fields++
			if res.Fields > l.MaxFields {
				return res, overCap(ReasonTooManyVars), nil
			}
		}

		w.str("--" + newBoundary + "\r\nContent-Disposition: form-data; name=\"" + d.Name + "\"")
		if d.HasFilename {
			w.str("; filename=\"" + d.Filename + "\"")
		}
		w.str("\r\n")
		if ct != "" {
			w.str("Content-Type: " + ct + "\r\n")
		}
		w.str("\r\n")
		if w.err != nil {
			return res, nil, &IOError{Err: w.err}
		}

		var data io.Reader = p
		if !d.HasFilename {
			data = io.LimitReader(p, l.MaxFieldValue+1)
		}
		n, err := io.Copy(w, data)
		if err != nil {
			if w.err != nil {
				return res, nil, &IOError{Err: w.err}
			}
			return res, nil, classify(err)
		}
		if !d.HasFilename && n > l.MaxFieldValue {
			return res, overCap(ReasonFieldTooLarge), nil
		}
		if declaredLen >= 0 && declaredLen != n {
			return res, malformed(ReasonPartLength), nil
		}
		w.str("\r\n")
	}
	w.str("--" + newBoundary + "--\r\n")
	if w.err != nil {
		return res, nil, &IOError{Err: w.err}
	}
	return res, nil, nil
}

// UploadProgressViolation returns the PA-UPROG violation (SPEC 4.1: 403).
func UploadProgressViolation() *policy.Violation {
	return &policy.Violation{Reason: ReasonUploadProgress, Status: http.StatusForbidden}
}

// classifyErr maps an error from the multipart reader: I/O errors from the
// source pass through as *IOError; anything else (including a missing
// final boundary) is a syntax error.
func classifyErr(err error) error {
	var ioErr *IOError
	if errors.As(err, &ioErr) {
		return ioErr
	}
	return &syntaxError{err: err}
}

type syntaxError struct{ err error }

func (e *syntaxError) Error() string { return fmt.Sprintf("multipart: syntax: %v", e.err) }

// AsViolation turns an error returned by Canonicalize into a PA-MPART
// violation if it is a syntax error. It returns nil for I/O errors.
func AsViolation(err error) *policy.Violation {
	var se *syntaxError
	if errors.As(err, &se) {
		return malformed(ReasonMalformed)
	}
	return nil
}

// identityEncoding reports whether a part Content-Transfer-Encoding leaves
// the data untouched (RFC 2045 7bit, 8bit, binary).
func identityEncoding(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "7bit", "8bit", "binary":
		return true
	}
	return false
}

func parseLength(v string) (int64, bool) {
	if v == "" || len(v) > 18 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
		n = n*10 + int64(v[i]-'0')
	}
	return n, true
}

func validPartType(ct string) bool {
	if ct == "" || len(ct) > MaxPartTypeLength {
		return false
	}
	for i := 0; i < len(ct); i++ {
		if c := ct[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	_, _, err := mime.ParseMediaType(ct)
	return err == nil
}

// srcReader marks read errors (other than EOF) from the request body and
// remembers the first one: bufio hands a partial line to textproto before
// the error, so a client failure mid-header would otherwise surface as a
// syntax error.
type srcReader struct {
	r   io.Reader
	err *IOError
}

func (s *srcReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		if s.err == nil {
			s.err = &IOError{Err: err}
		}
		return n, s.err
	}
	return n, err
}

// dstWriter records the first write error.
type dstWriter struct {
	w   io.Writer
	err error
}

func (d *dstWriter) Write(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	n, err := d.w.Write(p)
	if err != nil {
		d.err = err
	}
	return n, err
}

func (d *dstWriter) str(s string) {
	if d.err == nil {
		_, _ = d.Write([]byte(s))
	}
}
