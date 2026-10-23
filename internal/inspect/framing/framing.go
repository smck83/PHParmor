// Package framing implements the request-level part of PA-FRAME (SPEC
// section 5.1).
//
// net/http parses the request head before PHParmor sees it. It rejects
// differing Content-Length values, non-numeric lengths, non-chunked
// Transfer-Encoding, invalid header names and NUL/CR/LF in header values,
// whatever the PA-FRAME mode. It normalises (and so hides from this package)
// Content-Length together with Transfer-Encoding (treated as chunked),
// repeated identical Content-Length values, obsolete line folding and
// bare-LF line endings. That is safe because the proxy always re-frames the
// body with an exact Content-Length; server tests pin this behaviour so a Go
// upgrade cannot change it silently. The checks below repeat what can still
// be seen, so behaviour does not depend on the Go version.
package framing

import (
	"net/http"
	"strings"

	"github.com/smck83/phparmor/internal/policy"
)

// Violation reasons.
const (
	ReasonTransferEncoding = "bad_transfer_encoding"
	ReasonContentLength    = "bad_content_length"
	ReasonHeaderValue      = "invalid_header_value"
	ReasonBodyNotAllowed   = "body_not_allowed"
	ReasonContentEncoding  = "content_encoding"
)

func bad(reason string) *policy.Violation {
	return &policy.Violation{Reason: reason, Status: http.StatusBadRequest}
}

// Check validates request framing. noBody lists methods that must not carry
// a body.
func Check(r *http.Request, noBody []string) *policy.Violation {
	if te := r.TransferEncoding; len(te) > 1 || len(te) == 1 && te[0] != "chunked" {
		return bad(ReasonTransferEncoding)
	}
	if _, ok := r.Header["Transfer-Encoding"]; ok {
		return bad(ReasonTransferEncoding)
	}
	if cl := r.Header["Content-Length"]; len(cl) > 1 || len(cl) == 1 && !digits(cl[0]) {
		return bad(ReasonContentLength)
	}
	for _, vs := range r.Header {
		for _, v := range vs {
			if strings.ContainsAny(v, "\x00\r\n") {
				return bad(ReasonHeaderValue)
			}
		}
	}

	hasBody := r.ContentLength != 0 // -1 means chunked
	if hasBody {
		for _, m := range noBody {
			if r.Method == m {
				return bad(ReasonBodyNotAllowed)
			}
		}
		// A compressed body cannot be inspected, and Apache's DEFLATE input
		// filter can inflate it before PHP parses it.
		for _, ce := range r.Header.Values("Content-Encoding") {
			if !strings.EqualFold(strings.TrimSpace(ce), "identity") {
				return &policy.Violation{Reason: ReasonContentEncoding, Status: http.StatusUnsupportedMediaType}
			}
		}
	}
	return nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
