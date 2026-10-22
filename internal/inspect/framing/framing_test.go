package framing

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var noBody = []string{"GET", "HEAD", "OPTIONS", "DELETE"}

func TestCheck(t *testing.T) {
	tests := []struct {
		name   string
		build  func() *http.Request
		reason string
		status int
	}{
		{"plain GET", func() *http.Request { return httptest.NewRequest("GET", "/", nil) }, "", 0},
		{"POST with body", func() *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader("a=1")) }, "", 0},
		{"chunked POST", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a=1"))
			r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
			return r
		}, "", 0},
		{"TE not chunked", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a"))
			r.TransferEncoding = []string{"gzip"}
			return r
		}, ReasonTransferEncoding, 400},
		{"TE list", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a"))
			r.TransferEncoding = []string{"gzip", "chunked"}
			return r
		}, ReasonTransferEncoding, 400},
		{"TE header left in map", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a"))
			r.Header.Set("Transfer-Encoding", "chunked")
			return r
		}, ReasonTransferEncoding, 400},
		{"two Content-Length", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a"))
			r.Header["Content-Length"] = []string{"1", "1"}
			return r
		}, ReasonContentLength, 400},
		{"non-numeric Content-Length", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("a"))
			r.Header["Content-Length"] = []string{"+1"}
			return r
		}, ReasonContentLength, 400},
		{"NUL in header value", func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header["X-A"] = []string{"a\x00b"}
			return r
		}, ReasonHeaderValue, 400},
		{"CR in header value", func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header["X-A"] = []string{"a\rb"}
			return r
		}, ReasonHeaderValue, 400},
		{"LF in header value", func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header["X-A"] = []string{"a\nb"}
			return r
		}, ReasonHeaderValue, 400},
		{"GET with body", func() *http.Request { return httptest.NewRequest("GET", "/", strings.NewReader("x")) }, ReasonBodyNotAllowed, 400},
		{"DELETE with chunked body", func() *http.Request {
			r := httptest.NewRequest("DELETE", "/", strings.NewReader("x"))
			r.ContentLength, r.TransferEncoding = -1, []string{"chunked"}
			return r
		}, ReasonBodyNotAllowed, 400},
		{"PUT with body allowed", func() *http.Request { return httptest.NewRequest("PUT", "/", strings.NewReader("x")) }, "", 0},
		{"gzip body", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("x"))
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}, ReasonContentEncoding, 415},
		{"identity encoding allowed", func() *http.Request {
			r := httptest.NewRequest("POST", "/", strings.NewReader("x"))
			r.Header.Set("Content-Encoding", " Identity ")
			return r
		}, "", 0},
		{"encoding without body allowed", func() *http.Request {
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Check(tt.build(), noBody)
			if tt.reason == "" {
				if v != nil {
					t.Fatalf("unexpected violation %+v", v)
				}
				return
			}
			if v == nil || v.Reason != tt.reason || v.Status != tt.status {
				t.Fatalf("got %+v, want %s/%d", v, tt.reason, tt.status)
			}
		})
	}
	if v := Check(httptest.NewRequest("GET", "/", strings.NewReader("x")), nil); v != nil {
		t.Errorf("empty no-body list should allow GET bodies: %+v", v)
	}
}
