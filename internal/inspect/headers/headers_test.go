package headers

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

var limits = Limits{
	MaxHeaders: 10, MaxHeaderValue: 200,
	MaxCookies: 3, MaxCookieBytes: 100, MaxCookieSize: 30,
	MaxNesting: 2, MaxKeyLength: 12,
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestCheck(t *testing.T) {
	many := http.Header{}
	for i := 0; i < 10; i++ {
		many.Add("X-H"+strconv.Itoa(i), "v")
	}
	repeated := http.Header{"X-A": make([]string, 10)}

	tests := []struct {
		name   string
		h      http.Header
		reason string
		status int
	}{
		{"no headers", http.Header{}, "", 0},
		{"plain cookies", hdr("Cookie", "a=1; b[x]=2; PHPSESSID=abc"), "", 0},
		{"too many headers (Host counts)", many, ReasonTooManyHeaders, 431},
		{"repeated header lines count", repeated, ReasonTooManyHeaders, 431},
		{"header value too large", hdr("X-A", strings.Repeat("v", 201)), ReasonHeaderTooLarge, 431},
		{"two Cookie headers", hdr("Cookie", "a=1", "Cookie", "b=2"), ReasonMultipleCookie, 400},
		{"cookie header too large", hdr("Cookie", strings.Repeat("a=1;", 30)), ReasonCookieHdrTooBig, 431},
		{"too many cookies", hdr("Cookie", "a=1; b=2; c=3; d=4"), ReasonTooManyCookies, 431},
		{"empty cookie segments ignored", hdr("Cookie", "a=1;;; ;b=2"), "", 0},
		{"single cookie too large", hdr("Cookie", "a="+strings.Repeat("x", 29)), ReasonCookieTooLarge, 431},
		{"cookie name too deep", hdr("Cookie", "a[1][2][3]=x"), ReasonCookieTooDeep, 400},
		{"encoded cookie nesting", hdr("Cookie", "a%5B1%5D%5B2%5D%5B3%5D=x"), ReasonCookieTooDeep, 400},
		{"cookie key too long", hdr("Cookie", "abcdefghijklm=1"), ReasonCookieKeyTooLong, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Check(tt.h, limits)
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
}

func TestStripCookies(t *testing.T) {
	names := []string{"PHPSESSID", "my.cookie"}
	tests := []struct {
		name, in, want string
		removed        int
	}{
		{"no match", "a=1; b=2", "a=1; b=2", 0},
		{"middle", "a=1; PHPSESSID=x; b=2", "a=1; b=2", 1},
		{"first", "PHPSESSID=x; b=2", " b=2", 1},
		{"only", "PHPSESSID=x", "", 1},
		{"all with stray separators", "PHPSESSID=x; ;", "", 1},
		{"percent-encoded name", "PHP%53ESSID=x; a=1", " a=1", 1},
		{"plus and NUL tail", "a=1; PHPSESSID%00junk=x", "a=1", 1},
		{"array form", "PHPSESSID[x]=1; a=1", " a=1", 1},
		{"leading whitespace", "a=1;\t PHPSESSID=x", "a=1", 1},
		{"dot normalised both sides", "my_cookie=1; my.cookie=2; a=3", " a=3", 2},
		{"repeated", "PHPSESSID=1; PHPSESSID=2; a=1", " a=1", 2},
		{"case sensitive like PHP", "phpsessid=x", "phpsessid=x", 0},
		{"prefix only", "PHPSESSIDX=1", "PHPSESSIDX=1", 0},
		{"value bytes kept exactly", "a=\"q;r\"; PHPSESSID=x", "a=\"q;r\"", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, n := StripCookies(tt.in, names)
			if got != tt.want || n != tt.removed {
				t.Fatalf("StripCookies(%q) = %q, %d; want %q, %d", tt.in, got, n, tt.want, tt.removed)
			}
		})
	}
	if got, n := StripCookies("a=1", nil); got != "a=1" || n != 0 {
		t.Errorf("no names: %q %d", got, n)
	}
}

func FuzzStripCookies(f *testing.F) {
	for _, s := range []string{"", "a=1; PHPSESSID=2", "PHP%53ESSID=x", ";;;", "PHPSESSID[a][b]=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, n := StripCookies(s, []string{"PHPSESSID"})
		if n == 0 && out != s {
			t.Fatalf("changed without removing: %q -> %q", s, out)
		}
		if len(out) > len(s) {
			t.Fatalf("grew: %q -> %q", s, out)
		}
		// Idempotent: nothing left for PHP to register as PHPSESSID.
		if _, again := StripCookies(out, []string{"PHPSESSID"}); again != 0 {
			t.Fatalf("second pass removed %d from %q", again, out)
		}
	})
}
