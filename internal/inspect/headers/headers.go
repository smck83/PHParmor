// Package headers implements PA-HDR (header and cookie limits) and
// PA-COOKIE-STRIP (SPEC section 5.2).
package headers

import (
	"net/http"
	"strings"

	"github.com/smck83/phparmor/internal/inspect/query"
	"github.com/smck83/phparmor/internal/policy"
)

// Limits are the PA-HDR limits. MaxNesting and MaxKeyLength apply to cookie
// names, which PHP parses into $_COOKIE with the same rules as the query.
type Limits struct {
	MaxHeaders     int
	MaxHeaderValue int64
	MaxCookies     int
	MaxCookieBytes int64
	MaxCookieSize  int64
	MaxNesting     int
	MaxKeyLength   int
}

// Violation reasons.
const (
	ReasonTooManyHeaders   = "too_many_headers"
	ReasonHeaderTooLarge   = "header_value_too_large"
	ReasonMultipleCookie   = "multiple_cookie_headers"
	ReasonCookieHdrTooBig  = "cookie_header_too_large"
	ReasonTooManyCookies   = "too_many_cookies"
	ReasonCookieTooLarge   = "cookie_too_large"
	ReasonCookieTooDeep    = "cookie_nesting_too_deep"
	ReasonCookieKeyTooLong = "cookie_key_too_long"
)

func tooLarge(reason string) *policy.Violation {
	return &policy.Violation{Reason: reason, Status: http.StatusRequestHeaderFieldsTooLarge}
}

func malformed(reason string) *policy.Violation {
	return &policy.Violation{Reason: reason, Status: http.StatusBadRequest}
}

// Check applies the PA-HDR limits. h is the request header as parsed by
// net/http, which has already removed Host into Request.Host; the count
// includes it.
func Check(h http.Header, l Limits) *policy.Violation {
	count := 1 // Host
	for _, vs := range h {
		count += len(vs)
		for _, v := range vs {
			if int64(len(v)) > l.MaxHeaderValue {
				return tooLarge(ReasonHeaderTooLarge)
			}
		}
	}
	if count > l.MaxHeaders {
		return tooLarge(ReasonTooManyHeaders)
	}

	cookies := h.Values("Cookie")
	switch {
	case len(cookies) == 0:
		return nil
	case len(cookies) > 1:
		// HTTP/1.1 clients send one Cookie header. How several would be
		// joined differs between servers, so reject rather than guess.
		return malformed(ReasonMultipleCookie)
	}
	c := cookies[0]
	if int64(len(c)) > l.MaxCookieBytes {
		return tooLarge(ReasonCookieHdrTooBig)
	}
	n := 0
	for _, seg := range strings.Split(c, ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		n++
		if int64(len(seg)) > l.MaxCookieSize {
			return tooLarge(ReasonCookieTooLarge)
		}
	}
	if n > l.MaxCookies {
		return tooLarge(ReasonTooManyCookies)
	}
	for _, v := range query.ParseCookies(c).Vars {
		if v.Depth > l.MaxNesting {
			return malformed(ReasonCookieTooDeep)
		}
		if len(v.Key) > l.MaxKeyLength {
			return malformed(ReasonCookieKeyTooLong)
		}
	}
	return nil
}

// StripCookies removes every cookie whose name PHP would register as one of
// names (so "PHP%53ESSID" or " PHPSESSID[x]" match "PHPSESSID"). All other
// bytes of the header are kept exactly. It returns the new header value and
// the number of cookies removed.
func StripCookies(cookie string, names []string) (string, int) {
	if len(names) == 0 || cookie == "" {
		return cookie, 0
	}
	strip := make(map[string]bool, len(names))
	for _, n := range names {
		if v, ok := query.Register(n); ok {
			strip[v.Base] = true
		}
	}
	segs := strings.Split(cookie, ";")
	kept := segs[:0]
	removed := 0
	for _, seg := range segs {
		name := seg
		if i := strings.IndexByte(seg, '='); i >= 0 {
			name = seg[:i]
		}
		name = strings.TrimLeft(name, " \t\n\v\f\r")
		if v, ok := query.Register(query.Decode(name)); ok && strip[v.Base] {
			removed++
			continue
		}
		kept = append(kept, seg)
	}
	if removed == 0 {
		return cookie, 0
	}
	out := strings.Join(kept, ";")
	if strings.TrimSpace(strings.ReplaceAll(out, ";", "")) == "" {
		out = ""
	}
	return out, removed
}
