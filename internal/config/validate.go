package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Validate checks the whole config and reports every problem found.
func (c *Config) Validate() error {
	var v validator

	v.check(c.Listen != "", "listen: required")
	v.check(c.AdminListen != "", "admin_listen: required")
	v.check(c.Listen != c.AdminListen || strings.HasSuffix(c.Listen, ":0"), "admin_listen: must differ from listen")
	var lvl slog.Level
	v.check(lvl.UnmarshalText([]byte(c.LogLevel)) == nil, "log_level: want debug, info, warn or error")
	v.check(c.ShutdownTimeout > 0, "shutdown_timeout: must be > 0")

	v.check(len(c.Upstreams) > 0, "upstreams: at least one required")
	for i, u := range c.Upstreams {
		if _, err := ParseUpstream(u); err != nil {
			v.addf("upstreams[%d]: %v", i, err)
		}
	}
	if _, err := ParseTrustedProxies(c.TrustedProxies); err != nil {
		v.addf("trusted_proxies: %v", err)
	}

	s := c.Server
	v.check(s.ReadHeaderTimeout > 0, "server.read_header_timeout: must be > 0")
	v.check(s.BodyMinRateBytesPerSec > 0, "server.body_min_rate_bytes_per_sec: must be > 0")
	v.check(s.IdleTimeout > 0, "server.idle_timeout: must be > 0")
	v.check(s.MaxConcurrentRequests > 0, "server.max_concurrent_requests: must be > 0")
	v.check(s.MaxHeaderBytes >= 1024, "server.max_header_bytes: must be >= 1024")
	v.check(s.UnknownHostStatus >= 400 && s.UnknownHostStatus <= 499, "server.unknown_host_status: must be a 4xx status")
	v.check(s.UpstreamDialTimeout > 0, "server.upstream_dial_timeout: must be > 0")
	v.check(s.UpstreamResponseTimeout > 0, "server.upstream_response_timeout: must be > 0")
	v.check(s.UpstreamProbeInterval > 0, "server.upstream_probe_interval: must be > 0")
	v.check(s.ReadyWindow >= s.UpstreamProbeInterval, "server.ready_window: must be >= upstream_probe_interval")

	b := c.Buffers
	v.check(b.MemoryPerRequest > 0, "buffers.memory_per_request: must be > 0")
	v.check(b.MemoryGlobal >= b.MemoryPerRequest, "buffers.memory_global: must be >= memory_per_request")
	v.check(b.SpoolDir != "", "buffers.spool_dir: required")
	v.check(b.SpoolQuota > 0, "buffers.spool_quota: must be > 0")
	v.check(b.OnOverload == "reject" || b.OnOverload == "bypass", "buffers.on_overload: want reject or bypass")

	switch c.State.Backend {
	case "memory":
	case "redis":
		v.check(c.State.RedisURL != "", "state.redis_url: required when backend is redis")
	default:
		v.add("state.backend: want memory or redis")
	}

	v.check(isToken(c.PHP.UploadProgressField), "php.upload_progress_field: must be a non-empty token")
	sep := c.PHP.ArgSeparatorInput
	v.check(sep != "" && len(sep) <= 8 && !strings.ContainsAny(sep, "=%+[]") && printableASCII(sep),
		"php.arg_separator_input: 1 to 8 printable characters, not '=', '%', '+', '[' or ']'")
	v.check(len(c.PHP.SessionCookieNames) > 0, "php.session_cookie_names: at least one required")
	for i, n := range c.PHP.SessionCookieNames {
		v.check(isToken(n), fmt.Sprintf("php.session_cookie_names[%d]: must be a non-empty token", i))
	}

	v.controls("controls", c.Controls)
	v.limits("limits", c.Limits)

	seen := map[string]bool{}
	for hi, h := range c.Hosts {
		hp := fmt.Sprintf("hosts[%d]", hi)
		v.check(len(h.Names) > 0, hp+".names: at least one required")
		for _, n := range h.Names {
			ln := strings.ToLower(n)
			if !validHostName(ln) {
				v.addf("%s.names: invalid host name %q", hp, n)
			}
			if seen[ln] {
				v.addf("%s.names: %q is listed in more than one host", hp, n)
			}
			seen[ln] = true
		}
		for _, n := range h.CookieStrip {
			v.check(isToken(n), fmt.Sprintf("%s.cookie_strip: invalid cookie name %q", hp, n))
		}
		v.controls(hp+".controls", h.Controls)
		for ri, r := range h.Routes {
			v.route(fmt.Sprintf("%s.routes[%d]", hp, ri), r)
		}
	}

	return v.err()
}

func (v *validator) route(p string, r Route) {
	m := r.Match
	switch {
	case m.PathPrefix != "" && m.PathRegex != "":
		v.add(p + ".match: set path_prefix or path_regex, not both")
	case m.PathPrefix != "":
		v.check(strings.HasPrefix(m.PathPrefix, "/"), p+".match.path_prefix: must start with /")
	case m.PathRegex != "":
		if _, err := regexp.Compile(m.PathRegex); err != nil {
			v.addf("%s.match.path_regex: %v", p, err)
		}
	default:
		v.add(p + ".match: path_prefix or path_regex required")
	}
	for _, meth := range m.Methods {
		v.check(isToken(meth) && meth == strings.ToUpper(meth), fmt.Sprintf("%s.match.methods: invalid method %q", p, meth))
	}
	v.check(r.Multipart == "" || r.Multipart == "allow" || r.Multipart == "deny", p+".multipart: want allow or deny")
	if r.Name != "" {
		v.check(isToken(r.Name), p+".name: must be a token (used as a metric label)")
	}
	l := r.Limits
	v.check(l.MaxBody == nil || *l.MaxBody > 0, p+".limits.max_body: must be > 0")
	v.check(l.MaxParts == nil || *l.MaxParts > 0, p+".limits.max_parts: must be > 0")
	v.check(l.MaxFiles == nil || *l.MaxFiles >= 0, p+".limits.max_files: must be >= 0")
	v.check(l.MaxVars == nil || *l.MaxVars > 0, p+".limits.max_vars: must be > 0")
	v.check(l.MaxNesting == nil || *l.MaxNesting > 0, p+".limits.max_nesting: must be > 0")
	v.check(l.MaxFieldValue == nil || *l.MaxFieldValue > 0, p+".limits.max_field_value: must be > 0")
	v.check(l.MaxKeyLength == nil || *l.MaxKeyLength > 0, p+".limits.max_key_length: must be > 0")
	v.check(l.MaxQueryLength == nil || *l.MaxQueryLength > 0, p+".limits.max_query_length: must be > 0")
	v.check(l.MaxHeaders == nil || *l.MaxHeaders > 0, p+".limits.max_headers: must be > 0")
	v.check(l.MaxHeaderValue == nil || *l.MaxHeaderValue > 0, p+".limits.max_header_value: must be > 0")
	v.check(l.MaxCookies == nil || *l.MaxCookies > 0, p+".limits.max_cookies: must be > 0")
	v.check(l.MaxCookieBytes == nil || *l.MaxCookieBytes > 0, p+".limits.max_cookie_bytes: must be > 0")
	v.check(l.MaxCookieSize == nil || *l.MaxCookieSize > 0, p+".limits.max_cookie_size: must be > 0")
	if l.NoBodyMethods != nil {
		v.methods(p+".limits.no_body_methods", *l.NoBodyMethods)
	}
	if l.AllowedPartHeaders != nil {
		v.partHeaders(p+".limits.allowed_part_headers", *l.AllowedPartHeaders)
	}
	v.controls(p+".controls", r.Controls)
}

func (v *validator) limits(p string, l Limits) {
	v.check(l.MaxBody > 0, p+".max_body: must be > 0")
	v.check(l.MaxParts > 0, p+".max_parts: must be > 0")
	v.check(l.MaxFiles >= 0, p+".max_files: must be >= 0")
	v.check(l.MaxVars > 0, p+".max_vars: must be > 0")
	v.check(l.MaxNesting > 0, p+".max_nesting: must be > 0")
	v.check(l.MaxFieldValue > 0, p+".max_field_value: must be > 0")
	v.check(l.MaxKeyLength > 0, p+".max_key_length: must be > 0")
	v.check(l.MaxQueryLength > 0, p+".max_query_length: must be > 0")
	v.check(l.MaxHeaders > 0, p+".max_headers: must be > 0")
	v.check(l.MaxHeaderValue > 0, p+".max_header_value: must be > 0")
	v.check(l.MaxCookies > 0, p+".max_cookies: must be > 0")
	v.check(l.MaxCookieBytes > 0, p+".max_cookie_bytes: must be > 0")
	v.check(l.MaxCookieSize > 0, p+".max_cookie_size: must be > 0")
	v.methods(p+".no_body_methods", l.NoBodyMethods)
	v.partHeaders(p+".allowed_part_headers", l.AllowedPartHeaders)
}

func (v *validator) partHeaders(p string, hs []string) {
	for _, h := range hs {
		v.check(isToken(h), fmt.Sprintf("%s: invalid header name %q", p, h))
	}
}

func (v *validator) methods(p string, ms []string) {
	for _, m := range ms {
		v.check(isToken(m) && m == strings.ToUpper(m), fmt.Sprintf("%s: invalid method %q", p, m))
	}
}

func (v *validator) controls(p string, m map[string]Mode) {
	for id, mode := range m {
		if !IsControl(id) {
			v.addf("%s: unknown control %q", p, id)
		}
		if _, err := ParseMode(string(mode)); err != nil {
			v.addf("%s.%s: %v", p, id, err)
		}
	}
}

// ParseUpstream parses and checks an upstream base URL.
func ParseUpstream(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("must not contain userinfo, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("must not contain a path")
	}
	u.Path = ""
	return u, nil
}

// ParseTrustedProxies parses CIDRs or bare IPs (treated as single hosts).
func ParseTrustedProxies(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or IP %q", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return true
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// isToken reports whether s is a non-empty RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

type validator struct{ problems []string }

func (v *validator) add(msg string) { v.problems = append(v.problems, msg) }

func (v *validator) addf(format string, args ...any) { v.add(fmt.Sprintf(format, args...)) }

func (v *validator) check(ok bool, msg string) {
	if !ok {
		v.add(msg)
	}
}

func (v *validator) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid config:\n  %s", strings.Join(v.problems, "\n  "))
}
