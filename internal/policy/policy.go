// Package policy resolves the host and route policy for a request and defines
// the decision records every control produces.
package policy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/smck83/phparmor/internal/config"
)

// Outcome is the result of a control evaluating a request or response.
type Outcome string

const (
	Pass       Outcome = "pass"
	WouldBlock Outcome = "would_block"
	Block      Outcome = "block"
	Modify     Outcome = "modify"
)

// Decision is the record a control produces. Reason must never contain
// cookie values, header values or body content.
type Decision struct {
	Control string      `json:"control"`
	Mode    config.Mode `json:"mode"`
	Outcome Outcome     `json:"outcome"`
	Reason  string      `json:"reason,omitempty"`
}

// Metric labels used when no configured host or route applies. Labels are
// always taken from config, never from request data, to bound cardinality.
const (
	LabelAnyHost      = "_any"
	LabelUnknownHost  = "_unknown"
	LabelDefaultRoute = "_default"
)

// Policy is a compiled, immutable view of the host and route config.
type Policy struct {
	hosts     map[string]*Host
	fallback  *Host // used when no hosts are configured
	unknownSC int
}

// Host is the compiled policy for one configured host entry.
type Host struct {
	Label       string
	CookieStrip []string
	Routes      []*Route
	Default     *Route
}

// Route is the compiled, fully resolved policy for one route.
type Route struct {
	Label     string
	Methods   map[string]bool
	Prefix    string
	Regex     *regexp.Regexp
	Multipart string
	Limits    config.Limits
	Controls  map[string]config.Mode
}

// Mode returns the effective mode of a control on this route.
func (r *Route) Mode(control string) config.Mode {
	if m, ok := r.Controls[control]; ok {
		return m
	}
	return config.ModeOff
}

// Compile builds a Policy from a validated config.
func Compile(cfg *config.Config) (*Policy, error) {
	p := &Policy{hosts: map[string]*Host{}, unknownSC: cfg.Server.UnknownHostStatus}

	if len(cfg.Hosts) == 0 {
		p.fallback = &Host{
			Label:   LabelAnyHost,
			Default: defaultRoute(cfg, nil),
		}
		return p, nil
	}

	for hi, hc := range cfg.Hosts {
		h := &Host{
			Label:       strings.ToLower(hc.Names[0]),
			CookieStrip: hc.CookieStrip,
			Default:     defaultRoute(cfg, hc.Controls),
		}
		for ri, rc := range hc.Routes {
			r, err := compileRoute(cfg, hc.Controls, rc, ri)
			if err != nil {
				return nil, fmt.Errorf("hosts[%d].routes[%d]: %w", hi, ri, err)
			}
			h.Routes = append(h.Routes, r)
		}
		for _, n := range hc.Names {
			p.hosts[strings.ToLower(n)] = h
		}
	}
	return p, nil
}

func defaultRoute(cfg *config.Config, hostControls map[string]config.Mode) *Route {
	return &Route{
		Label:     LabelDefaultRoute,
		Multipart: "allow",
		Limits:    cfg.Limits,
		Controls:  mergeControls(cfg.Controls, hostControls, nil),
	}
}

func compileRoute(cfg *config.Config, hostControls map[string]config.Mode, rc config.Route, idx int) (*Route, error) {
	r := &Route{
		Label:     rc.Name,
		Prefix:    rc.Match.PathPrefix,
		Multipart: rc.Multipart,
		Limits:    mergeLimits(cfg.Limits, rc.Limits),
		Controls:  mergeControls(cfg.Controls, hostControls, rc.Controls),
	}
	if r.Label == "" {
		r.Label = strconv.Itoa(idx)
	}
	if r.Multipart == "" {
		r.Multipart = "allow"
	}
	if len(rc.Match.Methods) > 0 {
		r.Methods = map[string]bool{}
		for _, m := range rc.Match.Methods {
			r.Methods[m] = true
		}
	}
	if rc.Match.PathRegex != "" {
		re, err := regexp.Compile(rc.Match.PathRegex)
		if err != nil {
			return nil, fmt.Errorf("path_regex: %w", err)
		}
		r.Regex = re
	}
	return r, nil
}

func mergeControls(layers ...map[string]config.Mode) map[string]config.Mode {
	out := map[string]config.Mode{}
	for _, l := range layers {
		for k, v := range l {
			out[k] = v
		}
	}
	return out
}

func mergeLimits(base config.Limits, o config.LimitOverrides) config.Limits {
	if o.MaxBody != nil {
		base.MaxBody = *o.MaxBody
	}
	if o.MaxParts != nil {
		base.MaxParts = *o.MaxParts
	}
	if o.MaxFiles != nil {
		base.MaxFiles = *o.MaxFiles
	}
	if o.MaxVars != nil {
		base.MaxVars = *o.MaxVars
	}
	if o.MaxNesting != nil {
		base.MaxNesting = *o.MaxNesting
	}
	if o.MaxFieldValue != nil {
		base.MaxFieldValue = *o.MaxFieldValue
	}
	if o.MaxKeyLength != nil {
		base.MaxKeyLength = *o.MaxKeyLength
	}
	if o.MaxQueryLength != nil {
		base.MaxQueryLength = *o.MaxQueryLength
	}
	if o.MaxHeaders != nil {
		base.MaxHeaders = *o.MaxHeaders
	}
	if o.MaxHeaderValue != nil {
		base.MaxHeaderValue = *o.MaxHeaderValue
	}
	if o.MaxCookies != nil {
		base.MaxCookies = *o.MaxCookies
	}
	if o.MaxCookieBytes != nil {
		base.MaxCookieBytes = *o.MaxCookieBytes
	}
	if o.MaxCookieSize != nil {
		base.MaxCookieSize = *o.MaxCookieSize
	}
	if o.NoBodyMethods != nil {
		base.NoBodyMethods = *o.NoBodyMethods
	}
	if o.AllowedPartHeaders != nil {
		base.AllowedPartHeaders = *o.AllowedPartHeaders
	}
	return base
}

// Match is the policy resolved for one request.
type Match struct {
	Host  *Host
	Route *Route
}

// Resolve finds the host and first matching route for a request. hostHeader
// may include a port. ok is false when hosts are configured and none match;
// UnknownHostStatus gives the status to reply with.
func (p *Policy) Resolve(hostHeader, method, path string) (m Match, ok bool) {
	h := p.fallback
	if h == nil {
		h = p.hosts[normaliseHost(hostHeader)]
		if h == nil {
			return Match{}, false
		}
	}
	for _, r := range h.Routes {
		if r.matches(method, path) {
			return Match{Host: h, Route: r}, true
		}
	}
	return Match{Host: h, Route: h.Default}, true
}

// UnknownHostStatus is the status returned for hosts not in the config.
func (p *Policy) UnknownHostStatus() int { return p.unknownSC }

func (r *Route) matches(method, path string) bool {
	if r.Methods != nil && !r.Methods[method] {
		return false
	}
	if r.Regex != nil {
		return r.Regex.MatchString(path)
	}
	return strings.HasPrefix(path, r.Prefix)
}

func normaliseHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
