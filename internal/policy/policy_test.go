package policy

import (
	"strings"
	"testing"

	"github.com/smck83/phparmor/internal/config"
)

const hostsYAML = `
upstreams: ["http://127.0.0.1:1"]
controls: { PA-STRIKE: monitor }
hosts:
  - names: ["App.Example.com", "www.example.com"]
    controls: { PA-COOKIE-STRIP: enforce }
    routes:
      - name: upload
        match: { methods: [POST], path_prefix: "/reports/upload" }
        limits: { max_body: 50MiB }
        controls: { PA-STRIKE: enforce }
      - match: { path_regex: "^/api/v[0-9]+/" }
        multipart: deny
      - match: { path_prefix: "/" }
        limits: { max_body: 8MiB }
`

func compile(t *testing.T, yml string) *Policy {
	t.Helper()
	cfg, err := config.Parse(strings.NewReader(yml), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolve(t *testing.T) {
	p := compile(t, hostsYAML)
	tests := []struct {
		name, host, method, path string
		ok                       bool
		hostLabel, route         string
		maxBody                  config.ByteSize
	}{
		{"upload route", "app.example.com", "POST", "/reports/upload/x", true, "app.example.com", "upload", 50 << 20},
		{"upload wrong method falls through", "app.example.com", "GET", "/reports/upload", true, "app.example.com", "2", 8 << 20},
		{"regex route", "app.example.com", "GET", "/api/v2/x", true, "app.example.com", "1", 32 << 20},
		{"host with port and case", "WWW.example.com:8080", "GET", "/", true, "app.example.com", "2", 8 << 20},
		{"trailing dot", "www.example.com.", "GET", "/", true, "app.example.com", "2", 8 << 20},
		{"unknown host", "evil.test", "GET", "/", false, "", "", 0},
		{"empty host", "", "GET", "/", false, "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := p.Resolve(tt.host, tt.method, tt.path)
			if ok != tt.ok {
				t.Fatalf("ok = %v", ok)
			}
			if !ok {
				return
			}
			if m.Host.Label != tt.hostLabel || m.Route.Label != tt.route || m.Route.Limits.MaxBody != tt.maxBody {
				t.Errorf("got host=%s route=%s max_body=%v", m.Host.Label, m.Route.Label, m.Route.Limits.MaxBody)
			}
		})
	}
	if p.UnknownHostStatus() != 421 {
		t.Errorf("UnknownHostStatus = %d", p.UnknownHostStatus())
	}
}

func TestControlLayering(t *testing.T) {
	p := compile(t, hostsYAML)
	up, _ := p.Resolve("app.example.com", "POST", "/reports/upload")
	if up.Route.Mode(config.CtlStrike) != config.ModeEnforce {
		t.Errorf("route override lost")
	}
	if up.Route.Mode(config.CtlCookieStrip) != config.ModeEnforce {
		t.Errorf("host override lost")
	}
	if up.Route.Mode(config.CtlFrame) != config.ModeEnforce {
		t.Errorf("global default lost")
	}
	other, _ := p.Resolve("app.example.com", "GET", "/")
	if other.Route.Mode(config.CtlStrike) != config.ModeMonitor {
		t.Errorf("route override leaked to another route")
	}
	if other.Route.Mode("PA-UNKNOWN") != config.ModeOff {
		t.Errorf("unknown control should be off")
	}
}

func TestNoHostsAcceptsAny(t *testing.T) {
	p := compile(t, `upstreams: ["http://127.0.0.1:1"]`)
	m, ok := p.Resolve("anything.test", "GET", "/x")
	if !ok || m.Host.Label != LabelAnyHost || m.Route.Label != LabelDefaultRoute {
		t.Fatalf("got %v %+v", ok, m)
	}
}

func TestHostWithoutMatchingRouteUsesDefault(t *testing.T) {
	p := compile(t, `
upstreams: ["http://127.0.0.1:1"]
hosts:
  - names: [a.test]
    routes:
      - match: { path_prefix: "/only" }
`)
	m, ok := p.Resolve("a.test", "GET", "/other")
	if !ok || m.Route.Label != LabelDefaultRoute || m.Route.Limits.MaxBody != 32<<20 {
		t.Fatalf("got %v %+v", ok, m.Route)
	}
}
