package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = "upstreams: [\"http://127.0.0.1:8081\"]\n"

func mustParse(t *testing.T, yml string, env ...string) *Config {
	t.Helper()
	cfg, err := Parse(strings.NewReader(yml), env)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestExampleConfigParses(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if got := cfg.Hosts[0].Routes[0].Limits.MaxBody; got == nil || *got != 50<<20 {
		t.Errorf("route max_body = %v, want 50MiB", got)
	}
	if cfg.Controls[CtlCookieStrip] != ModeOff {
		t.Errorf("PA-COOKIE-STRIP = %q, want off (YAML 'off' must stay a string)", cfg.Controls[CtlCookieStrip])
	}
}

func TestDefaults(t *testing.T) {
	cfg := mustParse(t, minimal)
	if cfg.Listen != ":8080" || cfg.AdminListen != ":9090" {
		t.Errorf("listeners = %q %q", cfg.Listen, cfg.AdminListen)
	}
	if cfg.Limits.MaxBody != 32<<20 || cfg.Buffers.MemoryGlobal != 256<<20 {
		t.Errorf("limits not defaulted: %+v %+v", cfg.Limits, cfg.Buffers)
	}
	if cfg.Server.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("read_header_timeout = %v", cfg.Server.ReadHeaderTimeout)
	}
	for id, want := range DefaultControls() {
		if cfg.Controls[id] != want {
			t.Errorf("control %s = %q, want %q", id, cfg.Controls[id], want)
		}
	}
}

func TestPartialControlsMergeWithDefaults(t *testing.T) {
	cfg := mustParse(t, minimal+"controls: { PA-STRIKE: enforce }\n")
	if cfg.Controls[CtlStrike] != ModeEnforce {
		t.Errorf("PA-STRIKE = %q", cfg.Controls[CtlStrike])
	}
	if cfg.Controls[CtlFrame] != ModeEnforce || len(cfg.Controls) != len(DefaultControls()) {
		t.Errorf("defaults lost: %v", cfg.Controls)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name, yml, want string
	}{
		{"unknown key", minimal + "lisen: \":1\"\n", "field lisen not found"},
		{"bad byte size", minimal + "limits: { max_body: 32MB }\n", "invalid byte size"},
		{"bad mode", minimal + "controls: { PA-FRAME: block }\n", "invalid mode"},
		{"bad duration", minimal + "server: { idle_timeout: soon }\n", "time.Duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.yml), nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"no listen", func(c *Config) { c.Listen = "" }, "listen: required"},
		{"same listeners", func(c *Config) { c.AdminListen = c.Listen }, "must differ"},
		{"bad log level", func(c *Config) { c.LogLevel = "loud" }, "log_level"},
		{"zero shutdown", func(c *Config) { c.ShutdownTimeout = 0 }, "shutdown_timeout"},
		{"no upstreams", func(c *Config) { c.Upstreams = nil }, "upstreams: at least one"},
		{"upstream scheme", func(c *Config) { c.Upstreams = []string{"ftp://x"} }, "scheme"},
		{"upstream path", func(c *Config) { c.Upstreams = []string{"http://x/app"} }, "path"},
		{"upstream query", func(c *Config) { c.Upstreams = []string{"http://x?a=1"} }, "query"},
		{"upstream userinfo", func(c *Config) { c.Upstreams = []string{"http://u:p@x"} }, "userinfo"},
		{"bad cidr", func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/33"} }, "trusted_proxies"},
		{"zero header timeout", func(c *Config) { c.Server.ReadHeaderTimeout = 0 }, "read_header_timeout"},
		{"zero min rate", func(c *Config) { c.Server.BodyMinRateBytesPerSec = 0 }, "body_min_rate"},
		{"zero idle", func(c *Config) { c.Server.IdleTimeout = 0 }, "idle_timeout"},
		{"zero concurrency", func(c *Config) { c.Server.MaxConcurrentRequests = 0 }, "max_concurrent_requests"},
		{"tiny header bytes", func(c *Config) { c.Server.MaxHeaderBytes = 10 }, "max_header_bytes"},
		{"unknown host status", func(c *Config) { c.Server.UnknownHostStatus = 200 }, "unknown_host_status"},
		{"zero dial timeout", func(c *Config) { c.Server.UpstreamDialTimeout = 0 }, "upstream_dial_timeout"},
		{"zero response timeout", func(c *Config) { c.Server.UpstreamResponseTimeout = 0 }, "upstream_response_timeout"},
		{"zero probe interval", func(c *Config) { c.Server.UpstreamProbeInterval = 0 }, "upstream_probe_interval"},
		{"ready window too short", func(c *Config) { c.Server.ReadyWindow = time.Second }, "ready_window"},
		{"zero per-request memory", func(c *Config) { c.Buffers.MemoryPerRequest = 0 }, "memory_per_request"},
		{"global below per-request", func(c *Config) { c.Buffers.MemoryGlobal = 1 }, "memory_global"},
		{"no spool dir", func(c *Config) { c.Buffers.SpoolDir = "" }, "spool_dir"},
		{"zero spool quota", func(c *Config) { c.Buffers.SpoolQuota = 0 }, "spool_quota"},
		{"bad on_overload", func(c *Config) { c.Buffers.OnOverload = "ignore" }, "on_overload"},
		{"bad backend", func(c *Config) { c.State.Backend = "etcd" }, "state.backend"},
		{"redis without url", func(c *Config) { c.State.Backend = "redis" }, "redis_url"},
		{"empty upload field", func(c *Config) { c.PHP.UploadProgressField = "" }, "upload_progress_field"},
		{"no session cookies", func(c *Config) { c.PHP.SessionCookieNames = nil }, "session_cookie_names"},
		{"bad session cookie", func(c *Config) { c.PHP.SessionCookieNames = []string{"a b"} }, "session_cookie_names[0]"},
		{"unknown control", func(c *Config) { c.Controls["PA-NOPE"] = ModeOff }, "unknown control"},
		{"zero max_body", func(c *Config) { c.Limits.MaxBody = 0 }, "limits.max_body"},
		{"zero max_parts", func(c *Config) { c.Limits.MaxParts = 0 }, "limits.max_parts"},
		{"negative max_files", func(c *Config) { c.Limits.MaxFiles = -1 }, "limits.max_files"},
		{"zero max_vars", func(c *Config) { c.Limits.MaxVars = 0 }, "limits.max_vars"},
		{"zero max_nesting", func(c *Config) { c.Limits.MaxNesting = 0 }, "limits.max_nesting"},
		{"zero max_field_value", func(c *Config) { c.Limits.MaxFieldValue = 0 }, "limits.max_field_value"},
		{"host without names", func(c *Config) { c.Hosts = []Host{{}} }, "names: at least one"},
		{"bad host name", func(c *Config) { c.Hosts = []Host{{Names: []string{"a b"}}} }, "invalid host name"},
		{"duplicate host", func(c *Config) {
			c.Hosts = []Host{{Names: []string{"a.test"}}, {Names: []string{"A.test"}}}
		}, "more than one host"},
		{"bad cookie_strip", func(c *Config) { c.Hosts = []Host{{Names: []string{"a"}, CookieStrip: []string{"x;y"}}} }, "cookie_strip"},
		{"host unknown control", func(c *Config) {
			c.Hosts = []Host{{Names: []string{"a"}, Controls: map[string]Mode{"X": ModeOff}}}
		}, "unknown control"},
		{"route no match", func(c *Config) { c.Hosts = route(Route{}) }, "path_prefix or path_regex required"},
		{"route both matches", func(c *Config) {
			c.Hosts = route(Route{Match: Match{PathPrefix: "/", PathRegex: "x"}})
		}, "not both"},
		{"route relative prefix", func(c *Config) { c.Hosts = route(Route{Match: Match{PathPrefix: "x"}}) }, "must start with /"},
		{"route bad regex", func(c *Config) { c.Hosts = route(Route{Match: Match{PathRegex: "("}}) }, "path_regex"},
		{"route lowercase method", func(c *Config) {
			c.Hosts = route(Route{Match: Match{PathPrefix: "/", Methods: []string{"post"}}})
		}, "invalid method"},
		{"route bad multipart", func(c *Config) {
			c.Hosts = route(Route{Match: Match{PathPrefix: "/"}, Multipart: "maybe"})
		}, "multipart"},
		{"route bad name", func(c *Config) { c.Hosts = route(Route{Name: "a b", Match: Match{PathPrefix: "/"}}) }, "name"},
		{"route zero max_body", func(c *Config) {
			z := ByteSize(0)
			c.Hosts = route(Route{Match: Match{PathPrefix: "/"}, Limits: LimitOverrides{MaxBody: &z}})
		}, "limits.max_body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			c.Upstreams = []string{"http://127.0.0.1:8081"}
			tt.mod(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func route(r Route) []Host { return []Host{{Names: []string{"a.test"}, Routes: []Route{r}}} }

func TestEnvOverrides(t *testing.T) {
	cfg := mustParse(t, minimal,
		"PHPARMOR_LISTEN=:7000",
		"PHPARMOR_SERVER__READ_HEADER_TIMEOUT=3s",
		"PHPARMOR_SERVER__MAX_CONCURRENT_REQUESTS=7",
		"PHPARMOR_BUFFERS__MEMORY_GLOBAL=64MiB",
		"PHPARMOR_UPSTREAMS=http://a:1, http://b:2",
		"PHPARMOR_PHP__SESSION_COOKIE_NAMES=SID",
		"PHPARMOR_CONTROLS__PA_COOKIE_STRIP=enforce",
		"PHPARMOR_CONFIG=/ignored.yaml",
		"OTHER=ignored",
	)
	if cfg.Listen != ":7000" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Server.ReadHeaderTimeout != 3*time.Second || cfg.Server.MaxConcurrentRequests != 7 {
		t.Errorf("server = %+v", cfg.Server)
	}
	if cfg.Buffers.MemoryGlobal != 64<<20 {
		t.Errorf("memory_global = %v", cfg.Buffers.MemoryGlobal)
	}
	if strings.Join(cfg.Upstreams, "|") != "http://a:1|http://b:2" {
		t.Errorf("upstreams = %v", cfg.Upstreams)
	}
	if strings.Join(cfg.PHP.SessionCookieNames, "|") != "SID" {
		t.Errorf("session_cookie_names = %v", cfg.PHP.SessionCookieNames)
	}
	if cfg.Controls[CtlCookieStrip] != ModeEnforce {
		t.Errorf("PA-COOKIE-STRIP = %q", cfg.Controls[CtlCookieStrip])
	}
}

func TestEnvRejects(t *testing.T) {
	tests := []struct{ env, want string }{
		{"PHPARMOR_LISEN=:1", "unknown setting"},
		{"PHPARMOR_SERVER__IDLE_TIMEOUT=forever", "invalid duration"},
		{"PHPARMOR_LIMITS__MAX_PARTS=many", "invalid integer"},
		{"PHPARMOR_LIMITS__MAX_BODY=1TB", "invalid byte size"},
		{"PHPARMOR_CONTROLS__PA_NOPE=off", "unknown control"},
		{"PHPARMOR_CONTROLS__PA_FRAME=block", "invalid mode"},
		{"PHPARMOR_HOSTS=a", "not settable"},
		{"PHPARMOR_SERVER__MAX_CONCURRENT_REQUESTS=0", "max_concurrent_requests"},
	}
	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			_, err := Parse(strings.NewReader(minimal), []string{tt.env})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in   string
		want ByteSize
		ok   bool
	}{
		{"4096", 4096, true},
		{"8KiB", 8 << 10, true},
		{"32MiB", 32 << 20, true},
		{"2GiB", 2 << 30, true},
		{"10B", 10, true},
		{" 1 MiB ", 1 << 20, true},
		{"32MB", 0, false},
		{"-1", 0, false},
		{"MiB", 0, false},
		{"99999999999GiB", 0, false},
	}
	for _, tt := range tests {
		got, err := ParseByteSize(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("ParseByteSize(%q) = %v, %v", tt.in, got, err)
		}
	}
	if s := ByteSize(32 << 20).String(); s != "32MiB" {
		t.Errorf("String = %q", s)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}
