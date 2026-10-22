// Package config loads, overrides and validates the PHParmor configuration.
//
// The YAML file is decoded on top of Default(), then PHPARMOR_ environment
// variables are applied, then the result is validated. An invalid config is
// never returned.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Control IDs. These are stable across releases (SPEC section 5).
const (
	CtlFrame       = "PA-FRAME"
	CtlHdr         = "PA-HDR"
	CtlCookieStrip = "PA-COOKIE-STRIP"
	CtlQuery       = "PA-QUERY"
	CtlURLEnc      = "PA-URLENC"
	CtlMPart       = "PA-MPART"
	CtlUProg       = "PA-UPROG"
	CtlSessCookie  = "PA-SESSCOOKIE"
	CtlStrike      = "PA-STRIKE"
	CtlRate        = "PA-RATE"
	CtlRouteMPart  = "PA-ROUTE-MPART"
)

// DefaultControls returns the default mode of every known control.
func DefaultControls() map[string]Mode {
	return map[string]Mode{
		CtlFrame:       ModeEnforce,
		CtlHdr:         ModeEnforce,
		CtlCookieStrip: ModeOff,
		CtlQuery:       ModeEnforce,
		CtlURLEnc:      ModeEnforce,
		CtlMPart:       ModeEnforce,
		CtlUProg:       ModeEnforce,
		CtlSessCookie:  ModeEnforce,
		CtlStrike:      ModeMonitor,
		CtlRate:        ModeOff,
		CtlRouteMPart:  ModeMonitor,
	}
}

// IsControl reports whether id is a known control ID.
func IsControl(id string) bool {
	_, ok := DefaultControls()[id]
	return ok
}

// Config is the full PHParmor configuration (SPEC section 8).
type Config struct {
	Listen          string          `yaml:"listen"`
	AdminListen     string          `yaml:"admin_listen"`
	LogLevel        string          `yaml:"log_level"`
	ShutdownTimeout time.Duration   `yaml:"shutdown_timeout"`
	Upstreams       []string        `yaml:"upstreams"`
	TrustedProxies  []string        `yaml:"trusted_proxies"`
	Server          Server          `yaml:"server"`
	Buffers         Buffers         `yaml:"buffers"`
	State           State           `yaml:"state"`
	PHP             PHP             `yaml:"php"`
	Controls        map[string]Mode `yaml:"controls"`
	Limits          Limits          `yaml:"limits"`
	Hosts           []Host          `yaml:"hosts"`
}

// Server holds listener and upstream connection settings.
type Server struct {
	ReadHeaderTimeout       time.Duration `yaml:"read_header_timeout"`
	BodyMinRateBytesPerSec  int64         `yaml:"body_min_rate_bytes_per_sec"`
	IdleTimeout             time.Duration `yaml:"idle_timeout"`
	MaxConcurrentRequests   int64         `yaml:"max_concurrent_requests"`
	MaxHeaderBytes          int           `yaml:"max_header_bytes"`
	UnknownHostStatus       int           `yaml:"unknown_host_status"`
	UpstreamDialTimeout     time.Duration `yaml:"upstream_dial_timeout"`
	UpstreamResponseTimeout time.Duration `yaml:"upstream_response_timeout"`
	UpstreamProbeInterval   time.Duration `yaml:"upstream_probe_interval"`
	ReadyWindow             time.Duration `yaml:"ready_window"`
}

// Buffers holds request body buffering limits (SPEC section 6.5).
type Buffers struct {
	MemoryPerRequest ByteSize `yaml:"memory_per_request"`
	MemoryGlobal     ByteSize `yaml:"memory_global"`
	SpoolDir         string   `yaml:"spool_dir"`
	SpoolQuota       ByteSize `yaml:"spool_quota"`
	OnOverload       string   `yaml:"on_overload"`
}

// State selects the strike and rate-limit backend.
type State struct {
	Backend  string `yaml:"backend"`
	RedisURL string `yaml:"redis_url"`
}

// PHP mirrors the php.ini settings PHParmor needs to know about.
type PHP struct {
	UploadProgressField string   `yaml:"upload_progress_field"`
	SessionCookieNames  []string `yaml:"session_cookie_names"`
}

// Limits are the global input limits. Routes may override any of them.
type Limits struct {
	MaxBody       ByteSize `yaml:"max_body"`
	MaxParts      int      `yaml:"max_parts"`
	MaxFiles      int      `yaml:"max_files"`
	MaxVars       int      `yaml:"max_vars"`
	MaxNesting    int      `yaml:"max_nesting"`
	MaxFieldValue ByteSize `yaml:"max_field_value"`
}

// LimitOverrides are per-route limits; nil fields inherit the global value.
type LimitOverrides struct {
	MaxBody       *ByteSize `yaml:"max_body"`
	MaxParts      *int      `yaml:"max_parts"`
	MaxFiles      *int      `yaml:"max_files"`
	MaxVars       *int      `yaml:"max_vars"`
	MaxNesting    *int      `yaml:"max_nesting"`
	MaxFieldValue *ByteSize `yaml:"max_field_value"`
}

// Host is a set of host names sharing a policy.
type Host struct {
	Names       []string        `yaml:"names"`
	CookieStrip []string        `yaml:"cookie_strip"`
	Controls    map[string]Mode `yaml:"controls"`
	Routes      []Route         `yaml:"routes"`
}

// Route is a request match within a host. The first matching route wins.
type Route struct {
	Name      string          `yaml:"name"`
	Match     Match           `yaml:"match"`
	Multipart string          `yaml:"multipart"`
	Limits    LimitOverrides  `yaml:"limits"`
	Controls  map[string]Mode `yaml:"controls"`
}

// Match selects requests by method and path. Exactly one of PathPrefix and
// PathRegex must be set. Empty Methods matches any method.
type Match struct {
	Methods    []string `yaml:"methods"`
	PathPrefix string   `yaml:"path_prefix"`
	PathRegex  string   `yaml:"path_regex"`
}

// Default returns the built-in defaults from SPEC section 8.1.
func Default() *Config {
	return &Config{
		Listen:          ":8080",
		AdminListen:     ":9090",
		LogLevel:        "info",
		ShutdownTimeout: 30 * time.Second,
		Server: Server{
			ReadHeaderTimeout:       10 * time.Second,
			BodyMinRateBytesPerSec:  4096,
			IdleTimeout:             75 * time.Second,
			MaxConcurrentRequests:   2000,
			MaxHeaderBytes:          32768,
			UnknownHostStatus:       421,
			UpstreamDialTimeout:     5 * time.Second,
			UpstreamResponseTimeout: 120 * time.Second,
			UpstreamProbeInterval:   5 * time.Second,
			ReadyWindow:             30 * time.Second,
		},
		Buffers: Buffers{
			MemoryPerRequest: 1 << 20,
			MemoryGlobal:     256 << 20,
			SpoolDir:         "/var/lib/phparmor/spool",
			SpoolQuota:       2 << 30,
			OnOverload:       "reject",
		},
		State: State{Backend: "memory"},
		PHP: PHP{
			UploadProgressField: "PHP_SESSION_UPLOAD_PROGRESS",
			SessionCookieNames:  []string{"PHPSESSID"},
		},
		Controls: DefaultControls(),
		Limits: Limits{
			MaxBody:       32 << 20,
			MaxParts:      256,
			MaxFiles:      20,
			MaxVars:       1000,
			MaxNesting:    8,
			MaxFieldValue: 1 << 20,
		},
	}
}

// Load reads the YAML file at path, applies env overrides from the process
// environment and validates the result.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	return Parse(f, os.Environ())
}

// Parse decodes YAML from r, applies env overrides from environ (KEY=VALUE
// entries) and validates the result.
func Parse(r io.Reader, environ []string) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	// Decode controls separately so a partial controls map in the file
	// merges with the defaults rather than replacing them.
	cfg.Controls = nil
	if len(bytes.TrimSpace(data)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	merged := DefaultControls()
	for id, m := range cfg.Controls {
		merged[id] = m
	}
	cfg.Controls = merged

	if err := applyEnv(cfg, environ); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
