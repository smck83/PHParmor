# PHParmor

> **PHParmor is a stopgap, not a fix.** The only complete remediation for
> PHP2Shell (CVE-2026-109618, CVE-2026-109619) is a patched PHP runtime.
> Deploy PHParmor to reduce exposure while you patch, and apply the host-side
> mitigations below as well.

PHParmor is a reverse proxy that sits between your load balancer and a legacy
PHP web stack (nginx or Apache in front of PHP). It hardens the HTTP input PHP
parses before any application code runs. See [SPEC.md](SPEC.md) for the full
design.

```
Client -> ALB (TLS, WAF) -> phparmor (N replicas) -> nginx/Apache -> PHP-FPM / mod_php
```

## Status

Milestone **M1 (skeleton)**: config with env overrides and SIGHUP reload, data
and admin listeners, pass-through proxy, JSON access logs, Prometheus metrics,
and health endpoints. **No PHP2Shell controls are active yet**: they land in
M2 to M5 (SPEC section 15).

What M1 already does on every request:

- Caps concurrent requests (503 with `Retry-After` when full).
- Rejects unknown `Host` values with 421 when `hosts` is configured.
- Buffers the request body in memory under the route's `max_body` (413 when
  over) and a global budget (`buffers.memory_global`; 503 when exhausted,
  unless `on_overload: bypass`). It enforces `body_min_rate_bytes_per_sec`
  while reading.
- Forwards with an exact `Content-Length`. `Transfer-Encoding` is never sent
  upstream.
- Preserves the client `Host`, sets `X-Forwarded-For` (trusted chain plus
  peer), `X-Forwarded-Proto` (trusted value or `http`) and `X-Request-ID`. It
  strips `Forwarded` and `X-Real-IP` from untrusted peers.

## Running

```bash
make build
./bin/phparmor -config deploy/config.example.yaml
```

Flags: `-config` (or `PHPARMOR_CONFIG`; default `/etc/phparmor/config.yaml`),
`-check` (validate the config and exit), `-version`.

Signals: `SIGHUP` reloads the config. An invalid config is rejected and the
running config is kept. `SIGTERM` stops accepting connections and drains
in-flight requests for up to `shutdown_timeout`.

## Configuration

See [deploy/config.example.yaml](deploy/config.example.yaml). Every scalar can
be overridden with an environment variable: the `PHPARMOR_` prefix plus the
upper-cased key path joined by `__`, for example
`PHPARMOR_SERVER__READ_HEADER_TIMEOUT=5s`. Lists of scalars take
comma-separated values (`PHPARMOR_UPSTREAMS=http://a,http://b`). Control modes
use `PHPARMOR_CONTROLS__PA_FRAME=monitor`, where underscores in the ID stand
for hyphens. `hosts` can only be set in the file. Unknown keys and unknown
`PHPARMOR_` variables are errors, so typos do not silently disable anything.

These settings need a restart to change (a reload logs a warning and keeps the
running value): `listen`, `admin_listen`, `server.read_header_timeout`,
`server.idle_timeout`, `server.max_header_bytes`,
`server.upstream_dial_timeout`, `server.upstream_response_timeout`,
`buffers.spool_dir` and `state`.

## Admin endpoints (`admin_listen`, never expose publicly)

| Path | Purpose |
|---|---|
| `/healthz` | Process is up |
| `/readyz` | Not draining, spool directory writable, an upstream reached within `server.ready_window` |
| `/metrics` | Prometheus metrics |
| `/version` | Version, commit and the stopgap notice |

## Host-side mitigations (do these too)

The proxy cannot reach PHP worker state. Alongside PHParmor:

- Install a patched PHP runtime (8.5.12, 8.4.27, 8.3.36, 8.2.35, or a
  distro/vendor backport).
- Set `session.upload_progress.enabled=0` in php.ini or the FPM pool.
- Set `memory_limit=-1` via `php_admin_value`, bounded by a cgroup or
  container memory limit. Never use `RLIMIT_AS` or `RLIMIT_DATA`.
- Set `post_max_size` to 8M (no uploads) or 32M.
- On PHP 8.5, set `fatal_error_backtraces=0`.
- Consider `pm.max_requests=1` to stop stale state crossing requests
  (benchmark first).
- Lock the upstream so it only accepts traffic from PHParmor.

## Development

| Command | What it does |
|---|---|
| `make test` | Unit tests (with `-race`) |
| `make lint` | `go vet`, staticcheck, gosec, govulncheck |
| `make fuzz` | Fuzz smoke per target (from M3) |
| `make harness` | PHP equivalence harness (from M6) |
| `make bench` | Benchmarks (from M6) |
| `make image` | Distroless container image (from M7) |

## Licence

Apache-2.0. See [LICENSE](LICENSE).
