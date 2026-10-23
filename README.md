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

Milestone **M3**: framing, header, cookie and query controls, multipart
canonicalisation, the upload-progress block and per-route multipart policy
are active. **Still to come**: urlencoded bodies (PA-URLENC) in M4, and
session-cookie validation, strikes and rate limits (PA-SESSCOOKIE,
PA-STRIKE, PA-RATE) in M5 (SPEC section 15).

On every request PHParmor also:

- Caps concurrent requests (503 with `Retry-After` when full).
- Rejects unknown `Host` values with 421 when `hosts` is configured.
- Buffers the request body before forwarding: in memory up to
  `buffers.memory_per_request`, then in an owner-only temp file in
  `buffers.spool_dir`. Limits:
  - The route's `max_body` (413 when over).
  - The global `memory_global` budget and the `spool_quota` disk quota (503
    when either is exhausted, unless `on_overload: bypass`).
  - `body_min_rate_bytes_per_sec`, enforced while reading.

  Temp files are removed when the response completes or on any error.
- Forwards with an exact `Content-Length`. `Transfer-Encoding` is never sent
  upstream.
- Preserves the client `Host`, sets `X-Forwarded-For` (trusted chain plus
  peer), `X-Forwarded-Proto` (trusted value or `http`) and `X-Request-ID`. It
  strips `Forwarded` and `X-Real-IP` from untrusted peers.

## Controls

Every control has a stable ID and a mode:

- `enforce` blocks the request (or modifies it).
- `monitor` forwards the request and records `would_block`.
- `off` skips the check.

Set modes globally under `controls`, per host, or per route. Each control
that runs adds a decision to the access log line and increments
`phparmor_decisions_total{control,outcome}`. Clients only ever see a short
status text and the request ID; the control and reason go to the log.

PHP parses query strings and cookies with its own rules, and PHParmor counts
the way PHP will:

- `+` and `%XX` are decoded.
- A name is truncated at a NUL byte.
- `.` and spaces in the base name become `_`.
- An unmatched `[` becomes `_`.
- Only consecutive `[...]` groups count as nesting.

### PA-FRAME: request framing (default: enforce)

Rejects with 400:
- A body on a method in `limits.no_body_methods` (default GET, HEAD,
  OPTIONS, DELETE).
- Any `Transfer-Encoding` other than a single `chunked`.
- Repeated or non-numeric `Content-Length`.
- NUL, CR or LF in a header value.

Rejects with 415: a request body with a `Content-Encoding` other than
`identity`. PHParmor cannot inspect a compressed body, and Apache's DEFLATE
input filter can inflate it before PHP parses it.

Go's HTTP server parses the request head first:
- **Always rejected, even in monitor mode:** differing or malformed
  `Content-Length` values, non-chunked `Transfer-Encoding`, invalid header
  names, and NUL or CR in header values.
- **Normalised before PHParmor sees them:**
  - `Content-Length` together with `Transfer-Encoding` (treated as chunked).
  - Repeated identical `Content-Length` values.
  - Obsolete line folding.
  - Bare-LF line endings.

  This departs from SPEC 5.1, which says to reject them. It is safe because
  PHParmor always re-frames the body with an exact `Content-Length`, so the
  upstream never sees ambiguous framing. Tests pin this behaviour.

If you run behind an AWS ALB, also set its desync mitigation mode to
`strictest`.

*Expected breakage:* clients that send bodies on DELETE (override
`no_body_methods` per route), and clients that compress request bodies.

### PA-HDR: headers and cookies (default: enforce)

| Limit | Default | Over the limit |
|---|---|---|
| `max_headers` (header lines, including Host) | 100 | 431 |
| `max_header_value` | 8 KiB | 431 |
| `max_cookies` | 50 | 431 |
| `max_cookie_bytes` (whole Cookie header) | 8 KiB | 431 |
| `max_cookie_size` (one pair) | 4 KiB | 431 |
| Cookie-name nesting (`max_nesting`) | 8 | 400 |
| Cookie-name length (`max_key_length`) | 256 | 400 |
| More than one `Cookie` header | rejected | 400 |

PHP parses cookies into `$_COOKIE` with the same bracket-nesting rules as the
query string, so cookie names get the same nesting and key-length limits.
Requests with several `Cookie` headers are rejected because servers disagree
on how to join them.

*Expected breakage:* sites with very many or very large cookies (raise the
limits per route).

### PA-COOKIE-STRIP: strip named cookies (default: off)

Removes the cookies listed in a host's `cookie_strip` before forwarding, and
leaves every other byte of the `Cookie` header as sent. Matching uses the
name PHP would register, so `PHP%53ESSID`, `PHPSESSID%00x` and
`PHPSESSID[x]` all match `PHPSESSID`. In monitor mode it only records
`would_block`.

**For apps that do not use native PHP sessions, stripping `PHPSESSID`
removes the session upload-progress path entirely.** It is off by default
because many legacy apps do use native sessions. Enable it per host only
after confirming the app does not.

*Expected breakage:* logins and carts in apps that use native PHP sessions,
if enabled for them.

### PA-QUERY: query string (default: enforce)

| Limit | Default | Over the limit |
|---|---|---|
| `max_vars` (PHP's `max_input_vars` default) | 1000 | 400 |
| `max_nesting` (PHP allows 64) | 8 | 400 |
| `max_key_length` | 256 | 400 |
| `max_query_length` | 8 KiB | 414 |

These limit what PHP allocates when it builds `$_GET` at start-up. The query
is validated only and is forwarded byte for byte. In M4 the variable count
will be shared with urlencoded bodies.

*Expected breakage:* forms submitted by GET with more than 1000 fields or
very deep array names.

### PA-MPART: multipart canonicalisation (default: enforce)

PHParmor detects multipart bodies the way PHP does. PHP lowercases the
`Content-Type` and cuts it at the first `;`, `,` or space, so
`multipart/form-data,x; boundary=...` is still multipart and is still
inspected.

In enforce mode the body is parsed as it streams in. It is then forwarded in a
canonical form:
- A fresh random `phparmor-…` boundary.
- CRLF line endings only.
- No preamble or epilogue.
- Each part carries only `Content-Disposition: form-data; name="…"` (plus
  `filename="…"` for files) and its `Content-Type`.
- An exact `Content-Length`.

PHP only ever sees the structure PHParmor parsed, so folded or bloated part
headers and other parser-differential tricks never reach it.

| Rule | Default | Status |
|---|---|---|
| `Content-Type`: exactly one `boundary`, 1–70 RFC 2046 characters, no duplicate or unknown parameters (`charset` allowed) | | 400 |
| Part headers allowed (`limits.allowed_part_headers`) | `Content-Disposition`, `Content-Type`, `Content-Length`, `Content-Transfer-Encoding` | 400 |
| Part `Content-Length` must match the data | | 400 |
| Part `Content-Transfer-Encoding` must be `7bit`, `8bit` or `binary` | | 400 |
| Disposition type `form-data`; `name` required, 1–256 bytes; `filename` up to 255 bytes; no `"`, `\`, control characters or DEL; no duplicate or unknown parameters | | 400 |
| `filename*` without a plain `filename`; any `name*` | | 400 |
| Nesting in field names (`max_nesting`) | 8 | 400 |
| Part `Content-Type` up to 128 bytes, a valid media type | | 400 |
| Missing final boundary, or anything the parser cannot read | | 400 |
| Parts (`max_parts`) | 256 | 413 |
| File parts (`max_files`) | 20 | 413 |
| Fields plus query variables (`max_vars`) | 1000 | 413 |
| One field value (`max_field_value`) | 1 MiB | 413 |

**Differences from SPEC 6.2, all found through the benign corpus:**
- **Part `Content-Length`:** Guzzle sends one on every part.
- **Identity `Content-Transfer-Encoding`:** Apache HttpClient 4 sends one on
  every part by default.
- **`filename*` alongside `filename`:** .NET `HttpClient` always sends both.

PHP ignores all three: it uses the plain `filename`, and an identity transfer
encoding changes nothing. PHParmor checks them, then drops them from the
canonical body. Remove `Content-Length` and `Content-Transfer-Encoding` from
`allowed_part_headers` for the strict SPEC list.

In monitor (or off) mode PHParmor spools the body, inspects it, and forwards
the client's original bytes unchanged.

*Expected breakage:*
- Clients that send base64 or quoted-printable parts.
- `filename*` without a plain `filename`.
- Names or filenames containing `"` or `\`. Browsers percent-encode `"`. A
  backslash in a filename is rare outside Windows paths.
- Forms over the part or field limits (raise them per route).
- Upload progress bars that rely on streaming to the backend, because
  PHParmor buffers the whole body first.

### PA-UPROG: session upload-progress field (default: enforce)

Rejects (403) a multipart field named `php.upload_progress_field` (default
`PHP_SESSION_UPLOAD_PROGRESS`). It matches the exact name, or the name PHP
would register, such as `PHP.SESSION.UPLOAD.PROGRESS`. This field is an
ingredient of the PHP2Shell upload-progress attack paths. PA-UPROG has its
own mode, so it still applies when PA-MPART is in monitor or off.

If a body that is not being canonicalised cannot be parsed, PHParmor fails
closed: it rejects the request if the field name appears anywhere in the
body. PA-URLENC adds the same check for urlencoded bodies in M4.

*Expected breakage:* apps that use PHP's session upload-progress UI. Also
set `session.upload_progress.enabled=0`.

### PA-ROUTE-MPART: multipart per route (default: monitor)

When enforced, a multipart request on a route marked `multipart: deny` gets
403. Most routes never accept uploads, so allowlisting the few that do
removes the multipart attack surface from everything else. Run it in monitor
mode first to find the routes that legitimately receive multipart.

## Running

```bash
make build
./bin/phparmor -config deploy/config.example.yaml
```

### Container

Images for linux/amd64 and linux/arm64 are published to GitHub Packages by
the [build workflow](.github/workflows/build.yml):

- Pushes to `main` produce the `main` tag.
- `v*` git tags produce semver tags.
- Every build produces a `sha-<commit>` tag.

Images are distroless, run as non-root (UID 65532), and ship with an SBOM and
provenance attestation. They are signed with cosign (keyless).

```bash
docker run --rm -p 8080:8080 -p 127.0.0.1:9090:9090 -e PHPARMOR_UPSTREAMS=http://nginx:80 -e PHPARMOR_TRUSTED_PROXIES=10.0.0.0/16 ghcr.io/smck83/phparmor:main
```

The image's built-in `/etc/phparmor/config.yaml` uses the defaults only. Set
`PHPARMOR_UPSTREAMS` (required) and any other overrides with env vars, or
mount your own config over that path for per-host routes. The spool directory
is `/var/lib/phparmor/spool`. Give it a volume if you want spooled bodies off
the container's writable layer (spooling to disk arrives in M3). Port 9090 is
the admin port: keep it off public networks. `make image` builds a local
image.

Verify a published image's signature:

```bash
cosign verify ghcr.io/smck83/phparmor:main --certificate-identity-regexp '^https://github.com/smck83/PHParmor/' --certificate-oidc-issuer https://token.actions.githubusercontent.com
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
| `make fuzz` | 60 s fuzz smoke per target (`FUZZTIME=` to change) |
| `make harness` | PHP equivalence harness (from M6) |
| `make bench` | Benchmarks (from M6) |
| `make image` | Local distroless container image |

### Test corpora

`make test` replays both corpora through the proxy:

- **`test/corpus/benign/`:** real requests captured byte for byte from these
  clients, all with synthetic content:
  - Chromium (fetch with `FormData`)
  - curl
  - Go `net/http`
  - Python requests
  - Node axios
  - PHP Guzzle
  - Java Apache HttpClient 4 and 5
  - .NET `HttpClient`

  Each request must be accepted, and the upstream must receive the same parts
  as PHP would read from the original. Add clients with the capture tool in
  `test/corpus/capture`, using the scripts in `test/corpus/clients`.
  **Firefox and Safari captures are still wanted.**
- **`test/corpus/negative/`:** structural cases only, with the expected
  status in `manifest.json`. Regenerate with
  `go test ./internal/server -run TestNegativeCorpus -update-corpus`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
