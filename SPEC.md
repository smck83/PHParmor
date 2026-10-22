# PHParmor: design specification

Status: draft v0.1 (2026-10-22)
Licence: Apache-2.0
Language: Go (current stable release; minimum 1.22)

## 1. Purpose

PHParmor is a reverse proxy that sits between a load balancer and a legacy PHP web stack (nginx or Apache in front of PHP) and hardens the HTTP input that PHP parses before any application code runs.

It exists because of PHP2Shell (CVE-2026-109618 and CVE-2026-109619, disclosed 2026-10-21). Both bugs are in the PHP runtime, are reachable by unauthenticated requests, and affect every PHP version back to 5.4. Upstream PHP only ships fixed releases for 8.2 to 8.5 (plus source-only backport branches for 7.4, 8.0 and 8.1). Many production apps run PHP 8.1 or older and cannot be upgraded quickly.

**PHParmor is a stopgap, not a fix.** The only complete remediation is a patched PHP runtime. The README, startup log line and `/version` endpoint must all say so.

### 1.1 Goals

1. Cut the known PHP2Shell attack paths at the HTTP layer without any change to the PHP application.
2. Enforce the input-parsing limits legacy PHP lacks or sets too loosely (multipart part counts, input variable counts, nesting depth, cookie volume).
3. Detect and suppress the known PHP2Shell memory-disclosure channel in responses.
4. Run horizontally at load-balancer scale with low added latency, as a stateless container.
5. Be safe to deploy on day one: a default configuration that blocks only near-zero-false-positive patterns.

### 1.2 Non-goals

- Not a general WAF. No SQLi/XSS signature matching; use a WAF for that.
- No TLS termination in v1 (the load balancer terminates TLS). Optional TLS listener is a later milestone.
- No FastCGI. Upstream is always HTTP to nginx/Apache.
- Does not inspect or fix PHP worker memory, OPcache or process lifecycle. Those mitigations are documented, not implemented (see section 11).

## 2. Threat model

### 2.1 What PHP2Shell needs

Public write-ups (Wiz, Calif, PHP advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp) describe four primitives:

| Primitive | CVE | Trigger | Needs |
|---|---|---|---|
| Upload-progress unserializer use-after-free | 109618 | Multipart request with the session upload-progress field; OOM during RFC 1867 parsing | A later request on the same worker |
| Remote memory disclosure | 109618 | Multipart + upload-progress + OOM leaves a stale session ID pointer | A later multipart request on the same worker; leaked heap returned in a `PHPSESSID` response cookie |
| Fatal-error backtrace use-after-free | 109619 | Any fatal OOM, then an early diagnostic in the next request | The same worker |
| OPcache type confusion | 109619 | Allocation failure during OPcache script persistence | Another worker reusing a shared-memory slot |

Common ingredients: memory pressure during request start-up (large or amplified bodies), the multipart parser, the session upload-progress feature, and state surviving into a later request.

### 2.2 What the proxy can and cannot do

| Ingredient | Proxy control |
|---|---|
| Multipart parsed by PHP | Re-serialise every multipart body into a canonical, bounded form (section 6) |
| Upload-progress field | Reject requests carrying it |
| Memory pressure from body size, part count, part-header amplification, input var count, nesting, cookies | Hard caps; canonicalisation strips per-part header bloat |
| Chunked or lengthless bodies | Always buffer and forward with `Content-Length` |
| Memory disclosure via `PHPSESSID` | Validate session cookies in responses and drop malformed ones |
| Repeated attempts | Strike counting on 5xx after body requests; rate limits |
| Worker reuse, OPcache | Out of scope; documented host mitigations |

### 2.3 Attacks on the proxy itself

- **Parser differentials** between Go and PHP. Mitigated by canonicalisation: PHP only ever sees the structure Go parsed, written in a narrow format both agree on. Reject anything ambiguous rather than repairing it.
- **Resource exhaustion of the proxy.** Global in-flight buffer budget, disk spool quota, per-request caps, read timeouts, concurrency limit. Fail closed.
- **Request smuggling between proxy and upstream.** Strict framing checks; the proxy always re-frames requests to the upstream.
- **Client IP spoofing.** Trusted-proxy CIDR list for `X-Forwarded-For`.

## 3. Architecture

```
Client -> ALB (TLS, AWS WAF) -> phparmor (N replicas) -> nginx/Apache -> PHP-FPM / mod_php
                                     |
                                     +-- optional Redis (fleet-wide strikes and rate limits)
```

- Data listener: `:8080` HTTP/1.1 (h2c optional, off by default).
- Admin listener: `:9090` with `/healthz`, `/readyz`, `/metrics`, `/version`. Never exposed publicly.
- Stateless replicas. Local in-memory state by default; optional Redis backend.
- Upstream: a pool of HTTP keep-alive connections to one or more upstream URLs (round robin), or a single URL behind an internal load balancer.

### 3.1 Package layout

```
cmd/phparmor/            main, flags, //go:debug directives, signal handling
internal/config/           YAML + env overrides, validation, SIGHUP hot reload
internal/server/           listeners, timeouts, concurrency limiter, admin endpoints
internal/policy/           host/route matching, control registry, modes, decisions
internal/inspect/framing/  CL/TE and header syntax checks
internal/inspect/headers/  header count/size, cookie checks and stripping
internal/inspect/query/    query string var count, nesting, key length
internal/inspect/urlenc/   application/x-www-form-urlencoded validator (order preserving)
internal/inspect/multipart/ streaming parser + canonical writer
internal/spool/            memory/disk buffering under a global byte budget
internal/proxy/            httputil.ReverseProxy (Rewrite, ModifyResponse, ErrorHandler)
internal/response/         session-cookie validation, strike recording
internal/state/            Limiter/StrikeStore interfaces; memory and redis impls
internal/telemetry/        slog JSON logging, Prometheus metrics, request IDs
test/php/                  PHP equivalence harness (docker compose)
test/corpus/               benign real-client captures + negative structural cases
deploy/                    docker-compose, ECS, Kubernetes, systemd examples
```

## 4. Request pipeline

Order matters: cheap checks first, body work last.

1. **Connection limits**: `MaxHeaderBytes`, `ReadHeaderTimeout`, minimum body read rate, global concurrency cap.
2. **Framing** (section 5.1).
3. **Host policy**: match `Host` against configured hosts. Unknown host: `421` (configurable).
4. **Route policy**: first match on method + path prefix or regex within the host.
5. **Headers and cookies** (section 5.2).
6. **Query string** (section 5.3).
7. **Body by content type**:
   - `multipart/form-data`: canonicalise (section 6).
   - `application/x-www-form-urlencoded`: validate (section 5.4), forward original bytes.
   - Anything else (JSON, XML, binary): size cap only.
   - In all cases the body is buffered via `internal/spool` and forwarded with `Content-Length`; `Transfer-Encoding` is never sent upstream.
8. **Client state**: blocked-client check, rate limits.
9. **Forward** via ReverseProxy using `Rewrite` (not `Director`). Append `X-Forwarded-For`, set `X-Forwarded-Proto` from the trusted value, propagate or create `X-Request-ID`.
10. **Response rules** in `ModifyResponse` (section 7).

Every control produces a decision record: control ID, mode, outcome (`pass`, `would_block`, `block`, `modify`), reason, request ID. Logged once per request as a single JSON line.

### 4.1 Block responses

| Cause | Status |
|---|---|
| Malformed framing or multipart | 400 |
| Policy violation (upload-progress field, disallowed multipart, blocked client) | 403 |
| Body or part over cap | 413 |
| Too many headers/cookies | 431 |
| Overload (buffer budget or concurrency exhausted) | 503 with `Retry-After` |

Body: short plain text with the request ID only. No control names or limits in client responses (they go to logs).

## 5. Controls: framing, headers, query, urlencoded

Each control has an ID, a mode (`enforce`, `monitor`, `off`) and parameters. IDs are stable across releases.

### 5.1 PA-FRAME: request framing (default: enforce)

Reject with 400:
- Both `Content-Length` and `Transfer-Encoding` present.
- `Transfer-Encoding` with any coding other than a single `chunked`.
- Multiple or non-numeric `Content-Length`.
- Obsolete line folding, header names with invalid token characters, NUL/CR/LF in header values.
- Bodies on `GET`/`HEAD`/`OPTIONS`/`DELETE` above 0 bytes (configurable).

Go's `net/http` server already rejects some of these; keep explicit checks and tests so behaviour does not depend on Go version.

### 5.2 PA-HDR: headers and cookies (default: enforce)

- Max header count (default 100), max single header value (default 8 KiB).
- Max cookie count (default 50), max total `Cookie` bytes (default 8 KiB), max single cookie (default 4 KiB).
- **PA-COOKIE-STRIP** (default: off): remove named cookies before forwarding, e.g. `PHPSESSID` for apps that do not use native PHP sessions. Off by default because many legacy apps do use native sessions. Document strongly: for apps that do not, this removes the upload-progress session path entirely.

### 5.3 PA-QUERY: query string (default: enforce)

PHP parses the query string into `$_GET` at start-up.
- Max variables (default 1000, PHP's `max_input_vars` default).
- Max bracket nesting depth in keys (default 8; PHP allows 64).
- Max key length (default 256 bytes), max total query length (default 8 KiB).
- Validation only; original query forwarded unchanged.

### 5.4 PA-URLENC: urlencoded bodies (default: enforce)

Order-preserving parse (do not use `url.ParseQuery`, which loses ordering and treats `;` differently from PHP). PHP's default `arg_separator.input` is `&`.
- Same var, nesting and key limits as PA-QUERY, counted together with the query string (PHP's `max_input_vars` applies to each superglobal separately; we use a combined cap for simplicity and document it).
- Max body (route cap).
- Reject invalid percent-encoding.
- Reject if any key equals the configured upload-progress field name (it is harmless outside multipart, but its presence signals probing; mode follows PA-UPROG).
- Forward original bytes.

## 6. Multipart canonicalisation (PA-MPART, default: enforce)

The core control. Goal: PHP receives a multipart body that is structurally simple, bounded, and exactly what PHParmor parsed.

### 6.1 Parsing

- Require `Content-Type: multipart/form-data` with exactly one `boundary` parameter, 1 to 70 characters from the RFC 2046 boundary alphabet. Reject duplicates, empty, or quoted-with-escapes boundaries.
- Use `mime/multipart.Reader.NextRawPart` (no quoted-printable decoding), streaming. Do not use `ReadForm` (it buffers under its own rules and only enforces the part limit there).
- Set `//go:debug multipartmaxheaders=16` in `cmd/phparmor` so the stdlib caps headers per part at parse time (if the directive is not accepted by the Go toolchain in use, set `GODEBUG=multipartmaxheaders=16` in the container image instead); also enforce our own limits below.
- Discard preamble and epilogue.
- Reject (400) on any parse error, missing final boundary, or trailing garbage the reader reports.

### 6.2 Per-part rules

| Rule | Default |
|---|---|
| Allowed part headers | `Content-Disposition`, `Content-Type` only; any other header -> reject (configurable allowlist) |
| `Content-Transfer-Encoding` present | reject |
| Disposition type | must be `form-data` |
| `name` parameter | required, non-empty, max 256 bytes |
| `filename` parameter | optional, max 255 bytes; `filename*` (RFC 5987) -> reject |
| Characters in `name`/`filename` | printable; reject `"`, `\`, CR, LF, NUL, and other C0 controls |
| Duplicate parameters in one header | reject |
| Bracket nesting depth in `name` | max 8 |
| Part `Content-Type` | max 128 bytes, must parse as a media type |
| Field (non-file) value size | max 1 MiB |
| File size | route cap |
| Field name equals upload-progress name | reject (PA-UPROG) |

### 6.3 Per-request limits

| Limit | Default | Rationale |
|---|---|---|
| Total parts | 256 | PHP added `max_multipart_body_parts` only in 8.0.28 / 8.1.16 / 8.2.3 (CVE-2023-0662); older PHP has no cap |
| File parts | 20 | PHP `max_file_uploads` default |
| Field parts + query vars | 1000 | PHP `max_input_vars` default |
| Total body | route cap (default 32 MiB) | Matches PHP advisory guidance for `post_max_size` with uploads |

### 6.4 Canonical output

- New random boundary per request (32 hex chars), prefixed `phparmor-`.
- CRLF line endings only.
- For each part, in original order:
  ```
  --<boundary>\r\n
  Content-Disposition: form-data; name="<name>"[; filename="<filename>"]\r\n
  [Content-Type: <type>\r\n]
  \r\n
  <bytes>\r\n
  ```
- Final `--<boundary>--\r\n`. No preamble, no epilogue.
- Request `Content-Type` rewritten to `multipart/form-data; boundary=<new>`; `Content-Length` set to the exact output size.
- Because names and filenames are validated to exclude `"` and `\`, no escaping is ever needed, which removes a whole class of PHP/Go quoting differentials.

### 6.5 Buffering

- `internal/spool` writes part data to memory up to a per-request threshold (default 1 MiB), then to a temp file in a dedicated spool directory.
- Global in-memory budget across all requests (default 256 MiB) and spool directory quota (default 2 GiB). When exhausted: 503 (fail closed). An `on_overload: bypass` option exists for operators who prefer availability, documented as removing protection.
- Temp files are created with `0600`, unlinked after the upstream response completes or on any error.

## 7. Response controls

### 7.1 PA-SESSCOOKIE: session cookie validation (default: enforce)

The PHP2Shell memory disclosure returns leaked heap, URL-encoded, as the value of a `PHPSESSID` `Set-Cookie`.

- For each `Set-Cookie` whose name is in `session_cookie_names` (default `["PHPSESSID"]`): the value must match `^[A-Za-z0-9,-]{20,128}$` (PHP session IDs use only these characters for every `session.sid_bits_per_character` setting).
- On failure: remove that `Set-Cookie`, record decision `modify`, increment `phparmor_session_cookie_dropped_total`, log at `WARN` with the cookie length (never the value), and record a strike for the client.
- Safe for apps that use native sessions: valid IDs pass untouched. Apps that set custom session IDs via `session_id()` with other characters must widen the pattern in config.

### 7.2 PA-STRIKE: client strikes (default: monitor)

- A strike is recorded when a request with a body (multipart or urlencoded) receives a 5xx from the upstream, or when PA-SESSCOOKIE fires.
- `threshold` strikes (default 5) within `window` (default 60 s) blocks the client for `block_for` (default 15 min).
- Client key: resolved client IP (section 8.2). Optional: IP + `User-Agent` hash.
- Default monitor because NAT and corporate egress can aggregate users.

### 7.3 PA-RATE: rate limits (default: off)

Token bucket per client per route: `rps`, `burst`. Off until configured, because sensible values are app specific. Fleet-wide accuracy needs the Redis backend; otherwise limits are per replica.

### 7.4 Header hygiene (default: off)

Optional removal of `X-Powered-By` and version details in `Server`.

## 8. Configuration

YAML file (`/etc/phparmor/config.yaml`), every scalar overridable by env var (`PHPARMOR_` prefix, `__` for nesting). Validated at start-up and on SIGHUP; an invalid reload is rejected and the old config kept.

### 8.1 Example

```yaml
listen: ":8080"
admin_listen: ":9090"

upstreams:
  - "http://nginx.internal:80"

trusted_proxies:            # ALB subnets
  - "10.0.0.0/16"

server:
  read_header_timeout: 10s
  body_min_rate_bytes_per_sec: 4096
  idle_timeout: 75s          # must exceed the ALB idle timeout (60 s default)
  max_concurrent_requests: 2000
  max_header_bytes: 32768

buffers:
  memory_per_request: 1MiB
  memory_global: 256MiB
  spool_dir: /var/lib/phparmor/spool
  spool_quota: 2GiB
  on_overload: reject        # reject | bypass

state:
  backend: memory            # memory | redis
  redis_url: ""

php:
  upload_progress_field: PHP_SESSION_UPLOAD_PROGRESS   # session.upload_progress.name
  session_cookie_names: [PHPSESSID]                    # session.name

controls:                    # global modes; hosts/routes may override
  PA-FRAME: enforce
  PA-HDR: enforce
  PA-COOKIE-STRIP: off
  PA-QUERY: enforce
  PA-URLENC: enforce
  PA-MPART: enforce
  PA-UPROG: enforce
  PA-SESSCOOKIE: enforce
  PA-STRIKE: monitor
  PA-RATE: off
  PA-ROUTE-MPART: monitor

limits:
  max_body: 32MiB
  max_parts: 256
  max_files: 20
  max_vars: 1000
  max_nesting: 8
  max_field_value: 1MiB

hosts:
  - names: ["app.example.com"]
    cookie_strip: [PHPSESSID]          # this app does not use native sessions
    controls: { PA-COOKIE-STRIP: enforce }
    routes:
      - match: { methods: [POST], path_prefix: "/reports/upload" }
        multipart: allow
        limits: { max_body: 50MiB, max_files: 5 }
      - match: { path_prefix: "/" }
        multipart: deny                # enforced only when PA-ROUTE-MPART is enforce
        limits: { max_body: 8MiB }
  - names: ["api.example.com"]
    routes:
      - match: { path_prefix: "/" }
        multipart: deny
        limits: { max_body: 16MiB }    # JSON payloads
```

### 8.2 Client IP resolution

Walk `X-Forwarded-For` from the right, skipping addresses inside `trusted_proxies`; the first untrusted address is the client. If the TCP peer is not trusted, ignore `X-Forwarded-For` and use the peer address.

## 9. Observability

- **Logs**: `log/slog` JSON. One access line per request: request ID, host, method, path (no query values), status, bytes in/out, upstream latency, total latency, client IP, decisions array. Never log cookie values, body content, or header values beyond names and lengths.
- **Metrics** (Prometheus, admin port):
  - `phparmor_requests_total{host,route,status}`
  - `phparmor_decisions_total{control,outcome}`
  - `phparmor_request_duration_seconds` and `phparmor_upstream_duration_seconds` (histograms)
  - `phparmor_buffer_bytes_inflight`, `phparmor_spool_bytes`
  - `phparmor_session_cookie_dropped_total`
  - `phparmor_blocked_clients`
- **Health**: `/healthz` (process up), `/readyz` (config loaded, upstream reachable within the last N seconds, spool writable).

## 10. Performance and scale targets

Targets to verify by benchmark, not promises:
- Added p99 latency under 2 ms for requests without bodies.
- Linear horizontal scaling; no shared state on the hot path when `state.backend: memory`.
- Memory bounded by `buffers.memory_global` plus a fixed overhead.
- Benchmarks with k6 or vegeta in CI for: small GET, 10 KiB urlencoded POST, 5 MiB multipart upload, 1 MiB JSON.

## 11. Host-side mitigations (documented, not implemented)

The README must list these alongside the proxy, because the proxy cannot reach worker state:
- Patched PHP runtime (8.5.12, 8.4.27, 8.3.36, 8.2.35, or a distro/vendor backport).
- `session.upload_progress.enabled=0` in php.ini or the FPM pool.
- `memory_limit=-1` via `php_admin_value`, bounded by a cgroup/container limit; never `RLIMIT_AS`/`RLIMIT_DATA`.
- `post_max_size` 8M (no uploads) or 32M.
- `fatal_error_backtraces=0` on PHP 8.5.
- `pm.max_requests=1` to stop stale state crossing requests (benchmark first).
- Lock the upstream so it only accepts traffic from PHParmor.

## 12. Testing

1. **Unit tests** for every control, including each reject case in sections 5 and 6.
2. **Fuzzing** (`go test -fuzz`): `FuzzCanonicalize` with invariants: never panics; memory bounded; if accepted, the canonical output re-parses in Go to the same ordered list of (name, filename, content-type, sha256(data)).
3. **PHP equivalence harness** (`test/php/`, docker compose): PHP 7.4, 8.1 and 8.4 containers behind nginx, each exposing `dump.php` that returns JSON of `$_GET`, `$_POST`, `$_COOKIE` and `$_FILES` (name, type, size, sha256, error). For every request in the benign corpus, the JSON via PHParmor must equal the JSON direct to PHP (ignoring `tmp_name`).
4. **Benign corpus** (`test/corpus/benign`): real captures from Chrome, Firefox, Safari, curl, Python requests, Guzzle, axios `FormData`, Java `HttpClient`, .NET `HttpClient`, including array fields (`a[]`, `a[b][c]`), empty files, unicode filenames, large files.
5. **Negative corpus** (`test/corpus/negative`): structural cases only: upload-progress field, 5000 parts, deep nesting, oversized part headers, `filename*`, `Content-Transfer-Encoding`, chunked multipart, CL+TE, missing final boundary, quotes and backslashes in names.
6. **No exploit code** in the repo. Validation against real exploit tooling happens in a private lab and is not committed.
7. **CI**: `go vet`, `staticcheck`, `govulncheck`, `gosec`, unit + fuzz smoke (60 s), equivalence harness, benchmarks on main.

## 13. Packaging and release

- Static binaries (linux/amd64, linux/arm64) and a distroless, non-root container image.
- SBOM (syft), signed images and binaries (cosign keyless), SLSA provenance via GitHub Actions.
- `SECURITY.md` with a private disclosure address; `THREAT_MODEL.md` summarising section 2.
- Deployment examples in `deploy/`: docker compose, ECS (task definition + service autoscaling on `ALBRequestCountPerTarget`), Kubernetes (Deployment + HPA + PodDisruptionBudget), systemd unit.
- Graceful shutdown on SIGTERM: stop accepting, drain in-flight requests up to `shutdown_timeout` (default 30 s; align with ECS `stopTimeout` / Kubernetes `terminationGracePeriodSeconds`).

## 14. Compatibility notes for operators

Expected breakage with the default config, to document in the README:
- Apps that use PHP's session upload-progress UI.
- Clients that send extra per-part headers, `Content-Transfer-Encoding`, or RFC 5987 `filename*`.
- Field names or filenames containing `"` or `\` (browsers percent-encode these, so rare).
- Forms with more than 256 parts or deeper than 8 bracket levels (raise the limits per route).
- Upload progress bars that rely on streaming to the backend: PHParmor buffers the full body first.

## 15. Milestones

| # | Deliverable | Done when |
|---|---|---|
| M1 | Skeleton: config, listeners, pass-through proxy, logs, metrics, health | Proxies traffic unchanged; config reload works |
| M2 | PA-FRAME, PA-HDR, PA-COOKIE-STRIP, PA-QUERY | Unit tests for every reject case |
| M3 | Spool + PA-MPART + PA-UPROG canonicaliser | Fuzz invariants hold; benign corpus round-trips in Go |
| M4 | PA-URLENC | Unit tests; combined var counting |
| M5 | PA-SESSCOOKIE, PA-STRIKE, PA-RATE, Redis backend | Response tests; Redis integration test |
| M6 | PHP equivalence harness + corpora + CI | Benign corpus identical via proxy on PHP 7.4, 8.1, 8.4 |
| M7 | Packaging, docs, deploy examples, signed release | v0.1.0 tagged with SBOM and signatures |

## 16. Open questions

1. Should PA-ROUTE-MPART ship with a helper that imports routes from Laravel `route:list --json` or Symfony `debug:router --format=json`?
2. Is a per-host `max_vars` split by superglobal (exactly mirroring PHP) worth the complexity over the combined cap?
3. Do we publish a hosted test endpoint so operators can check their deployment, or only a CLI checker (`phparmor check https://host`) that sends the benign negative corpus?

## 17. References

- PHP security release, 2026-10-21: https://www.php.net/archive/2026.php#2026-10-21-5
- PHP advisories: GHSA-w8hw-w9fx-j79w (CVE-2026-109618), GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- Wiz Research write-up: https://www.wiz.io/blog/php2shell-php-rce
- AWS WAF mitigations: https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/
- Cloudflare WAF protections: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
- Go mime/multipart limits (CVE-2023-24536): https://github.com/golang/go/issues/59153
- PHP multipart part-count limit (CVE-2023-0662): https://security.alpinelinux.org/vuln/CVE-2023-0662
