# CLAUDE.md: PHParmor

Read `SPEC.md` first. It is the source of truth; if code and spec disagree, raise it rather than silently diverging.

## What this project is

A Go reverse proxy placed between a load balancer and nginx/Apache to harden HTTP input for legacy PHP apps exposed to PHP2Shell (CVE-2026-109618, CVE-2026-109619). It is a public, Apache-2.0 security tool and a stopgap, never described as a fix.

## Build order

Work milestone by milestone (SPEC section 15). Finish each with passing tests before starting the next. Propose a short plan before writing code for each milestone.

## Hard rules

- **No exploit code, payload generators or PoCs** anywhere in the repo, tests, issues or docs. Negative test cases are structural only (SPEC 12.5).
- **Stdlib first.** Allowed third-party modules: `gopkg.in/yaml.v3` (or `sigs.k8s.io/yaml`), `github.com/prometheus/client_golang`, `github.com/redis/go-redis/v9`. Ask before adding anything else.
- Use `httputil.ReverseProxy` with `Rewrite`, never `Director`.
- Multipart: stream with `NextRawPart`; never `ReadForm` or `ParseMultipartForm` on the hot path.
- Never forward `Transfer-Encoding` upstream; always send an exact `Content-Length`.
- Reject ambiguous input; never "repair" it.
- Fail closed on resource exhaustion unless config says `on_overload: bypass`.
- Never log cookie values, header values (beyond name and length) or body content.
- Every control has a stable ID (`PA-...`), a mode (`enforce`/`monitor`/`off`) and a decision record.

## Code conventions

- Go: current stable, minimum 1.22. `gofmt`, `go vet`, `staticcheck` clean.
- Packages as in SPEC 3.1; keep `internal/`.
- Errors wrap with `%w`; no panics outside `main`.
- Context-aware I/O with timeouts on every network call.
- Table-driven tests; one test per reject rule; fuzz targets for every parser.

## Commands (create these in M1)

- `make test`: unit tests
- `make fuzz`: 60 s fuzz smoke per target
- `make lint`: vet, staticcheck, gosec, govulncheck
- `make harness`: PHP equivalence harness (docker compose)
- `make bench`: k6/vegeta benchmarks
- `make image`: distroless container build

## Definition of done for a control

1. Implemented with enforce/monitor/off modes.
2. Unit tests for pass, every reject case and monitor mode.
3. Metric and log decision emitted.
4. Documented in README with default, rationale and expected breakage.
5. Benign corpus still passes the PHP equivalence harness.
