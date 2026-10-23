# Roadmap: application behaviour layer (post-v1 proposal)

Status: proposal, not scheduled (2026-10-23). Nothing here changes v1 scope or
the milestones in SPEC section 15. Where this document and `SPEC.md` disagree,
`SPEC.md` wins until this proposal is accepted and folded in.

## 1. Summary

PHParmor v1 is a protocol and input-parsing firewall for one vulnerability
class. This proposal adds two things on top, without making it a general WAF:

1. **Learn mode**: a passive observer that builds per-host, per-route profiles
   of request *shape* (methods, content kinds, sizes, variable and part counts,
   field names) and turns them into a **suggested config** that an operator
   reviews and applies. Learning never enforces anything by itself.
2. **More outcomes** for the existing decision model: divert a client to a
   quarantine upstream pool, and tarpit a blocked client. Both build on the
   M5 strike and rate-limit state.

The design rule throughout: the config file stays the only policy. Learning
proposes config; controls enforce config; the state backend holds only
short-lived client state (strikes, buckets, blocks).

## 2. The three-layer model, mapped to PHParmor

| Layer / outcome | Today (M1–M4) | M5 adds | This proposal adds |
|---|---|---|---|
| **1. Protocol and exploit firewall** (hard limits, malformed input) | PA-FRAME, PA-HDR, PA-COOKIE-STRIP, PA-QUERY, PA-MPART, PA-UPROG, PA-URLENC; global and per-route `limits`; spool budget with fail-closed 503 | PA-SESSCOOKIE (response side) | Nothing. Layer 1 is v1 and stays the core. |
| **2. Application behaviour** (routes, fields, sizes, sessions) | Static only: per-host `routes` with `multipart: allow/deny` (PA-ROUTE-MPART), per-route `limits`, written by hand | Per-client strike history (PA-STRIKE) | Learn mode (section 3): observes shape, emits suggested `hosts`/`routes` config. Optional per-route method and content-type allowlists (PA-ROUTE-METHOD, PA-ROUTE-CTYPE), generalising PA-ROUTE-MPART. |
| **3. Policy and decision engine** | `internal/policy`: host/route match, control registry, `enforce`/`monitor`/`off` per control, global/host/route overrides, one decision record per control in the access log line | `state` backend: `memory` or `redis` for strikes, rate buckets and blocked clients | New outcomes `divert` and `delay` (section 4). The "local policy database" is the YAML config plus the learn profile store; no separate mutable policy DB. |
| **Telemetry** | Access log line with `decisions[]`; `phparmor_decisions_total{control,outcome}`, `phparmor_requests_total{host,route,status}` | `phparmor_session_cookie_dropped_total`, `phparmor_blocked_clients` | Shape counts in the access log (section 3.2); `phparmor_learn_*` metrics; `phparmor_diverted_total`, `phparmor_tarpit_inflight`. |
| Outcome: **allow** | Decision `pass`; any control in `off` | | |
| Outcome: **log** | Control in `monitor`: decision `would_block`, request forwarded | | Learn mode is observe-only and produces no decisions at all. |
| Outcome: **rate-limit** | | PA-RATE: token bucket per client per route (`rps`, `burst`), per replica or fleet-wide with Redis | |
| Outcome: **block** | Decision `block` with 400/403/413/415/431/503 per SPEC 4.1 | PA-STRIKE blocks a client for `block_for` after `threshold` strikes in `window` | Tarpit before the block response (section 4.3). |
| Outcome: **challenge** | | | Not proposed (section 4.1). |
| Outcome: **divert / quarantine** | | | PA-DIVERT: struck clients go to a separate upstream pool (section 4.2). |

## 3. Learn mode

### 3.1 Scope and non-goals

Learn mode records **structure, never content**. It answers questions an
operator needs answered to tighten the v1 controls:

- Which routes receive multipart at all, and which of those carry files?
- What methods and content kinds does each route see?
- How large are bodies, and how many variables, parts and files per request?
- Which field names does a route accept (opt-in, see 3.4)?
- Does this host use native PHP sessions at all?

It does **not**:

- inspect, hash, classify or sample values (no SQLi/XSS signatures, no
  entropy or anomaly scoring on content);
- build per-user or per-session behaviour models;
- block, delay or divert anything, in any mode;
- write config. It writes a suggestion file; an operator applies it.

### 3.2 What is observed

An in-process observer runs after the layer 1 controls, reusing what the
parsers already compute, so it adds no extra body pass. Per request it emits
one *shape record*:

| Field | Source | Notes |
|---|---|---|
| host label, route label | `internal/policy` | Config labels only, as metrics do today |
| method | request | |
| path template | request path | Segments that look like IDs (all digits, UUID, 16+ hex, over 64 bytes) become `{id}`; depth capped at 6 |
| content kind | body dispatch | `none`, `urlenc`, `multipart`, `other` (plus the media type for `other`, lowercased, parameters dropped) |
| body bytes | spool | |
| vars (query + body), parts, files, max nesting | PA-QUERY, PA-URLENC, PA-MPART counters | |
| field names | PA-URLENC, PA-MPART | Opt-in only; PHP-registered base name with brackets collapsed (`a[0][x]` -> `a[][]`) |
| upstream status class | proxy | `2xx`, `3xx`, `4xx`, `5xx` |
| session cookie seen | request `Cookie`, response `Set-Cookie` | Names from `session_cookie_names` only, and the value **length** |
| client key | resolved client IP | Salted hash, used only for the distinct-client count (3.5), never stored raw |

The counts (content kind, vars, parts, files) are also worth adding to the
access log line in their own right: they are counts, which the logging rules
allow, and they make offline learning possible (3.6). Field names are not
added to the access log (3.4).

### 3.3 Profiles and storage

Shape records are folded into a **profile** keyed by
`(host label, route label, method, path template)`. Each profile holds only
additive aggregates, so replicas can be merged by summing:

- request count and first/last seen time;
- count per content kind and per upstream status class;
- fixed log2-bucket histograms for body bytes, vars, parts, files and nesting;
- a bounded distinct-client counter (salted hashes up to a cap, e.g. 64,
  then "64+"; the salt rotates per learning run);
- field-name set (opt-in), capped per profile (default 256) with an overflow
  flag;
- session cookie: request/response presence counts and a length histogram.

Memory is bounded by `learn.max_profiles` (default 10,000). Past the cap,
new path templates fold into the route's `_other` profile and
`phparmor_learn_dropped_total` increments. Learning never allocates without
a bound and never fails a request; if the observer is behind, it drops
records (counted), it does not block the hot path.

Backends:

| Store | Use | Behaviour |
|---|---|---|
| `memory` | Single replica, short runs | Lost on restart; read via the admin endpoint |
| `file` | Default for real runs | Snapshot to `learn.dir` every `flush_interval` (owner-only `0600`, write to temp then rename); one file per replica, merged by the CLI |
| `redis` | Fleets | Reuses the M5 `state.redis_url` connection; `HINCRBY` into one hash per profile with a TTL; the fleet sees one merged profile. Separate key prefix from strikes and rate buckets |

Proposed config (all off by default):

```yaml
learn:
  enabled: false
  store: file                 # memory | file | redis
  dir: /var/lib/phparmor/learn
  flush_interval: 60s
  max_profiles: 10000
  field_names: false          # opt-in, see 3.4
  max_fields_per_profile: 256
  trusted_clients: []         # optional CIDRs; if set, learn only from these
```

Learning is not a control: it has no ID, no mode and no decision record,
because it never affects a request. That keeps "every control has an ID and
a mode" true without stretching it.

### 3.4 Privacy

The logging rules (SPEC 9, CLAUDE.md) forbid cookie values, header values
beyond name and length, and body content. Learn mode follows them:

- Values of any kind are never read into the profile. Only counts, sizes,
  lengths, media types and (opt-in) field names.
- Client IPs are hashed with a per-run salt and kept only as a distinct
  count. The salt is not persisted with the profile.
- **Field names are body content in the strict sense.** Most are fixed
  identifiers (`email`, `items[]`), but some apps put data in names (for
  example `qty_<sku>` or an email address as a key). So field names are
  opt-in (`learn.field_names: true`), never written to the access log, kept
  only in the aggregated profile, capped per profile, and dropped when longer
  than `max_key_length`. Before shipping this, SPEC section 9 needs an
  explicit carve-out for aggregated field names in the profile store; see
  open question 1.
- Profiles reveal application structure. The profile file is `0600`; the
  admin endpoint stays on the private admin listener.

### 3.5 Poisoning

Attackers will send traffic during a learning window. The design keeps the
worst case bounded:

- **Layer 1 stays on.** Learning runs alongside the enforced v1 controls. A
  request that is blocked is not learned from, so nothing malformed shapes
  the profile.
- **Learn only from healthy outcomes.** Only requests whose upstream status
  is 2xx or 3xx, from clients with no strikes, are folded in.
- **Suggestions can only tighten.** A suggested limit is never above the
  current effective limit for that route. The worst a poisoned profile can do
  is leave a route at today's configured limits, or suggest `multipart: allow`
  where the operator would have denied it. Anything observed above a limit is
  listed under "review" in the suggestion, not raised.
- **Evidence thresholds.** A route is proposed for `multipart: allow` (or
  any widening of a per-route allowlist) only after `--min-requests`
  (default 100) from `--min-clients` distinct clients (default 5). Below that,
  it is listed as "insufficient evidence".
- **Percentiles, not maxima.** Size and count limits use a high percentile
  (default p99.9) times a headroom factor (default 2), rounded up to a
  bucket boundary, so a few large attacker requests do not set the cap.
- **Trusted sources.** `learn.trusted_clients` restricts learning to known
  CIDRs, for example a staging environment fed by QA or recorded traffic.
  This is the recommended mode when it is available.

### 3.6 Turning profiles into config

A CLI subcommand, so suggestions are files that go through review and version
control like any other config change:

```
phparmor learn status   -admin http://127.0.0.1:9090
phparmor learn export   -admin http://127.0.0.1:9090 -o profile.json
phparmor learn export   -dir /var/lib/phparmor/learn -o profile.json   # merge replica files
phparmor learn import   -access-log access.jsonl -o profile.json        # offline, counts only
phparmor learn suggest  -profile profile.json -config config.yaml -o suggested.yaml \
                        [-min-requests 100] [-min-clients 5] [-percentile 99.9] [-headroom 2]
phparmor learn reset    -admin http://127.0.0.1:9090
```

Admin endpoints (admin listener only): `GET /learn/profile` (JSON),
`GET /learn/status`, `POST /learn/reset`.

`learn suggest` emits a full `hosts:` block plus a diff against the current
config. Every suggested value carries its evidence as a comment:

```yaml
hosts:
  - names: ["app.example.com"]
    cookie_strip: [PHPSESSID]   # 0 of 412,000 responses set PHPSESSID; 0 requests sent it
    controls: { PA-COOKIE-STRIP: enforce, PA-ROUTE-MPART: enforce }
    routes:
      - match: { methods: [POST], path_prefix: "/reports/upload" }
        multipart: allow        # 1,204 multipart requests from 37 clients over 6 d
        limits: { max_body: 8MiB, max_files: 2, max_vars: 32 }  # p99.9 body 3.1 MiB; max files 1
      - match: { path_prefix: "/" }
        multipart: deny         # no multipart seen on any other path
        limits: { max_body: 1MiB, max_vars: 128 }
# review: /admin/import saw 3 multipart requests from 1 client (below thresholds)
```

What it can suggest:

- `multipart: allow` only on paths that received multipart; `deny` elsewhere,
  and PA-ROUTE-MPART to `enforce` once every multipart path is covered.
- Tightened per-route `max_body`, `max_vars`, `max_parts`, `max_files`,
  `max_nesting`.
- `cookie_strip: [PHPSESSID]` with PA-COOKIE-STRIP `enforce` when the host
  never set or received a session cookie during the run. This removes the
  upload-progress path entirely and is the highest-value single suggestion.
- A tighter PA-SESSCOOKIE length range when every observed session ID has
  the same length (for example `{26}` or `{32}`).
- With PA-ROUTE-METHOD / PA-ROUTE-CTYPE (M10), per-route method and
  content-type allowlists.

The output must pass `phparmor -check`. Applying it is the operator's job:
edit, commit, deploy, SIGHUP. The recommended rollout is to apply the
suggestion with the affected controls in `monitor`, watch
`phparmor_decisions_total{outcome="would_block"}`, then move to `enforce`.

## 4. Outcomes

### 4.1 Challenge: not proposed

An interactive challenge (JavaScript proof of work, CAPTCHA, interstitial)
only works for browsers on HTML pages. PHParmor fronts APIs, mobile apps,
webhooks, server-to-server clients and crawlers as well; a challenge breaks
all of them, and the proxy cannot reliably tell which clients are which. It
would also add new attack surface (response generation, a signed clearance
cookie and its key management) to a tool whose value is being small and
predictable. PHP2Shell tooling is scripted, so a challenge mostly costs
attackers a headless browser, while strikes, rate limits, divert and block
already raise their cost without breaking anyone.

**Trade-off, if it is ever wanted:** it could be scoped to routes an operator
marks `html: true`, applied only to clients that already have strikes, with
a static no-JS fallback. That is effectively a bot-management feature, which
the load balancer's WAF (AWS WAF, Cloudflare) already does better. The
recommendation is to leave challenges to that tier.

### 4.2 Divert: PA-DIVERT (quarantine pool)

Every PHP2Shell primitive needs state to survive into a **later request on
the same worker** (SPEC 2.1). `pm.max_requests=1` breaks that, but it is
expensive to run for all traffic. Divert applies it only to suspect clients.

- New config: named upstream pools. `upstreams` stays as the `default` pool.

  ```yaml
  upstream_pools:
    quarantine: ["http://nginx-quarantine.internal:80"]
  controls:
    PA-DIVERT: monitor
  divert:
    pool: quarantine
    min_strikes: 1            # below the PA-STRIKE block threshold
    for: 30m
  ```

- A client with at least `min_strikes` strikes (M5 strike store, so
  fleet-wide with Redis) but below the block threshold is routed to the
  quarantine pool for `for`. Above the threshold, PA-STRIKE blocks as today.
- The quarantine pool is a separate PHP-FPM **master** (not just a pool in
  the same master, because OPcache shared memory is per master) with
  `pm.max_requests=1`, a lower `memory_limit` within a cgroup cap, and
  `session.upload_progress.enabled=0`. It shares the session save path with
  the main pool so legitimate users caught by NAT keep working, only slower.
- Decision outcome: a new `divert` outcome. In monitor mode the decision is
  `would_block` with reason `divert`, so existing dashboards keep working.
- If the quarantine pool is unhealthy: fail closed (block) by default, or
  fall back to the default pool with `divert.on_unavailable: default`,
  documented as removing the protection.
- All layer 1 controls still apply to diverted requests.

Trade-off: an extra upstream to run, and diverted users see higher latency.
It does nothing for a client's first attempt; it limits what repeated
attempts can reach.

### 4.3 Tarpit

Before sending a block response to a client already blocked by PA-STRIKE (or
over PA-RATE), hold the connection for `tarpit.delay` (default 5 s, kept
below the load balancer idle timeout). This slows scripted retries.

- Bounded by `tarpit.max_inflight` (default 500). Over the cap, block
  immediately: the tarpit must never become a way to exhaust the proxy.
- Holds only a goroutine and a timer, never a body buffer; the request body
  is not read.
- Decision outcome `delay`, then `block`. Mode via a `PA-TARPIT` control,
  default `off`.
- Cheap for a small number of clients, and a self-inflicted DoS risk if
  misconfigured, hence the hard cap and the default of off.

## 5. Milestones (post-v1)

| # | Deliverable | Done when |
|---|---|---|
| M8 | Shape counts in the access log; in-process observer; `memory` and `file` profile stores; `/learn/*` admin endpoints; `learn.*` config | Replaying the benign corpus produces a profile equal to a checked-in golden file; memory stays under `max_profiles` under a fuzzed path generator; no values in any profile (tested against the corpus) |
| M9 | `phparmor learn export/import/suggest/reset`; evidence comments; tighten-only invariant | Suggested config passes `-check`; property test: a suggestion never raises any limit above the input config; poisoning tests (few clients, oversized requests) produce "review" entries, not widened config |
| M10 | PA-ROUTE-METHOD and PA-ROUTE-CTYPE (per-route allowlists, default monitor), suggested by `learn` | Definition of done for a control (CLAUDE.md); benign corpus still passes the equivalence harness |
| M11 | `redis` profile store, fleet-wide merge | Redis integration test: two replicas produce the same merged profile as one replica seeing all traffic |
| M12 | `upstream_pools`, PA-DIVERT | Diverted clients reach only the quarantine pool; fail-closed when it is down; deploy example with a separate FPM master and `pm.max_requests=1` |
| M13 | PA-TARPIT | `max_inflight` cap holds under load test; blocked clients get the block status after the delay; no body is read |

M8 and M9 are useful on their own and should ship first. M12 depends on M5
strikes being in production and stable.

## 6. Risks

- **Scope creep toward a WAF.** Mitigation: section 3.1 is the contract; any
  feature that reads values is out of scope by definition.
- **Operators applying suggestions blindly.** A suggestion is a hypothesis
  from one window; seasonal routes (year-end reports, annual imports) may
  not appear. Mitigation: evidence comments, monitor-first rollout, the
  "insufficient evidence" list, and README guidance on window length.
- **Privacy of field names.** Mitigated by opt-in and aggregation, but still
  a change to the logging rules (open question 1).
- **Hot-path cost.** The observer must reuse parser counters and drop records
  when behind. Covered by the M8 benchmark against SPEC 10 targets.
- **Divert masking problems.** A busy quarantine pool can hide real
  incidents behind latency. Mitigation: `phparmor_diverted_total` per host
  and an alert recipe in the docs.
- **NAT and shared egress.** Strikes, divert and tarpit inherit PA-STRIKE's
  false-positive risk; divert is the softest of these and the recommended
  first step above monitor.

## 7. Open questions

1. Is aggregated, opt-in field-name collection acceptable under the logging
   rules, or should learn mode stop at counts? (Counts alone still support
   every suggestion except a future per-route field allowlist.)
2. Should a per-route field-name allowlist ever become a control
   (PA-ROUTE-FIELDS), or is that too close to application logic for a
   stopgap?
3. Should `divert` and `delay` be new decision outcomes, or reasons on the
   existing ones? New outcomes are clearer; reusing keeps the metric label
   set fixed.
4. Should the admin listener gain authentication before it serves profiles,
   since they reveal application structure?
5. Can `learn import` usefully read nginx/Apache access logs (method, path,
   status, bytes) for apps where PHParmor is not yet deployed, to produce a
   first route list before day one?
6. Does the Laravel/Symfony route import (SPEC 16, question 1) belong in
   `learn suggest` as a second evidence source?
