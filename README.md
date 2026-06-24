# nginx-http-sentinel-module

`ngx_http_sentinel_module` — a single access-phase **client-reputation + tarpit**
engine for nginx / angie. Fuses three defenses that all share one shape
("score the client, then act"):

1. **CrowdSec reputation** — consume crowd-sourced + local-WAF ban decisions
   (out of band; never blocks the request path).
2. **AI-scraper / bad-bot tarpit** — when the score is bad, serve a cheap,
   bounded garbage drip instead of a clean 403, starving LLM scrapers and
   hostile crawlers.
3. **JA4+ fingerprinting** — JA4H (HTTP header order, in-module, Phase 1) feeds
   the score and survives TLS randomization that defeats JA3/IP alone. JA4 (TLS
   ClientHello) is **deferred to Phase 4** — it needs a core nginx patch
   (ClientHello SSL callback), so it can't live in a pure HTTP module; JA4H
   covers most TLS-randomized bots until then.

**Self-contained: one module, no runtime sibling deps.** Sentinel *absorbs* the
signal logic it needs (error-rate/scanner-path counter, UA/bot heuristics,
JA4H) into its own source rather than reading sibling runtime vars. Phase 1–3
ship with **zero core nginx patch**. The standalone `nginx-error-abuse-module`
is **deprecated later** once sentinel's native error-rate signal covers it.

> **Status: planning / Phase 0.** No module code yet. The full phased build plan
> is in [TODO.md](TODO.md); the locked design decisions and safety rules are in
> [DESIGN.md](DESIGN.md). Read those before writing code.

## Directives

### Core (location context)

| Directive | Default | Description |
|---|---|---|
| `sentinel on\|off;` | `off` | Enable the module for this location. |
| `sentinel_mode enforce\|shadow;` | `enforce` | `shadow` scores and sets variables but never blocks. |
| `sentinel_fail open\|closed;` | `open` | On zone/lookup error: `open` allows, `closed` blocks. |
| `sentinel_zone name:size;` | — | Shared-memory zone (http context). |
| `sentinel_threshold challenge=N tarpit=M block=K;` | `30/60/80` | Score thresholds for each verdict (see Scoring below). |

### Score weights (location context)

These tune how much each signal contributes to the final score. All accept a
non-negative integer.

| Directive | Default | Signal it weights |
|---|---|---|
| `sentinel_weight_errrate N;` | `1` | Multiplied by the number of errors recorded in the burst window for this identity. A client with 20 errors in the window contributes `20 × N` to the score. |
| `sentinel_weight_blocked N;` | `100` | Added once (flat) when the identity is already in a blocked state in the shared-memory zone. |
| `sentinel_weight_scanner N;` | `50` | Added once when the request URI matches a known scanner path prefix. |
| `sentinel_weight_bot N;` | `30` | Added once when the User-Agent header matches a heuristic bot-UA pattern. |
| `sentinel_weight_header N;` | `25` | Added once when a request-header anomaly is detected (HTTP/1.1 without Host, Content-Length + Transfer-Encoding both present, duplicate Host, or neither Accept nor User-Agent). |
| `sentinel_weight_honeypot N;` | `90` | Added once when the request URI matches a configured decoy-path prefix (see `sentinel_honeypot`). |
| `sentinel_weight_velocity N;` | `30` | Added once when the request rate for this identity exceeds the configured threshold in the velocity zone. |

### Velocity signal (`sentinel_velocity_zone` + `sentinel_velocity`)

Counts all completed requests per identity (SHA-256 of client IP) in a configurable sliding-window ring. If the count exceeds the configured `rate` threshold within `window` seconds, the identity is marked as rate-exceeded and `$sentinel_velocity` is set to `1`.

**Zone declaration (http context):**
```nginx
sentinel_velocity_zone name:size [rate=N] [window=S] [block=S];
```
- `name:size` — zone name and shared memory size (e.g. `vzone:10m`)
- `rate=N` — max requests allowed per window (default: 100)
- `window=S` — sliding-window duration in seconds (default: 10)
- `block=S` — ban duration in seconds once rate is exceeded (default: 3600)

**Per-location opt-in (http / server / location context):**
```nginx
sentinel_velocity <zone_name>;
```
Binds a location to a named velocity zone. **Velocity tracking is opt-in only** — a zone declared with `sentinel_velocity_zone` has no effect on a location unless that location (or a parent block) includes `sentinel_velocity <name>`. Nested locations inherit the binding from their parent unless they override it.

**Example:**
```nginx
http {
    sentinel_zone main:10m;
    sentinel_velocity_zone vzone:10m rate=100 window=10 block=3600;

    server {
        sentinel on;
        sentinel_velocity vzone;   # inherited by all locations below

        location /api/ {
            # inherits sentinel_velocity vzone
        }
        location /static/ {
            # no sentinel_velocity — velocity NOT tracked here
        }
    }
}
```

**Weight directive:**
```nginx
sentinel_weight_velocity 30;
```
Default weight: 30. Added once to the score when `velocity_exceeded=1`.

**Variable:** `$sentinel_velocity` — `1` if rate exceeded, `0` otherwise.

**Identity:** SHA-256 of `$remote_addr` text — same as errrate.

**Implementation:** reuses the errrate sliding-window ring (`sentinel_shm_errrate_record` / `sentinel_shm_errrate_lookup`) with a separate zone. Recording fires in the log handler on **every** request (no status filter). Lookup (read) fires in PREACCESS via `sentinel_velocity_signal()`.

### Honeypot (location / server / http context)

Operator-defined decoy URL paths that no legitimate client should ever request.
A prefix match against the request URI sets the `$sentinel_honeypot` variable to
`1` and adds `sentinel_weight_honeypot` (default 90) to the score. Match is
**case-sensitive** (URL paths are case-sensitive) and **prefix**: `/trap` matches
`/trap`, `/trap/`, `/trap?foo=1`, etc. No regex, no malloc in the request path;
bounded by the array of declared prefixes.

| Directive | Default | Description |
|---|---|---|
| `sentinel_honeypot /path [/path2 ...];` | — | One or more decoy path prefixes. Takes one or more arguments (space-separated); can be repeated across location/server/http levels (child inherits parent if not overridden). |
| `sentinel_weight_honeypot N;` | `90` | Score contribution of a decoy-path hit. Higher than `header_anomaly` (25) and `bot_ua` (30) since a decoy hit is near-certain evidence of malicious probing; lower than `crowdsec_ban` (100). |

**Variable:** `$sentinel_honeypot` — `1` if the current request URI matched a
decoy prefix, `0` otherwise.

**Example:**

```nginx
http {
    server {
        sentinel_honeypot /wp-login.php /.env /admin /actuator;

        location / {
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=30 tarpit=60 block=80;
        }
    }
}
```

### Allowlist (CIDR)

Operator-defined trusted IP ranges. If the client address matches any configured
CIDR, `$sentinel_allowlist` is set to `1` and the score is **short-circuited to
0** — every other signal is overridden. Intended for operator-**verified** ranges
only: published search-engine CIDR blocks, internal monitoring, office egress.
Pure in-memory match (`ngx_cidr_match`), no DNS, no network, no malloc in the
request path.

> **Security:** the allowlist does **not** nullify a CrowdSec ban. A deployed
> CrowdSec feed is the operator explicitly marking an IP malicious; if a trusted
> range is later compromised, the ban still applies (same auth-bypass guard as
> the `known_good_ua` short-circuit). Forward-confirmed reverse DNS (FCrDNS)
> verification of self-declaring crawlers is a separate, async follow-up — this
> directive is the static, request-path-safe half.

| Directive | Default | Description |
|---|---|---|
| `sentinel_allowlist <ip\|cidr> [...];` | — | One or more trusted IPv4/IPv6 addresses or CIDR ranges (space-separated; repeatable; child inherits parent if not overridden). A client in any range is exempt from scoring unless a CrowdSec ban is present. |

**Variable:** `$sentinel_allowlist` — `1` if the client IP matched a trusted
range, `0` otherwise.

**Example:**

```nginx
http {
    server {
        sentinel_allowlist 66.249.64.0/19 10.0.0.0/8 192.0.2.10;

        location / {
            sentinel on;
            sentinel_mode enforce;
        }
    }
}
```

### Tarpit (location context)

When the verdict is `tarpit`, the connection is held by a bounded "drip" writer
instead of being answered or dropped — slow, cheap to the server, expensive to
the bot. The tarpit is globally connection-capped (a per-worker shared-memory
counter summed across workers); at the cap, further tarpit verdicts are closed
immediately with `444` rather than queued. Decrement happens on every exit path
via a single request-pool cleanup, so the counter can never leak. Only active in
`enforce` mode; in `shadow` mode a "would tarpit" line is logged and the request
passes.

| Directive | Default | Bounds | Description |
|---|---|---|---|
| `sentinel_tarpit_max_conns N;` | `256` | `0`–`65536` | Global cap on concurrently tarpitted connections. `0` disables the tarpit (verdict downgrades to immediate `444`). |
| `sentinel_tarpit_delay ms;` | `5000` | `100`–`60000` | Delay between drip ticks. |
| `sentinel_tarpit_bytes N;` | `1024` | `1`–`65536` | Total bytes dripped before the response completes. |
| `sentinel_tarpit_max_lifetime ms;` | `30000` | `1000`–`600000` | Hard ceiling on how long a tarpitted connection is held; force-closed at the deadline regardless of drip progress. |

#### Throttle (instead of tarpit)

| Directive | Default | Description |
|---|---|---|
| `sentinel_throttle_rate size;` | `0` (off) | On a `tarpit`-band verdict in `enforce` mode, **let the request through but cap egress at `size` bytes/sec** (e.g. `32k`) via nginx's native `r->limit_rate`, instead of dripping a tarpit trap. |

When set (`> 0`), a `tarpit` verdict no longer opens a drip connection — the
request is served normally with its body rate-limited by the core limiter (no
extra timers, FDs, or connection cap; bounded entirely by nginx). Useful for
suspected-but-not-certain scrapers where a hard tarpit/block is too aggressive:
they get served, just slowly. `$sentinel_throttled` is `1` when applied. Only
active in `enforce` mode; `0` keeps the default tarpit behaviour.

### Block (location / server / http context)

When the verdict is `block`, the request is denied in the `PREACCESS` phase.
By default the configured HTTP status (`403`) is returned; the special value
`444` drops the connection without any response (nginx's non-standard close).
Only active in `enforce` mode; in `shadow` mode a `verdict=block` line is logged
and the request passes.

| Directive | Default | Bounds | Description |
|---|---|---|---|
| `sentinel_block_status N;` | `403` | `400`–`599`, or `444` | HTTP status returned for a `block` verdict. `444` closes the connection with no response. |
| `sentinel_block_ttl S;` | `0` (off) | `>= 0` | On a `block` verdict in `enforce` mode, persist a self-ban for `S` seconds in the errrate `sentinel_zone`. |

#### TTL soft-ban

With `sentinel_block_ttl S;` (S > 0), a `block` verdict in `enforce` mode also
writes `blocked_until = now + S` for the client identity (`SHA-256($binary_remote_addr)`)
into the errrate zone. Every subsequent request from that identity is then
short-circuited by the errrate lookup (it returns *blocked* → `sentinel_weight_blocked`,
default `100`, folds into the score → the score re-crosses the block band) for the
whole TTL — **with no re-evaluation of the original signals**. After the TTL
expires the entry ages out and the identity is evaluated normally again.

Requires a `sentinel_zone` bound to the location (the errrate zone); if none is
configured the soft-ban is skipped (fail-open) and only the immediate block fires.
Shadow mode never persists a soft-ban.

### CrowdSec feed (out-of-band)

Sentinel never queries CrowdSec from the request path. An external sidecar (the
CrowdSec lua bouncer in stream mode, or a small poller) writes decisions to a
flat feed file; sentinel loads it into a dedicated shared-memory ban table on a
worker timer and the request path does an O(1) locked lookup. A CrowdSec hit is
scored, not hard-blocked: it folds `sentinel_weight_crowdsec` into the weighted
sum (action-tiered — `ban` → block band, `captcha` → challenge band, `throttle`
→ tarpit band), so it respects shadow mode and the `known_good_ua` short-circuit.

Feed format: `# sentinel-crowdsec-feed v1` header, `<ip> <action> <expiry-epoch>`
per line, `%%EOF <N> <crc32hex>` trailer (count + CRC32 validated before the
table is touched; the writer must atomic-rename). Any malformed / truncated /
oversized / stale feed → log + keep the last-good table (fail-open).

| Directive | Default | Description |
|---|---|---|
| `sentinel_crowdsec_zone name:size;` | — | Dedicated shared-memory zone for the decision table (http context). |
| `sentinel_crowdsec_feed path;` | — | Path to the flat feed file written by the sidecar. |
| `sentinel_crowdsec_interval s;` | `10` | Refresh tick; the feed is reloaded only when its mtime changes. |
| `sentinel_crowdsec_default_ttl s;` | `3600` | TTL applied to entries whose `expiry-epoch` is `0`. |
| `sentinel_crowdsec_stale_after s;` | `600` | A feed older than this is treated as stale (logged); LRU age threshold. |
| `sentinel_crowdsec_max_bytes N;` | `16m` | Feed size cap; a larger file is rejected (fail-open). |
| `sentinel_weight_crowdsec N;` | `100` | Weight of a CrowdSec hit (scaled by action tier) in the score. |

### Scoring model

```
score = (sentinel_weight_errrate × errrate_count)
      + (sentinel_weight_blocked × errrate_blocked)   /* 0 or 1 */
      + (sentinel_weight_scanner × scanner_path)      /* 0 or 1 */
      + (sentinel_weight_bot     × bot_ua)            /* 0 or 1 */
      + (sentinel_weight_header  × header_anomaly)    /* 0 or 1 */
      + (sentinel_weight_honeypot × honeypot)         /* 0 or 1 */
      + (sentinel_weight_crowdsec × crowdsec_hit × tier) /* ban/captcha/throttle */
```

**Short-circuit:** if the User-Agent matches a known search-engine allowlist
(`known_good_ua`) **and** there is no CrowdSec hit, the score is forced to 0,
overriding the in-module heuristics. The match is currently UA-substring only
(not yet forward/reverse-DNS confirmed), so it is deliberately gated: a CrowdSec
ban — the operator's explicit "malicious regardless of headers" verdict — is
never nullified by a spoofable `User-Agent`. Once RDNS verification lands the
gate can relax to a verified flag.

**Clamp:** the score is capped at `100000` (`NGX_SENTINEL_SCORE_MAX`) to
prevent integer overflow from pathological weight × count products.

**Verdict mapping** (using `sentinel_threshold` defaults):

| Score range | Verdict |
|---|---|
| ≥ 80 | block (`sentinel_block_status`, default `403`; `444` = drop) |
| 60 – 79 | tarpit (garbage drip) |
| 30 – 59 | challenge (PoW / js-challenge) |
| 0 – 29 | allow |

### Variables & structured decision log

Every per-request decision input is exposed as an nginx variable, so you can emit
a complete, machine-parseable decision record with a stock `log_format` — no
custom log directive needed. All variables are `NOCACHEABLE` and resolve to the
values computed in the `PREACCESS` phase.

| Variable | Type | Meaning |
|---|---|---|
| `$sentinel_score` | int | Final weighted score |
| `$sentinel_verdict` | token | `allow` / `challenge` / `tarpit` / `block` |
| `$sentinel_ja4h` | hex | JA4H request fingerprint (24 hex chars) |
| `$sentinel_errrate` | int | Error-burst count from the sliding window |
| `$sentinel_scanner` | `0`/`1` | URI matched a known scanner-path prefix |
| `$sentinel_bot` | `0`/`1` | Heuristic bot User-Agent |
| `$sentinel_header_anomaly` | `0`/`1` | Suspicious/malformed request headers |
| `$sentinel_honeypot` | `0`/`1` | URI matched a decoy-path prefix |
| `$sentinel_velocity` | `0`/`1` | Per-identity request rate exceeded |
| `$sentinel_allowlist` | `0`/`1` | Client IP in a trusted CIDR |
| `$sentinel_crowdsec` | `0`/`1` | IP present in the CrowdSec ban table |
| `$sentinel_crowdsec_action` | token | `none` / `ban` / `captcha` / `throttle` |
| `$sentinel_throttled` | `0`/`1` | Throttle action applied (tarpit verdict served with capped egress) |

**Example — JSON decision log:**

```nginx
log_format sentinel_decision escape=json
    '{"ts":"$time_iso8601","ip":"$remote_addr","uri":"$request_uri",'
    '"score":$sentinel_score,"verdict":"$sentinel_verdict",'
    '"ja4h":"$sentinel_ja4h","errrate":$sentinel_errrate,'
    '"scanner":$sentinel_scanner,"bot":$sentinel_bot,'
    '"header_anomaly":$sentinel_header_anomaly,"honeypot":$sentinel_honeypot,'
    '"velocity":$sentinel_velocity,"allowlist":$sentinel_allowlist,'
    '"crowdsec":$sentinel_crowdsec,"crowdsec_action":"$sentinel_crowdsec_action",'
    '"throttled":$sentinel_throttled}';

server {
    sentinel on;
    sentinel_mode shadow;                       # observe first
    access_log /var/log/nginx/sentinel.jsonl sentinel_decision;
}
```

In `shadow` mode this gives you a full per-request decision feed to tune weights
and thresholds before switching to `enforce`. The same line is also emitted to
`error_log` at `info` level on every request (both modes) as a `key=value`
string for quick eyeballing.

---

## Per-route policy

Every sentinel directive is parsed in the `http`, `server` **and** `location`
contexts and merges with stock nginx inheritance — a directive set in a
`location {}` overrides the value inherited from `server`/`http`. There is no
separate "policy" directive: you compose per-route behaviour out of the existing
directives. This lets you run one global baseline and carve out exceptions
per-route — a stricter policy on an admin path, a relaxed one on a health probe,
shadow-only on a noisy API — without duplicating the whole config.

```nginx
http {
    sentinel_zone reps:10m;

    server {
        # Baseline for the whole vhost.
        sentinel on;
        sentinel_mode enforce;
        sentinel_zone reps:10m;
        sentinel_threshold challenge=30 tarpit=60 block=80;

        # Stricter: low block band, heavy bot weight -> bots blocked outright.
        location /admin/ {
            sentinel_threshold challenge=10 tarpit=50 block=90;
            sentinel_weight_bot 100;
        }

        # Relaxed: never block here (lift the bands out of reach, drop bot weight).
        location = /healthz {
            sentinel_threshold challenge=900 tarpit=950 block=990;
            sentinel_weight_bot 0;
        }

        # Observe only: score and log, never enforce, on a noisy API.
        location /api/ {
            sentinel_mode shadow;
        }

        # Disable entirely for a trusted internal callback.
        location = /internal/cb {
            sentinel off;
        }
    }
}
```

The same client identity can therefore receive different verdicts on different
routes within one request lifetime of the server — the policy is resolved from
the matched location, not globally. (Shared-memory **zone declarations**
— `sentinel_zone`, `sentinel_velocity_zone` — remain `http`-context only; only
the per-request *policy* directives are location-overridable.)

---

## Why one module

All three are the same pipeline at one decision point (`PREACCESS`):

```
request ──► [sentinel] ─► score = w1·crowdsec(ip)        (Phase 3, out-of-band)
                                 + w2·bot/UA signal       (in-module)
                                 + w3·error-burst          (in-module, absorbed)
                                 + w4·scanner-path         (in-module)
                                 + w5·header-anomaly        (in-module)
                                 + JA4H(headers)           (in-module)
                                 [+ JA4 TLS  — Phase 4, needs core patch]
            verdict:  low → allow
                      mid → challenge (built-in PoW / optional js-challenge)
                      hi  → tarpit (bounded drip)
                      max → 403
```

## Design pillars (see DESIGN.md)

- **No network in the request path** — per-request is a pure shared-memory
  lookup. Reputation data is loaded out of band. No added latency, no
  slowloris-against-yourself.
- **Fail-open by default** — a lookup/zone error logs and allows; `closed` is
  opt-in.
- **Bounded tarpit** — global concurrent-connection cap, tiny timers, fixed
  buffers, hard max lifetime. Never a self-DoS.
- **Self-contained** — every signal computed in-module; no runtime sibling-module
  dependency. Logic ported from `error-abuse` (error-rate), `bot-verifier` /
  `user-agent` (bot/UA), JA4H (in-module) into sentinel's own source.
- **Zero core patch in Phase 1–3** — JA4H + error-rate + UA/bot + CrowdSec all
  pure-HTTP / out-of-band. JA4 (TLS) needs a core nginx ClientHello patch, so it
  is deferred to Phase 4 (added only when JA4H evasion shows in traffic).

## See also

- Sibling own-modules (GitHub):
  - [nginx-error-abuse-module](https://github.com/eilandert/nginx-error-abuse-module)
    — error-rate + CI-harness source; **sentinel absorbs its logic, standalone
    deprecated later**
  - [nginx-autocert-module](https://github.com/eilandert/nginx-autocert-module)
  - [nginx-strip-filter-module](https://github.com/eilandert/nginx-strip-filter-module)
  - [nginx-cache-turbo-module](https://github.com/eilandert/nginx-cache-turbo-module)
  - [nginx-label-autoconf-module](https://github.com/eilandert/nginx-label-autoconf-module)
- Pitch / design overview:
  [deb.myguard.nl pitch page](https://deb.myguard.nl/pitch-ngx_http_sentinel-unified-client-reputation-tarpit-module/).
- Ships in the deb.myguard.nl nginx/angie build (`/opt/packages`):
  [nginx-modules stack](https://deb.myguard.nl/nginx-modules/) ·
  [angie-modules-optimized-extended stack](https://deb.myguard.nl/angie-modules-optimized-extended/).

## Development

- Per-item feature branch off `master` → PR to **`master`** → **remote CI green**
  → squash-merge. (No `dev` branch — the old dev/local-CI model is retired.)
- Build/test standalone: `bash tools/ci-build.sh`. valgrind + fuzz run manually +
  monthly (remote workflow) and weekly (local cron).

## License

MIT — see [LICENSE](LICENSE).
