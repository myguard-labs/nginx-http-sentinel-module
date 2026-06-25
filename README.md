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
| `sentinel_weight_asn N;` | `35` | Added once when the client's ASN (read from an operator-supplied geoip2 variable) matches the flagged datacenter/abuse-ASN list (see `sentinel_asn`). |
| `sentinel_weight_ja4 N;` | `50` | Added once when the client's JA4 TLS fingerprint (read from an operator-supplied ssl-fingerprint variable) matches the deny list (see `sentinel_ja4`). |
| `sentinel_weight_coherence N;` | `40` | Added once when the User-Agent claims a mainstream browser but the request lacks a real browser's header shape (see *UA↔request-shape coherence* below). |

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

### Datacenter / abuse ASN (location / server / http context)

Flags requests originating from a configured list of datacenter or abuse
Autonomous System Numbers (e.g. cloud-provider ranges that no legitimate
end-user browser should sit behind). A match sets `$sentinel_asn` to `1` and
adds `sentinel_weight_asn` (default `35`) once.

**The module does NOT link libmaxminddb or own any GeoIP database.** ASN lookup
is delegated entirely to the separately-packaged
[ngx_http_geoip2_module](https://github.com/leev/ngx_http_geoip2_module)
(Debian: `libnginx-mod-http-geoip2`). The operator maps a geoip2 ASN variable
into sentinel via `sentinel_asn`; sentinel reads that variable per request,
parses it as an unsigned ASN, and matches it against `sentinel_datacenter_asn`.

| Directive | Default | Meaning |
|-----------|---------|---------|
| `sentinel_asn <variable>;` | — | The geoip2 ASN source variable (e.g. `$geoip2_asn`). Empty/unset = signal off. The value is parsed as an unsigned integer; non-numeric or empty values fail open (no flag). |
| `sentinel_datacenter_asn N [N ...];` | — | One or more flagged ASNs (space-separated; repeatable; child inherits parent if not overridden). |

**Variable:** `$sentinel_asn` — `1` if the client's ASN matched the flagged
list, `0` otherwise.

**Example:**

```nginx
http {
    # geoip2 module owns the MaxMind DB and sets the ASN variable.
    geoip2 /usr/share/GeoIP/GeoLite2-ASN.mmdb {
        $geoip2_asn autonomous_system_number;
    }

    server {
        sentinel_asn $geoip2_asn;
        sentinel_datacenter_asn 16509 14618 15169 14061 16276;  # AWS, AWS, GCP, DigitalOcean, OVH

        location / {
            sentinel on;
            sentinel_mode enforce;
        }
    }
}
```

> **Fail-open:** if the geoip2 module is not loaded, the source variable is
> unset, or the IP is not in the DB (empty value), the signal contributes `0` —
> it never blocks on a missing lookup.

### JA4 (TLS) fingerprint deny-list (location / server / http context)

Flags requests whose **JA4 TLS fingerprint** (computed from the ClientHello)
matches an operator deny list of known-bad fingerprints — bot frameworks,
scrapers and scanners that present a distinctive, stable TLS stack. A match sets
`$sentinel_ja4` to `1` and adds `sentinel_weight_ja4` (default `50`) once.

This is JA4 **TLS** — distinct from the module's own in-HTTP JA4**H**
(`$sentinel_ja4h`, computed from request headers). **The module does NOT link
openssl or parse the ClientHello.** The TLS fingerprint is produced by the
separately-packaged ssl-fingerprint module (Debian:
`libnginx-mod-ssl-fingerprint`), which exposes `$ssl_fingerprint_ja4` (and
`_hash`, `_o`, `$ssl_fingerprint_ja3{,_hash}`) after `ssl_fingerprint on;`. The
operator maps that variable into sentinel via `sentinel_ja4`; sentinel reads it
per request and matches it (case-insensitive) against `sentinel_ja4_deny`.

| Directive | Default | Meaning |
|-----------|---------|---------|
| `sentinel_ja4 <variable>;` | — | The ssl-fingerprint JA4 source variable (e.g. `$ssl_fingerprint_ja4`). Empty/unset = signal off. An empty value (non-TLS / no ClientHello) fails open (no flag). |
| `sentinel_ja4_deny <ja4|hash> [...];` | — | One or more denied JA4 fingerprints (raw JA4 string or hash — whichever the source variable emits; space-separated; repeatable; child inherits parent if not overridden). Matched case-insensitively. |

**Variable:** `$sentinel_ja4` — `1` if the client's JA4 matched the deny list,
`0` otherwise.

**Example:**

```nginx
http {
    server {
        listen 443 ssl;
        ssl_fingerprint on;                 # ssl-fingerprint module

        sentinel_ja4 $ssl_fingerprint_ja4;
        sentinel_ja4_deny t13d1516h2_8daaf6152771_b186095e22b6  # e.g. a scraper stack
                          t13d1715h2_5b57614c22b0_3d5424432f57;

        location / {
            sentinel on;
            sentinel_mode enforce;
        }
    }
}
```

> **Fail-open:** if the ssl-fingerprint module is not loaded, the source
> variable is unset, or the connection is non-TLS (empty value), the signal
> contributes `0` — it never blocks on a missing fingerprint.

### UA↔request-shape coherence

Every mainstream interactive browser (Chrome, Firefox, Safari, Edge) emits a
characteristic request shape: an `Accept` header, an `Accept-Language` header, an
`Accept-Encoding` advertising `gzip` (and usually `br`), and HTTP/1.1 or HTTP/2.
A scraper that forges a browser `User-Agent` but speaks a bare HTTP client (no
`Accept*`, HTTP/1.0, no compression) is **incoherent** — it claims to be a
browser it demonstrably is not.

This signal flags exactly that mismatch: the UA claims a mainstream browser
family **and** the request is missing that family's header fingerprint entirely
(no `Accept`, **or** no `Accept-Language`, **or** no `gzip`/`br`
`Accept-Encoding`, **or** a pre-HTTP/1.1 protocol). It is deliberately
conservative — any one fingerprint present clears it — to keep the
false-positive rate near zero. A match sets `$sentinel_coherence` to `1` and
adds `sentinel_weight_coherence` (default `40`) once.

There is **no fingerprint database and no JA4H hash comparison** — a SHA-256
hash cannot be mapped to a browser family without a brittle per-version table.
This is a pure structural heuristic over the request headers: no DB, no regex,
no malloc, no network. It needs no configuration; it activates wherever
`sentinel on;` is set. Tune or disable it with `sentinel_weight_coherence`
(set `0` to turn it off).

**Variable:** `$sentinel_coherence` — `1` if the UA claimed a browser the
request shape contradicts, `0` otherwise (including for honest non-browser
clients, which make no browser claim and are scored by the bot-UA signal).

> **Fail-open:** no User-Agent, a non-browser UA, or a fully browser-shaped
> request all contribute `0`.

### FCrDNS verify — forward-confirmed reverse DNS (location context)

A `User-Agent: Googlebot` header is trivially spoofable, yet the bot-UA signal
sets `known_good_ua` on the substring alone and the score lets that short-circuit
the in-module heuristics — an auth-bypass risk for anyone impersonating a search
engine. FCrDNS closes it. When enabled, a request whose UA matches a known crawler
triggers an **asynchronous** PTR lookup of the client IP, then a forward (A/AAAA)
lookup of the resolved name, and only trusts the crawler claim if the forward
result contains the original client IP (optionally with a configured PTR-name
suffix such as `.googlebot.com`).

The verdict (`verified` / `spoofed`) is cached per-IP in a dedicated shm zone for
`sentinel_fcrdns_ttl` seconds. **The DNS work never blocks the request path:** the
first request from an IP fails open (verdict `pending` → `known_good_ua` keeps its
legacy behavior for that one request) and kicks the async resolve; the cached
verdict governs every subsequent request. A `spoofed` verdict **suppresses** the
`known_good_ua` short-circuit, so the impersonator is scored as the bot it is; a
`verified` verdict (or a still-`pending`/disabled signal) leaves the legacy
short-circuit intact.

**Zone declaration (http context)** + binding (enables the signal):
```nginx
http {
    resolver 1.1.1.1 8.8.8.8 valid=300s;   # required for the async lookups
    sentinel_fcrdns_zone fcdns:1m;          # verdict cache

    server {
        location / {
            sentinel on;
            sentinel_fcrdns fcdns;                              # bind + enable
            sentinel_fcrdns_ttl 1h;                             # verdict cache TTL
            sentinel_fcrdns_verify_suffix .googlebot.com .google.com
                                          .search.msn.com;      # optional PTR gate
        }
    }
}
```

| Directive | Default | Meaning |
|---|---|---|
| `sentinel_fcrdns_zone name:size;` | — | Declares the verdict-cache shm zone (http context). |
| `sentinel_fcrdns <zone>;` | off | Bind a location to a verdict zone and enable FCrDNS there. |
| `sentinel_fcrdns_ttl time;` | `1h` | How long a `verified`/`spoofed` verdict is cached before re-resolution. |
| `sentinel_fcrdns_verify_suffix <s>...;` | — | Restrict accepted PTR names to these suffixes (empty = accept any forward-confirmed name). |

**Variable:** `$sentinel_fcrdns` — `verified` / `spoofed` / `pending` (the last
also covers disabled, no-`known_good_ua`, and no-resolver cases).

> **Fail-open:** no resolver configured, no bound zone, lookup error/timeout, or
> NXDOMAIN all leave the verdict `pending` and never block the request. Only a
> positive disproof (wrong suffix, or a forward result that does not contain the
> client IP) caches `spoofed`.

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
| `sentinel_tarpit_maze on\|off;` | `off` | — | **Maze mode.** Drip HTML decoy crawl-links (`<a href="/…/">`) instead of blank padding, served as `text/html`. A link-following scraper keeps requesting fresh tarpit URLs, sinking more of its time. |

#### Maze mode

With `sentinel_tarpit_maze on;` the tarpit response becomes a never-ending stream
of unique decoy links instead of meaningless whitespace:

```nginx
location / {
    sentinel on;
    sentinel_mode enforce;
    sentinel_tarpit_maze on;
}
```

Each drip tick emits one `<a href="/<random-hex>/">x</a>` line; every href is
unique (a cheap per-connection PRNG, no allocation, no shared state) and points
back into the same tarpitted handler, so a crawler that follows links walks
deeper into the maze. All the bounding controls above (`max_conns`, `delay`,
`bytes`, `max_lifetime`) still apply unchanged — maze only changes the *content*
of the drip, not its resource envelope. Maze and `sentinel_throttle_rate` are
mutually exclusive in effect: throttle bypasses the drip entirely, so it wins.

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

#### Origin-shield (serve cache-only instead of tarpit)

| Directive | Default | Description |
|---|---|---|
| `sentinel_shield on\|off;` | `off` | On a `tarpit`-band verdict in `enforce` mode, **let the request through but raise `$sentinel_shield=1`** instead of dripping a trap, so the operator's `proxy_*` block can serve the response **from cache / stale** and spare the origin. |

A suspected scraper that hits the `tarpit` band still gets a response — but the
operator decides it must come from cache, never a fresh origin fetch. Because at
the `PREACCESS` phase the upstream/cache objects don't exist yet (and nginx's
stale-cache directives take no variable), the module only **raises the signal**;
you wire the enforcement in your proxy block. A typical recipe:

```nginx
# raise the flag when sentinel decides to shield
sentinel_shield on;

location / {
    proxy_pass http://backend;
    proxy_cache mycache;
    # serve stale to shielded clients even while updating / on error,
    # so a flagged scraper never reaches the origin
    proxy_cache_use_stale updating error timeout;
    proxy_cache_background_update on;
    # never let a shielded request populate a fresh cache entry from origin
    proxy_no_cache        $sentinel_shield;
    proxy_cache_bypass    "";
}
```

`$sentinel_shield` is `1` when applied. Only active in `enforce` mode. Throttle
takes precedence: if `sentinel_throttle_rate > 0`, the throttle fork runs first
and shield is not reached. `off` keeps the default tarpit behaviour.

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

### Proof-of-work challenge (location / server / http context)

When the verdict is `challenge` (the band between `tarpit` and `block`),
`enforce` mode can serve a built-in **proof-of-work** gate instead of letting
the request through. Sentinel returns a small, self-contained HTML+JS page that
asks the browser to find a nonce such that
`SHA256(challenge || nonce)` has at least `difficulty` leading zero **bits**.
A real browser solves it in well under a second; a headless flood pays CPU per
request. On success the client receives a signed bypass cookie and is not
challenged again until it expires.

| Directive | Default | Bounds | Description |
|---|---|---|---|
| `sentinel_pow on\|off;` | `off` | — | Enable the PoW challenge for `challenge`-band verdicts. |
| `sentinel_pow_secret <key>;` | — | required | HMAC signing key for the stateless challenge and the bypass cookie. **Required**; with no secret the challenge is disabled (fail-open). |
| `sentinel_pow_difficulty N;` | `16` | `1`–`32` | Required leading zero **bits** of the solution hash. Each extra bit doubles the expected work. |
| `sentinel_pow_ttl S;` | `3600` | `>= 1` | Lifetime (seconds) of both the challenge time-bucket and the bypass cookie. |

The challenge is **stateless** — no shared memory:

```
challenge = HMAC-SHA256(secret, binary_remote_addr || floor(now / ttl))
cookie    = <expiry> "." HMAC-SHA256(secret, IP || expiry)
```

The client re-requests with the nonce in the `X-Sentinel-Pow` header or the
`?__sentinel_pow=` query argument; the module recomputes the challenge, checks
the difficulty, and issues the `__sentinel_pow` cookie (`Path=/; HttpOnly`,
`Max-Age = ttl`). Subsequent requests carrying a valid, unexpired cookie bypass
the challenge.

Security posture: cookie/solution HMACs are **constant-time** compared; a
request with a **present but invalid/expired cookie fails closed** (it is
re-challenged, never allowed through); the module fails **open** only when PoW
is disabled or no secret is configured. No DNS, no malloc in the verify path
beyond a couple of small request-pool buffers. Uses OpenSSL (`-lcrypto`, already
linked) — no external dependency. `$sentinel_pow` reports `off` / `challenge`
(page served) / `verified` (cookie or solution accepted).

```nginx
location / {
    sentinel on;
    sentinel_mode enforce;
    sentinel_pow on;
    sentinel_pow_secret "change-me-to-a-long-random-string";
    sentinel_pow_difficulty 18;
    sentinel_pow_ttl 1800;
}
```

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

### Redis multi-box shared state (out-of-band)

When several nginx hosts front the same site, a ban learned on one box should
protect the others. `sentinel_redis` shares ban state across hosts through a
single Redis instance — **both directions, strictly out-of-band**: a per-worker
timer drives an async [hiredis](https://github.com/redis/hiredis) connection
bound to nginx's own event loop. There is **never** any synchronous network I/O
in the request path; if Redis is unreachable every operation is a no-op and the
module degrades cleanly to per-host shared memory (fail-open), reconnecting with
exponential backoff.

- **Pull** (timer): `SCAN <prefix>:ban:*`, `GET` each, and upsert the ban into
  the local CrowdSec ban table. Pulled bans flow through the existing
  `sentinel_weight_crowdsec` scoring tier — no new weight or zone. This requires
  a `sentinel_crowdsec_zone` declared in `http {}` (the same table the feed uses;
  sentinel auto-binds it).
- **Push** (timer): a local **BLOCK** decision in enforce mode is queued in a
  shared-memory ring and flushed as `SET <prefix>:ban:<ip> "<action> <expiry>"
  EX <ttl>`. **Ban-loop guard:** a block driven by a CrowdSec hit (i.e. an
  externally-sourced ban — from the feed or a Redis pull) is **never**
  re-published, so two boxes can't echo a ban back and forth forever. Only
  locally-originated decisions are pushed.

A pulled ban is marked internally so it is exempt from re-push; the request path
is untouched by either direction (it only ever reads the local CrowdSec table).

```nginx
http {
    sentinel_crowdsec_zone cs:4m;          # ban table (shared with feed, if any)
    server {
        location / {
            sentinel on;
            sentinel_mode enforce;
            sentinel_redis 10.0.0.9:6379;   # Redis endpoint (host[:port])
            sentinel_redis_password "${REDIS_PW}";
            sentinel_redis_interval 10;     # pull + flush tick (seconds)
            sentinel_redis_ttl 3600;        # TTL on pushed ban keys
            sentinel_redis_prefix sentinel; # key namespace
            # ... weights / thresholds ...
        }
    }
}
```

| Directive | Default | Description |
|---|---|---|
| `sentinel_redis host[:port];` | — | Enable Redis multi-box shared state and set the endpoint. Requires a `sentinel_crowdsec_zone`. One endpoint per worker (the first configured wins). |
| `sentinel_redis_password <pw>;` | — | Optional `AUTH` password. |
| `sentinel_redis_prefix <ns>;` | `sentinel` | Key namespace (`<prefix>:ban:<ip>`). |
| `sentinel_redis_interval s;` | `10` | Pull/flush tick. Bounds: 1–3600 s. |
| `sentinel_redis_ttl s;` | `3600` | TTL applied to pushed ban keys. Bounds: 60–86400 s. |

> **Build dependency:** the Redis integration links `libhiredis`
> (`Depends: libhiredis*` on the packaged build). Reference a password via an
> nginx variable / env-templated config — never hard-code it.

### CrowdSec decision feedback (out-of-band)

The reverse of the CrowdSec feed: sentinel exports its **own** BLOCK decisions as
a CrowdSec **file-acquisition decisions file**, so the rest of a CrowdSec
deployment (`cscli`, other bouncers, the LAPI) learns about abuse that nginx
detected locally. There is **no network in nginx** — the request path only
enqueues the ban into a shared-memory ring; a worker timer atomically rewrites
the file (write `.tmp`, rename) every interval. Only worker 0 owns the file.

Only **locally-originated** bans are exported: a block driven by a CrowdSec hit
(feed or Redis pull) is skipped — the same ban-loop guard the Redis push uses.

```nginx
location / {
    sentinel on;
    sentinel_mode enforce;
    sentinel_cs_sink_path /var/lib/crowdsec/sentinel-decisions.json;
    sentinel_cs_sink_ttl 4h;                       # decision duration
    sentinel_cs_sink_scenario sentinel/http-abuse; # shows up in cscli
}
```

The file is a stream of CrowdSec decision objects, one per line:

```json
{"value":"1.2.3.4","scope":"Ip","duration":"14400s","scenario":"sentinel/http-abuse","origin":"sentinel"}
```

Wire it into CrowdSec one of two ways:

- **Import on a cron** — `cscli decisions import -i /var/lib/crowdsec/sentinel-decisions.json --format json`
- **File acquisition** — point a CrowdSec acquisition at the file so the agent
  ingests it continuously.

| Directive | Default | Description |
|---|---|---|
| `sentinel_cs_sink_path <file>;` | — | Enable the sink and set the decisions file. The directory must be writable by the nginx worker. |
| `sentinel_cs_sink_interval s;` | `10` | Drain/rewrite tick. Bounds: 1–3600 s. |
| `sentinel_cs_sink_ttl s;` | `3600` | `duration` written for each decision. Bounds: 60–86400 s. |
| `sentinel_cs_sink_scenario <s>;` | `sentinel/http-abuse` | The `scenario` field value. |

> Fail-open: any filesystem error logs a warning and is skipped (the block
> itself still fires). The ring drops on overflow (bounded). Decisions age out of
> the file once their TTL elapses.

### Prometheus metrics (`sentinel_status`)

`sentinel_status;` installs a content handler that emits aggregate counters in
the Prometheus text exposition format (`text/plain; version=0.0.4`). It is a
**pull** endpoint — point your scraper at it; there is no push, no timer, and no
external dependency. Counters live in the same shared-memory segment as the
tarpit accounting (allocated once any `sentinel_zone` exists), are bumped
lock-free in the preaccess phase for **every** evaluated request (shadow and
enforce alike), and are read without locking. Metrics are best-effort: they
never block, allocate in, or fail a request.

```nginx
location = /sentinel-status {
    sentinel_status;
    allow 127.0.0.1;          # scraper / Prometheus node
    allow 10.0.0.0/8;
    deny  all;                # the endpoint is unauthenticated — restrict it
}
```

The location runs no sentinel evaluation itself — it only reports the counters
the *other* sentinel-enabled locations populate. **Protect it** with
`allow`/`deny` (or an auth layer): it exposes operational signal.

Exposed metrics:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sentinel_requests_total` | counter | — | Requests evaluated by sentinel. |
| `sentinel_verdict_total` | counter | `v=allow\|challenge\|tarpit\|block` | Verdicts by band. |
| `sentinel_signal_total` | counter | `s=errrate\|blocked\|scanner\|bot\|header\|honeypot\|velocity\|asn\|coherence\|crowdsec` | Per-signal hit count (one per request the signal fired on). |
| `sentinel_shadow_total` | counter | — | Would-block decisions (tarpit/block band) suppressed because the location is in shadow mode. |
| `sentinel_tarpit_active` | gauge | — | Connections currently held in a tarpit (live sum of per-worker counters). |

Example PromQL — block rate over 5 min:
`rate(sentinel_verdict_total{v="block"}[5m])`.

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
| `$sentinel_asn` | `0`/`1` | Client ASN in the flagged datacenter/abuse list |
| `$sentinel_ja4` | `0`/`1` | Client JA4 (TLS) fingerprint on the deny list |
| `$sentinel_coherence` | `0`/`1` | UA claims a browser the request shape contradicts |
| `$sentinel_fcrdns` | token | `verified` / `spoofed` / `pending` (forward-confirmed reverse-DNS verdict) |
| `$sentinel_allowlist` | `0`/`1` | Client IP in a trusted CIDR |
| `$sentinel_crowdsec` | `0`/`1` | IP present in the CrowdSec ban table |
| `$sentinel_crowdsec_action` | token | `none` / `ban` / `captcha` / `throttle` |
| `$sentinel_throttled` | `0`/`1` | Throttle action applied (tarpit verdict served with capped egress) |
| `$sentinel_shield` | `0`/`1` | Origin-shield action applied (tarpit verdict served cache-only by operator) |
| `$sentinel_pow` | token | `off` / `challenge` (PoW page served) / `verified` (cookie or solution accepted) |

**Example — JSON decision log:**

```nginx
log_format sentinel_decision escape=json
    '{"ts":"$time_iso8601","ip":"$remote_addr","uri":"$request_uri",'
    '"score":$sentinel_score,"verdict":"$sentinel_verdict",'
    '"ja4h":"$sentinel_ja4h","errrate":$sentinel_errrate,'
    '"scanner":$sentinel_scanner,"bot":$sentinel_bot,'
    '"header_anomaly":$sentinel_header_anomaly,"honeypot":$sentinel_honeypot,'
    '"velocity":$sentinel_velocity,"asn":$sentinel_asn,'
    '"ja4":$sentinel_ja4,"coherence":$sentinel_coherence,'
    '"fcrdns":"$sentinel_fcrdns",'
    '"allowlist":$sentinel_allowlist,'
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
