# nginx-http-sentinel-module

A single nginx PREACCESS module that scores every client and acts on the verdict —
tarpit bots, block scanners, PoW-challenge grey-area requests, feed decisions back
to CrowdSec. No network in the request path, no external process, no added latency.

Ships as `libnginx-mod-http-sentinel` in the
[deb.myguard.nl](https://deb.myguard.nl/nginx-modules/) nginx / angie build.

---

## How it works

Every request is scored by combining weighted signals — bot UA, error burst,
scanner paths, velocity, datacenter ASN, TLS/TCP fingerprints, CrowdSec decisions.
The score maps to a verdict: **allow** → **challenge** → **tarpit** → **block**.

```
score ≥ block_threshold  → 403 / 444 drop  (+ optional TTL soft-ban)
score ≥ tarpit_threshold → bounded garbage drip, throttle, or cache-only
score ≥ challenge_threshold → proof-of-work page
otherwise                → allow
```

In **shadow mode** (`sentinel_mode shadow`) the module scores and logs without
acting. Run shadow first, watch `$sentinel_verdict` in your access log, then flip
to `enforce` once you're happy with the weights.

The module has **no runtime sibling deps**: it absorbs its own error-rate counter,
bot-UA heuristics, JA4H fingerprinter, and scanner-path table. CrowdSec and Redis
state are loaded out-of-band by a worker timer; the request path only does
shared-memory lookups.

---

## Quick start

```nginx
http {
    sentinel_zone main:10m;          # shared-memory identity store

    server {
        listen 80;
        server_name example.com;

        sentinel on;
        sentinel_mode shadow;        # observe first, switch to enforce later
        sentinel_zone main:10m;

        log_format sentinel_log '$remote_addr $sentinel_score/$sentinel_verdict '
                                 'bot=$sentinel_bot scanner=$sentinel_scanner '
                                 'errrate=$sentinel_errrate';
        access_log /var/log/nginx/sentinel.log sentinel_log;

        location / {
            root /var/www/html;
        }
    }
}
```

Watch the log. When scores look right, change `shadow` → `enforce`.

---

## Examples

### 404 / scanner abuse

Bots constantly probe for `/.env`, `/.git`, `/wp-login.php`, `/wp-admin/`,
`/.aws`, `/phpinfo` and similar. The module has a built-in scanner-path table
(case-insensitive prefix match, no configuration needed) that scores those URIs
at **+50** immediately. A bot that keeps hitting 404s also accumulates error-rate
score (1 point per recorded error × `sentinel_weight_errrate`). Add honeypot
paths for anything extra you want to catch.

With default thresholds (`challenge=30 tarpit=60 block=80`) a scanner-path hit
already lands in the **tarpit band** on the first request (score 50). After 80+
errors the identity crosses into **block**.

```nginx
http {
    sentinel_zone reps:10m;

    server {
        listen 80;
        server_name example.com;

        sentinel on;
        sentinel_mode enforce;
        sentinel_zone reps:10m;

        # Built-in scanner paths (/.env /.git /wp-login /wp-admin /.aws /phpinfo)
        # are matched automatically at weight 50. No config needed.
        # Add your own decoy paths via sentinel_honeypot:
        sentinel_honeypot /xmlrpc.php /setup.php /config.php /.well-known/evil;

        # A bot that hits a honeypot scores 90 — straight to block band.
        sentinel_weight_honeypot 90;

        # Each 404 / 4xx error adds 1 point.  30 errors → challenge,
        # 60 → tarpit, 80 → block.  Weight can be raised if you see fast scans.
        sentinel_weight_errrate 1;

        # Once blocked, ban for 1 hour so retries don't make it past preaccess.
        sentinel_block_ttl 3600;

        location / {
            root /var/www/html;
        }
    }
}
```

**What happens on the first hit to `/wp-login.php`:**

| Signal | Score contribution |
|---|---|
| scanner_path (`/wp-login`) | +50 |
| *(no prior errors, no bot UA)* | +0 |
| **Total** | **50** → tarpit band |

The bot gets a slow garbage drip instead of a fast 404. If it keeps probing, the
error counter climbs and it eventually crosses into block, at which point
`sentinel_block_ttl` writes a 1-hour soft-ban so every subsequent request from
that IP is short-circuited without re-evaluation.

---

### Tarpitting AI scrapers

LLM crawlers and aggressive content scrapers usually send a recognisable bot UA
(weight 30 by default) and often hit pages rapidly (velocity signal). Combining
both puts them in the tarpit band without affecting real browsers.

```nginx
http {
    sentinel_zone reps:10m;
    sentinel_velocity_zone vzone:5m rate=60 window=10 block=1800;

    server {
        listen 80;
        server_name example.com;

        sentinel on;
        sentinel_mode enforce;
        sentinel_zone reps:10m;
        sentinel_velocity vzone;

        # Raise bot weight so bot-UA alone → tarpit (score 60).
        sentinel_weight_bot 60;

        # Velocity: >60 req in 10s → +30 on top.
        sentinel_weight_velocity 30;

        # Tarpit: slow drip of decoy links — the crawler follows them forever.
        sentinel_tarpit_maze on;
        sentinel_tarpit_delay 8000;      # 8 s between drip ticks
        sentinel_tarpit_bytes 2048;
        sentinel_tarpit_max_lifetime 120000;

        location / {
            root /var/www/html;
        }
    }
}
```

---

### Blocking malware C2 with the abuse.ch SSLBL JA3 feed

[abuse.ch SSLBL](https://sslbl.abuse.ch/blacklist/) publishes a curated list of
JA3 TLS fingerprints belonging to known malware / botnet C2 clients. These are
high-confidence: a real browser never matches one. The `ssl-fingerprint` module
exposes the client's JA3 MD5 as `$ssl_fingerprint_ja3_hash`; `sentinel_ja3`
scores a deny-list match at **+80** (default) — above the block threshold, so a
C2 client is blocked on the first request.

`tools/sslbl-ja3-fetch.sh` downloads the feed and generates an nginx include:

```bash
# Daily cron — only reload nginx when the feed actually changed (exit 10 = no change)
0 4 * * *  /opt/.../tools/sslbl-ja3-fetch.sh -o /etc/nginx/sentinel-ja3-deny.conf \
             && systemctl reload nginx
```

The generated `/etc/nginx/sentinel-ja3-deny.conf` is a single
`sentinel_ja3_deny <hash> <hash> ...;` statement. Wire it up:

```nginx
http {
    server {
        listen 443 ssl;
        ssl_fingerprint on;                       # libnginx-mod-ssl-fingerprint

        sentinel on;
        sentinel_mode enforce;
        sentinel_zone main:10m;

        sentinel_ja3 $ssl_fingerprint_ja3_hash;   # client's JA3 MD5
        include /etc/nginx/sentinel-ja3-deny.conf; # SSLBL deny list (generated)
        sentinel_weight_ja3 80;                    # SSLBL = malware/C2 → block band

        location / {
            root /var/www/html;
        }
    }
}
```

A C2 client whose JA3 is on the SSLBL list scores 80 → block on the first hit.
Everything else is unaffected (empty/missing JA3 fails open, contributes 0).

> JA3 (MD5) is the older fingerprint; JA4 is its modern successor. They catch
> different populations — JA3's value here is specifically the SSLBL malware
> feed. Run both (`sentinel_ja3` + `sentinel_ja4`) for layered coverage.

### Full defense stack (CrowdSec + all signals)

```nginx
http {
    resolver 1.1.1.1 8.8.8.8 valid=300s;   # needed for FCrDNS

    # Shared-memory zones
    sentinel_zone          main:20m;
    sentinel_velocity_zone vzone:5m rate=100 window=10 block=3600;
    sentinel_crowdsec_zone cs:4m;
    sentinel_fcrdns_zone   fcdns:1m;

    # GeoIP2 ASN (from libnginx-mod-http-geoip2)
    geoip2 /usr/share/GeoIP/GeoLite2-ASN.mmdb {
        $geoip2_asn autonomous_system_number;
    }

    server {
        listen 443 ssl;
        ssl_fingerprint on;              # libnginx-mod-ssl-fingerprint

        sentinel on;
        sentinel_mode enforce;
        sentinel_zone main:20m;
        sentinel_threshold challenge=30 tarpit=60 block=80;

        # Signals
        sentinel_velocity vzone;
        sentinel_honeypot /wp-login.php /xmlrpc.php /.env /.git /.aws /actuator;
        sentinel_asn $geoip2_asn;
        sentinel_datacenter_asn 16509 14618 15169 14061 16276;  # AWS/GCP/DO/OVH
        sentinel_ja4 $ssl_fingerprint_ja4;
        sentinel_ja4_deny t13d1516h2_8daaf6152771_b186095e22b6;
        sentinel_fcrdns fcdns;
        sentinel_fcrdns_verify_suffix .googlebot.com .google.com .search.msn.com;

        # CrowdSec feed (loaded out-of-band by worker timer)
        sentinel_crowdsec_zone   cs:4m;
        sentinel_crowdsec_feed   /var/lib/crowdsec/sentinel-feed.txt;
        sentinel_crowdsec_interval 10;

        # Actions
        sentinel_block_status 403;
        sentinel_block_ttl    3600;
        sentinel_tarpit_maze  on;
        sentinel_pow          on;
        sentinel_pow_secret   "generate-with-openssl-rand-hex-32";
        sentinel_pow_difficulty 18;

        location / {
            root /var/www/html;
        }

        # Stricter admin path
        location /admin/ {
            sentinel_threshold challenge=10 tarpit=40 block=60;
            sentinel_weight_bot 100;
            root /var/www/html;
        }

        # Prometheus scrape endpoint
        location = /sentinel-status {
            sentinel_status;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

---

## Complete directive reference

One block with every directive, grouped by function. Defaults shown in comments.

```nginx
http {
    # ── Shared-memory zones ────────────────────────────────────────────────
    # Identity store (error-rate, soft-ban, CrowdSec table)
    sentinel_zone NAME:SIZE;             # e.g. main:20m  (required for errrate/softban)

    # Velocity (request-rate) counter — separate zone
    sentinel_velocity_zone NAME:SIZE
        [rate=100]                       # max requests per window before flagged
        [window=10]                      # sliding window, seconds
        [block=3600];                    # how long the flag sticks, seconds

    # CrowdSec ban table (also used by Redis pull)
    sentinel_crowdsec_zone NAME:SIZE;    # e.g. cs:4m

    # FCrDNS verdict cache
    sentinel_fcrdns_zone NAME:SIZE;      # e.g. fcdns:1m

    # ── Core ───────────────────────────────────────────────────────────────
    sentinel on|off;                     # default: off
    sentinel_mode enforce|shadow;        # default: enforce
    sentinel_fail open|closed;           # on zone/lookup error; default: open
    sentinel_zone NAME:SIZE;             # bind the errrate zone (also http context)
    sentinel_threshold
        challenge=30                     # score ≥ this → PoW page (if enabled)
        tarpit=60                        # score ≥ this → tarpit / throttle / shield
        block=80;                        # score ≥ this → 403 / 444

    # ── Score weights ──────────────────────────────────────────────────────
    # Set 0 to disable a signal.
    sentinel_weight_errrate   1;         # per error event in the sliding window
    sentinel_weight_blocked   100;       # identity has an active soft-ban
    sentinel_weight_scanner   50;        # built-in scanner-path hit
    sentinel_weight_bot       30;        # heuristic bot User-Agent
    sentinel_weight_header    25;        # malformed / anomalous request headers
    sentinel_weight_honeypot  90;        # operator-defined decoy path hit
    sentinel_weight_velocity  30;        # per-identity request rate exceeded
    sentinel_weight_asn       35;        # client ASN in the flagged list
    sentinel_weight_coherence 40;        # browser UA but bare HTTP client shape
    sentinel_weight_ja3       80;        # JA3 (TLS) fp on deny list (SSLBL malware/C2)
    sentinel_weight_ja4       50;        # JA4 (TLS) fp on deny list
    sentinel_weight_ja4t      45;        # JA4T (TCP) fp on deny list
    sentinel_weight_crowdsec  100;       # CrowdSec ban table hit (action-tiered)

    # ── Signals ────────────────────────────────────────────────────────────

    # Velocity (bind a declared zone to this location/server/http)
    sentinel_velocity ZONE_NAME;

    # Honeypot decoy paths (prefix match, case-sensitive, no regex)
    sentinel_honeypot /wp-login.php /.env /.git /actuator [/more ...];

    # Trusted CIDR allowlist (score short-circuits to 0; CrowdSec ban still wins)
    sentinel_allowlist 192.0.2.0/24 10.0.0.0/8 203.0.113.42;

    # Datacenter / abuse ASN (reads a geoip2 module variable — no DB in module)
    sentinel_asn $geoip2_asn;
    sentinel_datacenter_asn 16509 14618 15169 14061 16276;

    # JA3 TLS fingerprint deny-list (reads ssl-fingerprint module variable)
    # Pairs with the abuse.ch SSLBL malware/C2 JA3 feed (see below).
    sentinel_ja3 $ssl_fingerprint_ja3_hash;
    sentinel_ja3_deny e7d705a3286e19ea42f587b344ee6865;
    # ... or generated from the SSLBL feed:
    #   include /etc/nginx/sentinel-ja3-deny.conf;

    # JA4 TLS fingerprint deny-list (reads ssl-fingerprint module variable)
    sentinel_ja4 $ssl_fingerprint_ja4;
    sentinel_ja4_deny t13d1516h2_8daaf6152771_b186095e22b6
                      t13d1715h2_5b57614c22b0_3d5424432f57;

    # JA4T TCP fingerprint deny-list (reads PROXY-protocol TLV from edge LB)
    sentinel_ja4t $proxy_protocol_tlv_0xe0;
    sentinel_ja4t_deny t00nn0_0000_00000000;

    # FCrDNS — async forward-confirmed rDNS for self-declaring crawlers
    # (prevents UA spoofing bypassing known_good_ua short-circuit)
    resolver 1.1.1.1 8.8.8.8 valid=300s;    # required for async lookups
    sentinel_fcrdns ZONE_NAME;               # bind + enable
    sentinel_fcrdns_ttl 1h;                  # verdict cache lifetime
    sentinel_fcrdns_verify_suffix .googlebot.com .google.com .search.msn.com;

    # ── Actions — Block ────────────────────────────────────────────────────
    sentinel_block_status 403;               # 400–599, or 444 (drop connection)
    sentinel_block_ttl    3600;              # seconds; 0 = off (no soft-ban)

    # ── Actions — Tarpit ───────────────────────────────────────────────────
    sentinel_tarpit_max_conns   256;         # global concurrent tarpit cap; 0 = disable
    sentinel_tarpit_delay       5000;        # ms between drip ticks (100–60000)
    sentinel_tarpit_bytes       1024;        # total bytes dripped (1–65536)
    sentinel_tarpit_max_lifetime 30000;      # hard ceiling ms (1000–600000)
    sentinel_tarpit_maze on|off;             # drip decoy crawl links instead of whitespace

    # ── Actions — Throttle (instead of tarpit) ─────────────────────────────
    # On tarpit-band verdict: serve normally but cap egress rate.
    # Mutually exclusive with tarpit (throttle wins).
    sentinel_throttle_rate 32k;              # e.g. 32k, 0 = off

    # ── Actions — Origin shield (instead of tarpit) ────────────────────────
    # On tarpit-band verdict: let request through, raise $sentinel_shield=1.
    # Operator wires proxy_no_cache / proxy_cache_use_stale in the proxy block.
    sentinel_shield on|off;                  # default: off

    # ── Actions — Proof-of-work challenge ──────────────────────────────────
    sentinel_pow           on|off;           # default: off
    sentinel_pow_secret    "long-random-string";   # required; generate with:
                                                   #   openssl rand -hex 32
    sentinel_pow_difficulty 16;              # leading zero bits (1–32)
    sentinel_pow_ttl        3600;            # challenge + cookie lifetime (s)

    # ── CrowdSec feed (out-of-band, worker timer) ──────────────────────────
    sentinel_crowdsec_zone      cs:4m;       # bind the ban table
    sentinel_crowdsec_feed      /path/to/feed.txt;
    sentinel_crowdsec_interval  10;          # reload tick seconds (1–3600)
    sentinel_crowdsec_default_ttl  3600;     # TTL for entries with expiry=0
    sentinel_crowdsec_stale_after  600;      # warn if feed is this old (s)
    sentinel_crowdsec_max_bytes    16m;      # feed size cap

    # ── Redis multi-box shared ban state (out-of-band, worker timer) ───────
    # Requires sentinel_crowdsec_zone.  Links libhiredis.
    sentinel_redis          10.0.0.9:6379;   # host[:port]; enables the feature
    sentinel_redis_password "${REDIS_PW}";   # optional AUTH
    sentinel_redis_prefix   sentinel;        # key namespace  (<prefix>:ban:<ip>)
    sentinel_redis_interval 10;              # pull + flush tick (1–3600 s)
    sentinel_redis_ttl      3600;            # TTL on pushed ban keys (60–86400 s)

    # ── CrowdSec decision feedback sink (out-of-band, worker timer) ────────
    sentinel_cs_sink_path     /var/lib/crowdsec/sentinel-decisions.json;
    sentinel_cs_sink_interval 10;            # drain/rewrite tick (1–3600 s)
    sentinel_cs_sink_ttl      3600;          # duration field in decision (60–86400 s)
    sentinel_cs_sink_scenario sentinel/http-abuse;

    # ── Prometheus metrics ─────────────────────────────────────────────────
    # Put sentinel_status; in a location{} block.  Protect with allow/deny.
    # (shown in server{} block below for clarity)

    server {
        listen 443 ssl proxy_protocol;      # proxy_protocol only if using JA4T

        location / {
            sentinel on;
            sentinel_mode enforce;
            # ... directives above are inherited from http{}/server{} ...
        }

        location = /sentinel-status {
            sentinel_status;               # content handler — no sentinel eval here
            allow 127.0.0.1;
            deny  all;
        }

        # Origin-shield wiring (when sentinel_shield on)
        location /proxied/ {
            sentinel on;
            sentinel_mode enforce;
            sentinel_shield on;

            proxy_pass http://backend;
            proxy_cache mycache;
            proxy_cache_use_stale updating error timeout;
            proxy_cache_background_update on;
            proxy_no_cache     $sentinel_shield;  # don't refresh cache for shielded clients
            proxy_cache_bypass "";
        }
    }
}
```

---

## Scoring

```
score = (weight_errrate × errrate_count)
      + (weight_blocked  × 1_if_softbanned)
      + (weight_scanner  × 1_if_scanner_path)
      + (weight_bot      × 1_if_bot_ua)
      + (weight_header   × 1_if_header_anomaly)
      + (weight_honeypot × 1_if_honeypot)
      + (weight_velocity × 1_if_rate_exceeded)
      + (weight_asn      × 1_if_datacenter_asn)
      + (weight_coherence × 1_if_ua_incoherent)
      + (weight_ja3      × 1_if_ja3_denied)
      + (weight_ja4      × 1_if_ja4_denied)
      + (weight_ja4t     × 1_if_ja4t_denied)
      + (weight_crowdsec × tier_factor × 1_if_crowdsec_hit)
```

**CrowdSec action tiers:** `ban` → full weight (1.0); `captcha` → block band; `throttle` → tarpit band. The tier maps the CrowdSec decision to the equivalent verdict without separate weights.

**Short-circuit:** a UA matching the known-good crawler list (Googlebot, Bingbot…) forces score → 0 **unless** there is a CrowdSec hit. FCrDNS spoofed verdict suppresses this short-circuit.

**Allowlist:** a client IP matching `sentinel_allowlist` forces score → 0, also unless there is a CrowdSec hit.

**Score cap:** 100 000 (prevents integer overflow from extreme errrate × weight products).

### Built-in scanner paths

The following URI prefixes are matched **automatically** (case-insensitive, no config needed). Hits add `sentinel_weight_scanner` (default 50).

| Prefix | What it catches |
|---|---|
| `/.env` | Laravel / generic env files |
| `/.git` | Exposed git repositories |
| `/wp-login` | WordPress login probing |
| `/wp-admin` | WordPress admin probing |
| `/.aws` | AWS credential files |
| `/phpinfo` | PHP info page probing |

Use `sentinel_honeypot` for anything else (custom decoys, `/xmlrpc.php`, `/actuator`, etc.).

### Signal reference

| Signal | Variable | Default weight | Triggered by |
|---|---|---|---|
| Error burst | `$sentinel_errrate` | ×1/error | HTTP 4xx/5xx burst in sliding window |
| Soft-ban | — | 100 flat | `sentinel_block_ttl` wrote a ban for this IP |
| Scanner path | `$sentinel_scanner` | 50 | Built-in prefix table (see above) |
| Bot UA | `$sentinel_bot` | 30 | Heuristic bot User-Agent match |
| Header anomaly | `$sentinel_header_anomaly` | 25 | HTTP/1.1 without Host; CL+TE; dup Host; no Accept+UA |
| Honeypot | `$sentinel_honeypot` | 90 | `sentinel_honeypot` prefix match |
| Velocity | `$sentinel_velocity` | 30 | Per-identity rate exceeded in velocity zone |
| ASN | `$sentinel_asn` | 35 | Client ASN in `sentinel_datacenter_asn` list |
| UA coherence | `$sentinel_coherence` | 40 | Browser UA + bare HTTP client headers |
| JA3 (TLS) | `$sentinel_ja3` | 80 | TLS fingerprint on `sentinel_ja3_deny` list (abuse.ch SSLBL malware/C2) |
| JA4 (TLS) | `$sentinel_ja4` | 50 | TLS fingerprint on `sentinel_ja4_deny` list |
| JA4T (TCP) | `$sentinel_ja4t` | 45 | TCP fingerprint on `sentinel_ja4t_deny` list |
| CrowdSec | `$sentinel_crowdsec` | 100 | IP in CrowdSec ban table |
| FCrDNS | `$sentinel_fcrdns` | — | `spoofed` suppresses known_good_ua only |
| Allowlist | `$sentinel_allowlist` | — | Score → 0 (not a weight) |

---

## Variables and structured decision log

All variables are `NOCACHEABLE` — they resolve to the value computed in PREACCESS.

| Variable | Values | Meaning |
|---|---|---|
| `$sentinel_score` | integer | Final weighted score |
| `$sentinel_verdict` | `allow/challenge/tarpit/block` | Verdict |
| `$sentinel_ja4h` | 24 hex chars | JA4H request fingerprint (in-module) |
| `$sentinel_errrate` | integer | Error events in the sliding window |
| `$sentinel_scanner` | `0/1` | Scanner-path hit |
| `$sentinel_bot` | `0/1` | Bot UA |
| `$sentinel_header_anomaly` | `0/1` | Header anomaly |
| `$sentinel_honeypot` | `0/1` | Honeypot path hit |
| `$sentinel_velocity` | `0/1` | Velocity exceeded |
| `$sentinel_asn` | `0/1` | Flagged ASN |
| `$sentinel_coherence` | `0/1` | UA/header incoherence |
| `$sentinel_ja3` | `0/1` | JA3 deny-list hit (SSLBL malware/C2) |
| `$sentinel_ja4` | `0/1` | JA4 deny-list hit |
| `$sentinel_ja4t` | `0/1` | JA4T deny-list hit |
| `$sentinel_fcrdns` | `verified/spoofed/pending` | FCrDNS verdict |
| `$sentinel_allowlist` | `0/1` | IP in trusted CIDR |
| `$sentinel_crowdsec` | `0/1` | CrowdSec ban table hit |
| `$sentinel_crowdsec_action` | `none/ban/captcha/throttle` | CrowdSec decision type |
| `$sentinel_throttled` | `0/1` | Throttle action applied |
| `$sentinel_shield` | `0/1` | Origin-shield action applied |
| `$sentinel_pow` | `off/challenge/verified` | PoW status |

### JSON decision log

```nginx
log_format sentinel_json escape=json
    '{"ts":"$time_iso8601","ip":"$remote_addr","uri":"$request_uri",'
    '"score":$sentinel_score,"verdict":"$sentinel_verdict",'
    '"ja4h":"$sentinel_ja4h","errrate":$sentinel_errrate,'
    '"scanner":$sentinel_scanner,"bot":$sentinel_bot,'
    '"header":$sentinel_header_anomaly,"honeypot":$sentinel_honeypot,'
    '"velocity":$sentinel_velocity,"asn":$sentinel_asn,'
    '"coherence":$sentinel_coherence,'
    '"ja4":$sentinel_ja4,"ja4t":$sentinel_ja4t,'
    '"fcrdns":"$sentinel_fcrdns","allowlist":$sentinel_allowlist,'
    '"crowdsec":$sentinel_crowdsec,"crowdsec_action":"$sentinel_crowdsec_action",'
    '"throttled":$sentinel_throttled}';

server {
    sentinel on;
    sentinel_mode shadow;       # observe without blocking
    access_log /var/log/nginx/sentinel.jsonl sentinel_json;
}
```

---

## Per-route policy

All `sentinel_*` directives are valid in `http`, `server`, and `location` context
and follow standard nginx inheritance — a location overrides what it sets,
inherits the rest. Zone declarations (`sentinel_zone`, `sentinel_velocity_zone`)
are `http`-context only.

```nginx
server {
    sentinel on;
    sentinel_mode enforce;
    sentinel_threshold challenge=30 tarpit=60 block=80;

    location /admin/ {
        # Strict: bot alone triggers block
        sentinel_threshold challenge=10 tarpit=40 block=60;
        sentinel_weight_bot 100;
    }

    location = /healthz {
        # Health probe: effectively disabled (thresholds out of reach)
        sentinel_threshold challenge=900 tarpit=950 block=990;
        sentinel_weight_bot 0;
    }

    location /api/ {
        sentinel_mode shadow;   # score but never act
    }

    location /internal/cb {
        sentinel off;
    }
}
```

---

## Prometheus metrics

`sentinel_status;` in a location block emits Prometheus text exposition
(`text/plain; version=0.0.4`). Counters are lock-free atomics in the same shm
as the tarpit; they are never blocking, never failing. Protect the endpoint:

```nginx
location = /sentinel-status {
    sentinel_status;
    allow 127.0.0.1;
    deny  all;
}
```

| Metric | Type | Labels |
|---|---|---|
| `sentinel_requests_total` | counter | — |
| `sentinel_verdict_total` | counter | `v=allow\|challenge\|tarpit\|block` |
| `sentinel_signal_total` | counter | `s=errrate\|blocked\|scanner\|bot\|header\|honeypot\|velocity\|asn\|coherence\|crowdsec\|ja3\|ja4\|ja4t` |
| `sentinel_shadow_total` | counter | — |
| `sentinel_tarpit_active` | gauge | — |

Example PromQL: `rate(sentinel_verdict_total{v="block"}[5m])`

---

## Design principles

- **No network in the request path.** Per-request work is shared-memory lookups only. CrowdSec and Redis I/O happen on worker timers.
- **Fail-open by default.** A zone error, missing variable, or absent module logs and allows. `sentinel_fail closed` flips it.
- **Bounded tarpit.** Global concurrent-connection cap, fixed drip buffers, hard max lifetime. Cannot become a self-DoS.
- **Self-contained.** Every signal is computed in-module. No runtime dependency on sibling modules (geoip2, ssl-fingerprint, proxy-protocol are opt-in sources, not hard deps).
- **Shadow-first.** The module is designed to be run in `shadow` mode first, with the full JSON log, before any `enforce` is switched on.

---

## See also

- Sibling modules:
  - [nginx-error-abuse-module](https://github.com/eilandert/nginx-error-abuse-module) — predecessor; sentinel absorbs its error-rate logic
  - [nginx-autocert-module](https://github.com/eilandert/nginx-autocert-module)
  - [nginx-strip-filter-module](https://github.com/eilandert/nginx-strip-filter-module)
  - [nginx-cache-turbo-module](https://github.com/eilandert/nginx-cache-turbo-module)
  - [nginx-label-autoconf-module](https://github.com/eilandert/nginx-label-autoconf-module)
- [Pitch / design overview](https://deb.myguard.nl/pitch-ngx_http_sentinel-unified-client-reputation-tarpit-module/)
- Package: [nginx-modules stack](https://deb.myguard.nl/nginx-modules/) · [angie-modules stack](https://deb.myguard.nl/angie-modules-optimized-extended/)

## Development

Feature branch off `master` → PR to `master` → remote CI green → squash-merge.
Build/test standalone: `bash tools/ci-build.sh`. Valgrind + fuzz run monthly (remote cron) and weekly (local cron).

## License

MIT — see [LICENSE](LICENSE).
