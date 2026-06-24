/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel.h — shared structs, constants, and signal-function prototypes
 *              for ngx_http_sentinel_module.
 */

#ifndef SENTINEL_H
#define SENTINEL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/sha.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/* SEC-3: identity in shared memory = SHA-256 digest of $binary_remote_addr. */
#define NGX_SENTINEL_DIGEST_LEN        SHA256_DIGEST_LENGTH   /* 32 */
#define NGX_SENTINEL_RAW_LOG_MAX       256

/* JA4H: hex-encoded first 12 bytes of SHA-256 over canonical header string. */
#define NGX_SENTINEL_JA4H_BIN_LEN     12
#define NGX_SENTINEL_JA4H_HEX_LEN     (NGX_SENTINEL_JA4H_BIN_LEN * 2)

/* Canonical-string buffer for JA4H computation (fixed stack). */
#define NGX_SENTINEL_JA4H_CANLEN      4096

/* Max scanner path prefixes. */
#define NGX_SENTINEL_SCANNER_PATHS_MAX 16

/* Sliding-window circular buffer: max error events tracked per identity. */
#define NGX_SENTINEL_MAX_WINDOW_EVENTS 64

/* LRU expire batch size (nodes evicted per lookup). */
#define NGX_SENTINEL_EXPIRE_BATCH     2

/* Zone log context label max. */
#define NGX_SENTINEL_ZONE_CTX_MAX     64

/* Default directive values. */
#define NGX_SENTINEL_DEFAULT_INTERVAL  300   /* seconds */
#define NGX_SENTINEL_DEFAULT_BLOCK     3600  /* seconds */
#define NGX_SENTINEL_DEFAULT_THRESH_CH 30
#define NGX_SENTINEL_DEFAULT_THRESH_TP 60
#define NGX_SENTINEL_DEFAULT_THRESH_BK 80

/* HTTP status returned for a BLOCK verdict in enforce mode.
 * Special value 444 = drop the connection (NGX_HTTP_CLOSE). */
#define NGX_SENTINEL_DEFAULT_BLOCK_STATUS 403

/* Default score weights (tunable via sentinel_weight_* directives). */
#define NGX_SENTINEL_DEFAULT_W_ERRRATE 1     /* per error event in burst window */
#define NGX_SENTINEL_DEFAULT_W_BLOCKED 100   /* identity already blocked        */
#define NGX_SENTINEL_DEFAULT_W_SCANNER 50    /* scanner-path prefix hit         */
#define NGX_SENTINEL_DEFAULT_W_BOT     30    /* heuristic bot user-agent        */
#define NGX_SENTINEL_DEFAULT_W_HEADER  25    /* request-header anomaly          */
#define NGX_SENTINEL_DEFAULT_W_HONEYPOT 90   /* decoy-URL (honeypot) hit        */
#define NGX_SENTINEL_DEFAULT_W_VELOCITY 30   /* request-rate abuse: meaningful but below scanner/honeypot */
#define NGX_SENTINEL_DEFAULT_W_ASN     35    /* request from a flagged datacenter/abuse ASN */
#define NGX_SENTINEL_DEFAULT_W_COHERENCE 40  /* UA claims a browser but request shape disagrees */
#define NGX_SENTINEL_VELOCITY_DEFAULT_THRESHOLD 100  /* requests per window */
#define NGX_SENTINEL_VELOCITY_DEFAULT_WINDOW    10   /* seconds */

/* Hard ceiling for the computed score (overflow/abuse guard). */
#define NGX_SENTINEL_SCORE_MAX         100000

/* -------------------------------------------------------------------------
 * Phase 3 — CrowdSec decision-feed constants
 * ---------------------------------------------------------------------- */

/* CrowdSec node action tiers (stored in node->cs_action). */
#define NGX_SENTINEL_CS_NONE      0
#define NGX_SENTINEL_CS_BAN       1
#define NGX_SENTINEL_CS_CAPTCHA   2
#define NGX_SENTINEL_CS_THROTTLE  3

/* -------------------------------------------------------------------------
 * FCrDNS (Forward-Confirmed reverse DNS) verdict tiers.
 *
 * Stored in the fcrdns verdict-cache node->cs_action field (reuses the
 * crowdsec node shape). blocked_until is repurposed as the cache-entry expiry
 * (now + fcrdns_ttl): once it lapses the verdict is re-resolved.
 * ---------------------------------------------------------------------- */
#define NGX_SENTINEL_FCRDNS_PENDING   0  /* no cached verdict (or expired)     */
#define NGX_SENTINEL_FCRDNS_VERIFIED  1  /* PTR + forward both confirmed the IP */
#define NGX_SENTINEL_FCRDNS_FAILED    2  /* PTR/forward mismatch or lookup fail */

/* Default cache TTL for an FCrDNS verdict (seconds). */
#define NGX_SENTINEL_FCRDNS_DEFAULT_TTL   3600
/* Resolver timeout per lookup (ms). */
#define NGX_SENTINEL_FCRDNS_RESOLVE_MSEC  5000

/* Refresh tick (seconds). */
#define NGX_SENTINEL_CROWDSEC_DEFAULT_INTERVAL    10
#define NGX_SENTINEL_CROWDSEC_MIN_INTERVAL        1
#define NGX_SENTINEL_CROWDSEC_MAX_INTERVAL        3600

/* TTL applied to lines whose expiry epoch == 0. */
#define NGX_SENTINEL_CROWDSEC_DEFAULT_TTL         3600
#define NGX_SENTINEL_CROWDSEC_MIN_TTL             60
#define NGX_SENTINEL_CROWDSEC_MAX_TTL             86400

/* Feed-age threshold => stale; also LRU age-out interval. */
#define NGX_SENTINEL_CROWDSEC_DEFAULT_STALE       600
#define NGX_SENTINEL_CROWDSEC_MIN_STALE           30
#define NGX_SENTINEL_CROWDSEC_MAX_STALE           86400

/* Feed size cap (bytes). */
#define NGX_SENTINEL_CROWDSEC_DEFAULT_MAXBYTES    (16 * 1024 * 1024)
#define NGX_SENTINEL_CROWDSEC_MAX_MAXBYTES        (64 * 1024 * 1024)

/* Default score weight added for a crowdsec ban. */
#define NGX_SENTINEL_DEFAULT_W_CROWDSEC           100

/* Parse batch (lines) — bound the work per pass; single-pass for v1, but the
 * constant documents the intended chunk size. */
#define NGX_SENTINEL_FEED_PARSE_BATCH             4096

/* Apply batch (nodes per locked critical section during the swap). */
#define NGX_SENTINEL_FEED_APPLY_BATCH             256

/* Max acceptable fraction of malformed lines before the whole file is rejected
 * (expressed as 1/N: reject if malformed*4 > total, i.e. > 25%). */
#define NGX_SENTINEL_FEED_MALFORMED_DENOM         4

/* Feed header sentinel (first line). */
#define NGX_SENTINEL_FEED_HEADER  "# sentinel-crowdsec-feed v1"

/* -------------------------------------------------------------------------
 * Phase 2 — Tarpit constants
 * ---------------------------------------------------------------------- */

/* Hard upper bound for tarpit_max_lifetime (ms). */
#define NGX_SENTINEL_TARPIT_MAX_MSEC   600000   /* 10 minutes */

/* Size of the process-global static drip buffer. Also the upper bound for
 * tarpit_bytes (per spec: same value). */
#define NGX_SENTINEL_TARPIT_TICK_MAX   65536

/* Bytes emitted per drip tick (small constant; keeps individual writes tiny). */
#define NGX_SENTINEL_TARPIT_TICK_BYTES 32

/* Per-tick maze fragment: one decoy <a href> line. Sized to comfortably hold
 * the longest fragment sentinel_tarpit emits ("<a href=\"/" + 16 hex + "/\">x</a>\n"). */
#define NGX_SENTINEL_TARPIT_MAZE_FRAG  64

/* -------------------------------------------------------------------------
 * Verdict enum
 * ---------------------------------------------------------------------- */

typedef enum {
    NGX_SENTINEL_VERDICT_ALLOW     = 0,
    NGX_SENTINEL_VERDICT_CHALLENGE = 1,
    NGX_SENTINEL_VERDICT_TARPIT    = 2,
    NGX_SENTINEL_VERDICT_BLOCK     = 3
} ngx_sentinel_verdict_e;

/* $sentinel_pow states (PoW challenge action). */
typedef enum {
    NGX_SENTINEL_POW_OFF       = 0,  /* disabled / no secret / fail-open */
    NGX_SENTINEL_POW_VERIFIED  = 1,  /* valid cookie or solution accepted */
    NGX_SENTINEL_POW_CHALLENGE = 2   /* challenge page served this request */
} ngx_sentinel_pow_state_e;

/* -------------------------------------------------------------------------
 * Shared-memory node (rbtree + LRU queue entry per identity)
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_rbtree_node_t  node;
    ngx_queue_t        queue;
    time_t             blocked_until;
    time_t             last_seen;
    ngx_uint_t         event_head;
    ngx_uint_t         event_count;
    ngx_uint_t         cs_generation; /* crowdsec mark-and-sweep stamp (0 else) */
    u_char             cs_action;     /* crowdsec action tier (0 for errrate)   */
    u_short            key_len;
    u_char             data[1];   /* key bytes then event timestamps (time_t[]) */
} ngx_sentinel_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel_rb;
    ngx_queue_t        queue;
    ngx_uint_t         cs_generation;  /* crowdsec swap generation (under lock) */
} ngx_sentinel_shctx_t;

/* -------------------------------------------------------------------------
 * Zone descriptor (main conf, one per sentinel_zone directive)
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_str_t              name;
    ngx_shm_zone_t        *shm_zone;
    ngx_sentinel_shctx_t  *sh;
    ngx_slab_pool_t       *shpool;
    time_t                 interval;
    time_t                 block;
    ngx_uint_t             threshold;
} ngx_sentinel_zone_t;

/* -------------------------------------------------------------------------
 * Signal inputs gathered per request
 * ---------------------------------------------------------------------- */

typedef struct {
    /* JA4H: hex string computed by sentinel_ja4h.c */
    u_char    ja4h[NGX_SENTINEL_JA4H_HEX_LEN + 1];  /* NUL-terminated */

    /* Error-rate: burst count from sliding window (0 = unknown/zone missing) */
    ngx_uint_t  errrate_count;
    ngx_flag_t  errrate_blocked;   /* 1 if identity is currently blocked */

    /* Scanner-path: did URI match a known scanner prefix? */
    ngx_flag_t  scanner_path;

    /* Bot-UA: heuristic bot-UA signal */
    ngx_flag_t  bot_ua;
    ngx_flag_t  known_good_ua;     /* search-engine UA SUBSTRING only — NOT
                                    * RDNS-verified yet, spoofable; gated on
                                    * !crowdsec_hit in sentinel_score_compute */

    /* FCrDNS: forward-confirmed reverse-DNS verdict for the client IP, looked
     * up ONLY when known_good_ua is set (confirm the crawler UA claim).
     *   verified=1 → the known_good_ua short-circuit is trustworthy.
     *   spoofed=1  → PTR/forward disproved the claim; DO NOT honor known_good_ua.
     *   both 0     → no cached verdict yet (pending/disabled) → fail-open:
     *                known_good_ua keeps its legacy (documented-spoofable)
     *                behavior this request; the async lookup settles the cache. */
    ngx_flag_t  fcrdns_verified;
    ngx_flag_t  fcrdns_spoofed;

    /* Header-anomaly: suspicious/malformed request headers */
    ngx_flag_t  header_anomaly;

    /* Honeypot: request URI matched a decoy-path prefix */
    ngx_flag_t  honeypot;

    /* Velocity: request rate exceeded the configured threshold */
    ngx_flag_t  velocity_exceeded;

    /* ASN: client's ASN (from an operator-supplied geoip2 variable) matched
     * the operator's flagged datacenter/abuse-ASN list */
    ngx_flag_t  datacenter_asn;

    /* Coherence: UA claims a mainstream browser family but the request lacks
     * the header shape every real instance of that family sends (no Accept /
     * Accept-Language / gzip Accept-Encoding, or pre-HTTP/1.1) */
    ngx_flag_t  ua_incoherent;

    /* Allowlist: client IP matched an operator-trusted CIDR (forces score 0,
     * unless a CrowdSec ban is present — see sentinel_score.c) */
    ngx_flag_t  allowlisted;

    /* CrowdSec: IP present + unexpired in the crowdsec ban table */
    ngx_flag_t  crowdsec_hit;
    u_char      crowdsec_action;   /* NGX_SENTINEL_CS_* — verdict/score tiering */
} ngx_sentinel_inputs_t;

/* -------------------------------------------------------------------------
 * Per-request context
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_sentinel_inputs_t   inputs;

    ngx_int_t               score;
    ngx_sentinel_verdict_e  verdict;

    /* Cached variable strings (allocated from request pool once, then reused) */
    ngx_str_t               var_score;
    ngx_str_t               var_verdict;
    ngx_str_t               var_ja4h;

    unsigned                computed:1;  /* signals already gathered */
    unsigned                throttled:1; /* throttle action applied this request */
    unsigned                shielded:1;  /* origin-shield action applied this request */
    unsigned                pow_state:2; /* ngx_sentinel_pow_state_e */
} ngx_sentinel_ctx_t;

/* -------------------------------------------------------------------------
 * Threshold config (parsed from sentinel_threshold directive)
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_int_t  challenge;
    ngx_int_t  tarpit;
    ngx_int_t  block;
} ngx_sentinel_threshold_t;

/* -------------------------------------------------------------------------
 * Score weights (parsed from sentinel_weight_* directives)
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_int_t  errrate;   /* multiplied by errrate_count */
    ngx_int_t  blocked;   /* added once if errrate_blocked */
    ngx_int_t  scanner;   /* added once if scanner_path    */
    ngx_int_t  bot;       /* added once if bot_ua          */
    ngx_int_t  header;    /* added once if header_anomaly  */
    ngx_int_t  honeypot;  /* added once if honeypot        */
    ngx_int_t  velocity;  /* added once if velocity_exceeded */
    ngx_int_t  asn;       /* added once if datacenter_asn      */
    ngx_int_t  coherence; /* added once if ua_incoherent       */
    ngx_int_t  crowdsec;  /* base weight for a crowdsec ban hit (tiered) */
} ngx_sentinel_weights_t;

/* -------------------------------------------------------------------------
 * Module configurations
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_array_t   zones;        /* ngx_sentinel_zone_t[] (errrate)                  */
    ngx_array_t   cs_zones;     /* ngx_sentinel_zone_t[] (crowdsec, Phase 3)        */
    ngx_array_t   vel_zones;     /* ngx_sentinel_zone_t[] (velocity)             */
    ngx_array_t   fcrdns_zones;  /* ngx_sentinel_zone_t[] (FCrDNS verdict cache) */
    ngx_atomic_t *tarpit_conns; /* per-worker sub-counters [NGX_MAX_PROCESSES]      */
                                /* allocated in dedicated shm at sentinel_zone init  */
} ngx_sentinel_main_conf_t;

typedef struct {
    ngx_flag_t               enabled;   /* sentinel on|off */
    ngx_flag_t               shadow;    /* 1=shadow, 0=enforce */
    ngx_flag_t               fail_open; /* 1=open (allow on error), 0=closed */
    ngx_sentinel_zone_t     *zone;      /* pointer into main conf zones array */
    ngx_sentinel_zone_t     *vel_zone;   /* velocity shm zone (NULL=off) */
    ngx_str_t                vel_zone_name;  /* pending name for sentinel_velocity bind */
    ngx_sentinel_threshold_t threshold;
    ngx_sentinel_weights_t   weights;

    /* Phase 3 — crowdsec decision feed */
    ngx_sentinel_zone_t     *cs_zone;             /* crowdsec shm zone          */
    ngx_str_t                cs_feed;             /* feed file path (empty=off) */
    ngx_int_t                cs_interval;         /* refresh tick (seconds)     */
    ngx_int_t                cs_default_ttl;      /* TTL for expiry==0 lines     */
    ngx_int_t                cs_stale_after;      /* stale threshold + LRU age   */
    size_t                   cs_max_bytes;        /* feed size cap (bytes)       */

    /* Honeypot: decoy URL path prefixes (empty = signal off) */
    ngx_array_t              decoy_paths;         /* ngx_str_t[] honeypot decoy
                                                   * path prefixes (empty = signal off) */

    /* Allowlist: operator-trusted client CIDRs (empty = signal off) */
    ngx_array_t              allow_cidrs;         /* ngx_cidr_t[] trusted ranges */

    /* ASN signal: operator points sentinel_asn at a geoip2 ASN variable; the
     * value is parsed as an unsigned ASN at request time and matched against
     * asn_list. No libmaxminddb link — the geoip2 module owns the DB. */
    ngx_http_complex_value_t *asn_source;         /* NULL = signal off */
    ngx_array_t              asn_list;            /* ngx_uint_t[] flagged ASNs */

    /* FCrDNS verify: when on, a known_good_ua (self-declared crawler) triggers
     * an async PTR + forward-confirm of the client IP. The verdict is cached in
     * fcrdns_zone for fcrdns_ttl seconds. fcrdns_suffixes optionally restricts
     * which resolved PTR names count as a real crawler (e.g. ".googlebot.com").
     * Empty suffix list = accept any forward-confirmed name.
     * Enabled iff fcrdns_zone is bound (sentinel_fcrdns <zone>;). */
    ngx_sentinel_zone_t     *fcrdns_zone;         /* verdict-cache shm zone     */
    ngx_str_t                fcrdns_zone_name;    /* pending name for bind      */
    ngx_int_t                fcrdns_ttl;          /* verdict cache TTL (seconds) */
    ngx_array_t              fcrdns_suffixes;     /* ngx_str_t[] allowed PTR suffixes */

    /* Phase 2 — tarpit parameters */
    ngx_int_t                tarpit_max_conns;    /* global cap across workers      */
    ngx_int_t                tarpit_delay;        /* ms between drip ticks          */
    ngx_int_t                tarpit_bytes;        /* total bytes to drip (cap)      */
    ngx_int_t                tarpit_max_lifetime; /* hard force-close ceiling (ms)  */
    /* Maze mode: drip HTML link-soup (decoy crawl links) instead of blank
     * padding, so a link-following bot keeps crawling into the tarpit
     * (0 = off, plain padding). */
    ngx_flag_t               tarpit_maze;

    /* BLOCK verdict enforcement: HTTP status to return (444 = close conn). */
    ngx_int_t                block_status;
    /* TTL soft-ban: on BLOCK in enforce mode, persist a self-ban in the
     * errrate zone for this many seconds (0 = off). */
    ngx_int_t                block_ttl;
    /* Throttle action: on a TARPIT-band verdict in enforce mode, instead of
     * dripping a trap, let the request proceed but cap egress at this many
     * bytes/sec via nginx's native r->limit_rate (0 = off, keep tarpit). */
    size_t                   throttle_rate;

    /* Origin-shield action: on a TARPIT-band verdict in enforce mode, instead
     * of tarpitting, let the request proceed but flag it ($sentinel_shield=1)
     * so the operator's proxy block serves cache-only / stale and spares the
     * origin. At PREACCESS the upstream/cache objects don't exist yet and
     * nginx's stale-cache directives take no variable, so the module only
     * raises the signal — the operator wires it (off = no shield). */
    ngx_flag_t               shield;

    /* PoW challenge: on a CHALLENGE-band verdict in enforce mode, serve a
     * stateless hashcash puzzle and gate access behind a signed cookie. */
    ngx_flag_t               pow_enabled;    /* sentinel_pow on|off */
    ngx_str_t                pow_secret;     /* HMAC key (empty = off) */
    ngx_int_t                pow_difficulty; /* required leading zero bits */
    ngx_int_t                pow_ttl;        /* challenge-bucket + cookie TTL (s) */
} ngx_sentinel_loc_conf_t;

/* -------------------------------------------------------------------------
 * Shared-memory API (sentinel_shm.c)
 * ---------------------------------------------------------------------- */

ngx_int_t sentinel_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

void sentinel_shm_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

/*
 * sentinel_shm_errrate_lookup — look up current burst count for `key` in `zone`.
 * Returns NGX_OK (not blocked), NGX_BUSY (blocked), NGX_ERROR (zone error).
 * count and blocked_until are output parameters.
 */
ngx_int_t sentinel_shm_errrate_lookup(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t now,
    ngx_uint_t *count, time_t *blocked_until);

/*
 * sentinel_shm_errrate_record — record one error event for `key`.
 * Called from the output filter (Phase 1b). Defined in sentinel_shm.c.
 */
ngx_int_t sentinel_shm_errrate_record(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t now,
    ngx_uint_t *count, time_t *blocked_until);

/*
 * sentinel_shm_softban_set — persist a self-ban (blocked_until = now + ttl)
 * for `key` in the errrate `zone`.  Used by the BLOCK verdict path when
 * sentinel_block_ttl > 0.  Returns NGX_OK / NGX_ERROR (caller fails open).
 */
ngx_int_t sentinel_shm_softban_set(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t now, time_t ttl);

/* -------------------------------------------------------------------------
 * JA4H API (sentinel_ja4h.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_ja4h_compute — fill `out` (NGX_SENTINEL_JA4H_HEX_LEN+1 bytes, NUL-
 * terminated) with the JA4H fingerprint for request `r`.
 * On any error: fills out with "000000000000000000000000" (fail-open).
 */
void sentinel_ja4h_compute(ngx_http_request_t *r, u_char *out);

/* -------------------------------------------------------------------------
 * Error-rate API (sentinel_errrate.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_errrate_signal — fill inputs->errrate_count and inputs->errrate_blocked
 * from the sentinel zone's shared-memory sliding window.
 * Also sets inputs->scanner_path if the request URI matches a known scanner prefix.
 * Fail-open: on any zone error, leaves errrate_count=0, errrate_blocked=0.
 */
void sentinel_errrate_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Bot-UA API (sentinel_botua.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_botua_signal — fill inputs->bot_ua and inputs->known_good_ua
 * from the User-Agent header using static substring tables (no regex).
 */
void sentinel_botua_signal(ngx_http_request_t *r,
    ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Header-anomaly API (sentinel_header.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_header_signal — fill inputs->header_anomaly (1 = suspicious
 * request headers) from r->headers_in. Pure-HTTP, no regex, no I/O.
 * Fail-open: NULL request -> header_anomaly = 0.
 */
void sentinel_header_signal(ngx_http_request_t *r,
    ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Honeypot API (sentinel_honeypot.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_honeypot_signal — set inputs->honeypot = 1 if r->uri matches
 * any prefix in lcf->decoy_paths (case-sensitive, no regex, no malloc).
 * Fail-open: NULL r / NULL lcf / empty decoy_paths → honeypot = 0.
 */
void sentinel_honeypot_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Allowlist API (sentinel_allowlist.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_allowlist_signal — set inputs->allowlisted = 1 if the client IP
 * matches any operator-configured CIDR in lcf->allow_cidrs (ngx_cidr_match,
 * no regex, no malloc, no network). Fail-open: NULL r / NULL lcf / empty
 * allow_cidrs / missing sockaddr → allowlisted = 0.
 */
void sentinel_allowlist_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Velocity API (sentinel_velocity.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_velocity_signal — check if the request rate for this identity
 * exceeds the configured threshold, set inputs->velocity_exceeded = 1 if so.
 * READ path only (preaccess). RECORD happens in the log handler on every
 * request. Fail-open: NULL args or no vel_zone → velocity_exceeded stays 0.
 */
void sentinel_velocity_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * ASN API (sentinel_asn.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_asn_signal — evaluate lcf->asn_source (an operator-supplied geoip2
 * ASN variable), parse it as an unsigned ASN, and set inputs->datacenter_asn = 1
 * if it matches any value in lcf->asn_list. No libmaxminddb link, no network,
 * no malloc in the request path. Fail-open: NULL args / no source / empty list /
 * empty or non-numeric value → datacenter_asn = 0.
 */
void sentinel_asn_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * FCrDNS API (sentinel_fcrdns.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_shm_fcrdns_get — read the cached FCrDNS verdict for `key`.
 * Returns NGX_SENTINEL_FCRDNS_{PENDING,VERIFIED,FAILED}. PENDING when no
 * (unexpired) entry exists. Takes the zone lock. Fail-open: zone error → PENDING.
 */
ngx_uint_t sentinel_shm_fcrdns_get(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t now);

/*
 * sentinel_shm_fcrdns_set — cache an FCrDNS verdict for `key` until now+ttl.
 * Takes the zone lock. Returns NGX_OK / NGX_ERROR (caller fails open).
 */
ngx_int_t sentinel_shm_fcrdns_set(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, ngx_uint_t verdict, time_t now, time_t ttl);

/*
 * sentinel_fcrdns_signal — when lcf->fcrdns is on AND inputs->known_good_ua is
 * set, read the cached verdict and set inputs->fcrdns_verified / fcrdns_spoofed.
 * On a PENDING/expired verdict it kicks off an async PTR+forward resolve (which
 * settles the cache for next time) and leaves both flags 0 (fail-open). Never
 * blocks the request on DNS. Fail-open on: fcrdns off, no known_good_ua, no
 * zone, no resolver, NULL args.
 */
void sentinel_fcrdns_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * Coherence API (sentinel_coherence.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_coherence_signal — set inputs->ua_incoherent = 1 if the User-Agent
 * claims a mainstream browser family (Chrome/Firefox/Safari/Edge/Gecko) but the
 * request is missing the header shape every real browser sends (no Accept /
 * Accept-Language / gzip-or-br Accept-Encoding, or pre-HTTP/1.1). Pure
 * structural heuristic over r->headers_in: no DB, no JA4H hash, no regex, no
 * malloc, no network. Fail-open: NULL r / no UA / non-browser UA / fully
 * browser-shaped request → ua_incoherent = 0.
 */
void sentinel_coherence_signal(ngx_http_request_t *r,
    ngx_sentinel_inputs_t *inputs);

/* -------------------------------------------------------------------------
 * PoW challenge API (sentinel_pow.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_pow_dispatch — handle a CHALLENGE-band verdict. Serves a stateless
 * hashcash puzzle (HMAC challenge keyed on IP+time-bucket) and gates access via
 * a signed cookie. Returns NGX_DECLINED to pass (off / valid cookie / valid
 * solution) or NGX_DONE if a challenge page was served. Fails CLOSED on a
 * present-but-invalid cookie; fails OPEN only when disabled / no secret.
 */
ngx_int_t sentinel_pow_dispatch(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_ctx_t *ctx);

/* -------------------------------------------------------------------------
 * Score API (sentinel_score.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_score_compute — combine signals into a weighted-sum score.
 * known_good_ua short-circuits to 0. Fail-open (NULL args -> 0). Clamped to
 * [0, NGX_SENTINEL_SCORE_MAX]. Pure arithmetic, no I/O, no allocation.
 */
ngx_int_t sentinel_score_compute(const ngx_sentinel_inputs_t *inputs,
    const ngx_sentinel_loc_conf_t *lcf);

/*
 * sentinel_score_to_verdict — map score to verdict using thresholds.
 */
ngx_sentinel_verdict_e sentinel_score_to_verdict(ngx_int_t score,
    const ngx_sentinel_threshold_t *thr);

/* -------------------------------------------------------------------------
 * Tarpit API (sentinel_tarpit.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_tarpit_start — dispatch a tarpitted connection.
 * Must be called from the PREACCESS handler when verdict == TARPIT and
 * shadow mode is off.
 *
 * Returns:
 *   NGX_DONE        — tarpit running; caller MUST return NGX_DONE
 *   NGX_HTTP_CLOSE  — at cap (max_conns); caller returns NGX_HTTP_CLOSE (444)
 *   NGX_DECLINED    — fail-open setup error; caller allows (NGX_DECLINED)
 */
ngx_int_t sentinel_tarpit_start(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf);

/*
 * sentinel_tarpit_init_process — zero this worker's sub-counter slot.
 * Called from the module init_process hook to self-heal after hard kills.
 */
ngx_int_t sentinel_tarpit_init_process(ngx_cycle_t *cycle);

/* -------------------------------------------------------------------------
 * Phase 3 — CrowdSec feed loader + read API (sentinel_feed.c)
 * ---------------------------------------------------------------------- */

/*
 * sentinel_shm_crowdsec_upsert — insert/update a crowdsec ban node for `key`.
 * Sets blocked_until=expiry, cs_action, stamps cs_generation. Caller holds the
 * zone lock. Returns NGX_OK (stored), NGX_ERROR (zone full / bad args).
 */
ngx_int_t sentinel_shm_crowdsec_upsert(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t expiry, u_char action, ngx_uint_t generation,
    time_t now);

/*
 * sentinel_shm_crowdsec_sweep — delete crowdsec nodes whose cs_generation does
 * not equal `generation` (absent from the latest feed). Caller holds the lock.
 * Bounded to `batch` deletions per call; returns the number deleted.
 */
ngx_uint_t sentinel_shm_crowdsec_sweep(ngx_sentinel_zone_t *zone,
    ngx_uint_t generation, ngx_uint_t batch);

/*
 * sentinel_shm_crowdsec_lookup — O(1) read of the crowdsec table.
 * Returns NGX_BUSY + *action if key present with blocked_until > now;
 * NGX_OK (no hit) otherwise; NGX_ERROR on zone error. Takes the zone lock.
 */
ngx_int_t sentinel_shm_crowdsec_lookup(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, time_t now, u_char *action);

/*
 * sentinel_feed_parse — parse a flat feed buffer in-place into the crowdsec
 * zone. Validates the header + %%EOF trailer (count + CRC32) BEFORE touching
 * shm. Returns NGX_OK (applied), NGX_DECLINED (rejected: bad trailer/crc/count/
 * oversized-malformed), NGX_ERROR (zone error). On NGX_DECLINED/NGX_ERROR the
 * live table is left untouched (fail-open). Pure byte scan, no regex, no JSON.
 */
ngx_int_t sentinel_feed_parse(ngx_sentinel_zone_t *zone, ngx_log_t *log,
    u_char *data, size_t len, ngx_int_t default_ttl, time_t now);

/*
 * sentinel_crowdsec_signal — request-path read: fill inputs->crowdsec_hit and
 * inputs->crowdsec_action from the crowdsec table. Fail-open.
 */
void sentinel_crowdsec_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs);

/*
 * sentinel_crowdsec_init_process — arm the per-worker feed-refresh timer for
 * every sentinel location that has a crowdsec feed configured.
 */
ngx_int_t sentinel_crowdsec_init_process(ngx_cycle_t *cycle);

/* -------------------------------------------------------------------------
 * Variable index (set by ngx_http_sentinel_module.c, used by sub-files)
 * ---------------------------------------------------------------------- */

extern ngx_module_t  ngx_http_sentinel_module;

#endif /* SENTINEL_H */
