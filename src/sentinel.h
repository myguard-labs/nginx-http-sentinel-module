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

/* Default score weights (tunable via sentinel_weight_* directives). */
#define NGX_SENTINEL_DEFAULT_W_ERRRATE 1     /* per error event in burst window */
#define NGX_SENTINEL_DEFAULT_W_BLOCKED 100   /* identity already blocked        */
#define NGX_SENTINEL_DEFAULT_W_SCANNER 50    /* scanner-path prefix hit         */
#define NGX_SENTINEL_DEFAULT_W_BOT     30    /* heuristic bot user-agent        */
#define NGX_SENTINEL_DEFAULT_W_HEADER  25    /* request-header anomaly          */
#define NGX_SENTINEL_DEFAULT_W_HONEYPOT 90   /* decoy-URL (honeypot) hit        */
#define NGX_SENTINEL_DEFAULT_W_VELOCITY 30   /* request-rate abuse: meaningful but below scanner/honeypot */
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

/* -------------------------------------------------------------------------
 * Verdict enum
 * ---------------------------------------------------------------------- */

typedef enum {
    NGX_SENTINEL_VERDICT_ALLOW     = 0,
    NGX_SENTINEL_VERDICT_CHALLENGE = 1,
    NGX_SENTINEL_VERDICT_TARPIT    = 2,
    NGX_SENTINEL_VERDICT_BLOCK     = 3
} ngx_sentinel_verdict_e;

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

    /* Header-anomaly: suspicious/malformed request headers */
    ngx_flag_t  header_anomaly;

    /* Honeypot: request URI matched a decoy-path prefix */
    ngx_flag_t  honeypot;

    /* Velocity: request rate exceeded the configured threshold */
    ngx_flag_t  velocity_exceeded;

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
    ngx_int_t  crowdsec;  /* base weight for a crowdsec ban hit (tiered) */
} ngx_sentinel_weights_t;

/* -------------------------------------------------------------------------
 * Module configurations
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_array_t   zones;        /* ngx_sentinel_zone_t[] (errrate)                  */
    ngx_array_t   cs_zones;     /* ngx_sentinel_zone_t[] (crowdsec, Phase 3)        */
    ngx_array_t   vel_zones;     /* ngx_sentinel_zone_t[] (velocity)             */
    ngx_atomic_t *tarpit_conns; /* per-worker sub-counters [NGX_MAX_PROCESSES]      */
                                /* allocated in dedicated shm at sentinel_zone init  */
} ngx_sentinel_main_conf_t;

typedef struct {
    ngx_flag_t               enabled;   /* sentinel on|off */
    ngx_flag_t               shadow;    /* 1=shadow, 0=enforce */
    ngx_flag_t               fail_open; /* 1=open (allow on error), 0=closed */
    ngx_sentinel_zone_t     *zone;      /* pointer into main conf zones array */
    ngx_sentinel_zone_t     *vel_zone;   /* velocity shm zone (NULL=off) */
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

    /* Phase 2 — tarpit parameters */
    ngx_int_t                tarpit_max_conns;    /* global cap across workers      */
    ngx_int_t                tarpit_delay;        /* ms between drip ticks          */
    ngx_int_t                tarpit_bytes;        /* total bytes to drip (cap)      */
    ngx_int_t                tarpit_max_lifetime; /* hard force-close ceiling (ms)  */
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
