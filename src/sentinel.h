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

/* Hard ceiling for the computed score (overflow/abuse guard). */
#define NGX_SENTINEL_SCORE_MAX         100000

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
    u_short            key_len;
    u_char             data[1];   /* key bytes then event timestamps (time_t[]) */
} ngx_sentinel_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel_rb;
    ngx_queue_t        queue;
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
    ngx_flag_t  known_good_ua;     /* forward-confirmed search engine UA */
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
} ngx_sentinel_weights_t;

/* -------------------------------------------------------------------------
 * Module configurations
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_array_t   zones;        /* ngx_sentinel_zone_t[]                            */
    ngx_atomic_t *tarpit_conns; /* per-worker sub-counters [NGX_MAX_PROCESSES]      */
                                /* allocated in dedicated shm at sentinel_zone init  */
} ngx_sentinel_main_conf_t;

typedef struct {
    ngx_flag_t               enabled;   /* sentinel on|off */
    ngx_flag_t               shadow;    /* 1=shadow, 0=enforce */
    ngx_flag_t               fail_open; /* 1=open (allow on error), 0=closed */
    ngx_sentinel_zone_t     *zone;      /* pointer into main conf zones array */
    ngx_sentinel_threshold_t threshold;
    ngx_sentinel_weights_t   weights;

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
 * Variable index (set by ngx_http_sentinel_module.c, used by sub-files)
 * ---------------------------------------------------------------------- */

extern ngx_module_t  ngx_http_sentinel_module;

#endif /* SENTINEL_H */
