/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * ngx_http_sentinel_module.c — core: conf, PREACCESS handler, variables,
 * directives for ngx_http_sentinel_module.
 *
 * Phase 1 skeleton.  Shadow mode by default; score stub returns 0; verdict
 * is always "allow"; enforcement dispatch marked TODO for Phase 2.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Variable indices
 * ---------------------------------------------------------------------- */


/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */

static ngx_int_t ngx_sentinel_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t ngx_sentinel_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_sentinel_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_sentinel_init(ngx_conf_t *cf);

static void *ngx_sentinel_create_main_conf(ngx_conf_t *cf);
static void *ngx_sentinel_create_loc_conf(ngx_conf_t *cf);
static char *ngx_sentinel_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_sentinel_set_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_threshold(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_mode(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_fail(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_sentinel_set_tarpit_delay(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_tarpit_bytes(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_tarpit_lifetime(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_sentinel_set_crowdsec_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_crowdsec_feed(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_redis(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_cs_sink(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_fcrdns_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_fcrdns(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_fcrdns_suffix(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *sentinel_conf_honeypot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *sentinel_conf_allowlist(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *sentinel_conf_asn_source(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *sentinel_conf_datacenter_asn(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *sentinel_conf_ja4_source(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *sentinel_conf_ja4_deny(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_velocity_zone(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_velocity_bind(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_sentinel_set_status(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_sentinel_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_sentinel_init_tarpit_shm(ngx_conf_t *cf,
    ngx_sentinel_main_conf_t *mcf);
static ngx_int_t ngx_sentinel_tarpit_shm_init(ngx_shm_zone_t *shm_zone,
    void *data);

static ngx_int_t ngx_sentinel_var_score(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_verdict(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_ja4h(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_header(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_honeypot(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_velocity(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_asn(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_coherence(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_fcrdns(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_allowlist(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_bot(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_shield(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_throttled(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_pow(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_scanner(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_errrate(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_crowdsec(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_sentinel_var_crowdsec_action(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_sentinel_ctx_t *ngx_sentinel_get_ctx(ngx_http_request_t *r);

/* -------------------------------------------------------------------------
 * Directive table
 * ---------------------------------------------------------------------- */

static ngx_command_t ngx_sentinel_commands[] = {

    /* sentinel on|off; — location context */
    { ngx_string("sentinel"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, enabled),
      NULL },

    /* sentinel_mode shadow|enforce; — location context */
    { ngx_string("sentinel_mode"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_zone name:size; — main context */
    { ngx_string("sentinel_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_fail open|closed; — location context */
    { ngx_string("sentinel_fail"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_fail,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_threshold challenge=N tarpit=M block=K; — location context */
    { ngx_string("sentinel_threshold"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      ngx_sentinel_set_threshold,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_weight_errrate N; — per error event in burst window */
    { ngx_string("sentinel_weight_errrate"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.errrate),
      NULL },

    /* sentinel_weight_blocked N; — identity already blocked */
    { ngx_string("sentinel_weight_blocked"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.blocked),
      NULL },

    /* sentinel_weight_scanner N; — scanner-path prefix hit */
    { ngx_string("sentinel_weight_scanner"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.scanner),
      NULL },

    /* sentinel_weight_bot N; — heuristic bot user-agent */
    { ngx_string("sentinel_weight_bot"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.bot),
      NULL },

    /* sentinel_weight_header N; — request-header anomaly */
    { ngx_string("sentinel_weight_header"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.header),
      NULL },

    /* sentinel_weight_honeypot N; — decoy-URL (honeypot) hit */
    { ngx_string("sentinel_weight_honeypot"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.honeypot),
      NULL },

    /* sentinel_velocity_zone name:size [rate=N] [window=S] [block=S]; — main context */
    { ngx_string("sentinel_velocity_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      ngx_sentinel_set_velocity_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_weight_velocity N; — added once if velocity_exceeded */
    { ngx_string("sentinel_weight_velocity"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.velocity),
      NULL },

    /* sentinel_weight_asn N; — added once if datacenter_asn */
    { ngx_string("sentinel_weight_asn"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.asn),
      NULL },

    /* sentinel_weight_coherence N; — added once if ua_incoherent */
    { ngx_string("sentinel_weight_coherence"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.coherence),
      NULL },

    /* sentinel_asn <variable>; — geoip2 ASN source variable (e.g. $geoip2_asn) */
    { ngx_string("sentinel_asn"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      sentinel_conf_asn_source,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_datacenter_asn N [N ...]; — flagged datacenter/abuse ASN list */
    { ngx_string("sentinel_datacenter_asn"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      sentinel_conf_datacenter_asn,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_weight_ja4 N; — added once if ja4_flagged */
    { ngx_string("sentinel_weight_ja4"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.ja4),
      NULL },

    /* sentinel_ja4 <variable>; — ssl-fingerprint JA4 source (e.g. $ssl_fingerprint_ja4) */
    { ngx_string("sentinel_ja4"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      sentinel_conf_ja4_source,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_ja4_deny <ja4|hash> [...]; — denied JA4 (TLS) fingerprint list */
    { ngx_string("sentinel_ja4_deny"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      sentinel_conf_ja4_deny,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_velocity <zone_name>; — bind this location to a velocity zone (opt-in) */
    { ngx_string("sentinel_velocity"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_velocity_bind,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_honeypot <path> [path ...]; — decoy path prefix(es) */
    { ngx_string("sentinel_honeypot"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      sentinel_conf_honeypot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_allowlist <ip|cidr> [ip|cidr ...]; — operator-trusted ranges */
    { ngx_string("sentinel_allowlist"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      sentinel_conf_allowlist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* ---- Phase 2: tarpit directives ---- */

    /* sentinel_tarpit_max_conns N;  default 256; 0=disabled (all TARPIT->444) */
    { ngx_string("sentinel_tarpit_max_conns"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, tarpit_max_conns),
      NULL },

    /* sentinel_tarpit_delay ms;  default 5000; bounds [100, 60000] */
    { ngx_string("sentinel_tarpit_delay"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_delay,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_tarpit_bytes N;  default 1024; bounds [1, 65536] */
    { ngx_string("sentinel_tarpit_bytes"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_bytes,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_tarpit_max_lifetime ms;  default 30000; bounds [1000, 600000] */
    { ngx_string("sentinel_tarpit_max_lifetime"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_lifetime,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_tarpit_maze on|off;  default off. When on, the tarpit drips
     * HTML decoy crawl-links instead of blank padding (maze mode). */
    { ngx_string("sentinel_tarpit_maze"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, tarpit_maze),
      NULL },

    /* sentinel_block_status N;  default 403; 444=drop conn; bounds [400,599] */
    { ngx_string("sentinel_block_status"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, block_status),
      NULL },

    /* sentinel_block_ttl S;  default 0 (off); >0 persists a self-ban for S sec */
    { ngx_string("sentinel_block_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, block_ttl),
      NULL },

    /* sentinel_throttle_rate size;  default 0 (off, keep tarpit). On a TARPIT
     * verdict in enforce mode, cap egress at `size` bytes/sec instead. */
    { ngx_string("sentinel_throttle_rate"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, throttle_rate),
      NULL },

    /* sentinel_shield on|off;  default off. On a TARPIT-band verdict in enforce
     * mode, raise $sentinel_shield=1 (the operator wires it into proxy cache
     * config to serve stale/cache-only) instead of tarpitting. */
    { ngx_string("sentinel_shield"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, shield),
      NULL },

    /* sentinel_pow on|off;  serve a PoW challenge on CHALLENGE-band verdicts */
    { ngx_string("sentinel_pow"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, pow_enabled),
      NULL },

    /* sentinel_pow_secret <key>;  HMAC signing key (required; empty = off) */
    { ngx_string("sentinel_pow_secret"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, pow_secret),
      NULL },

    /* sentinel_pow_difficulty N;  required leading zero bits (default 16) */
    { ngx_string("sentinel_pow_difficulty"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, pow_difficulty),
      NULL },

    /* sentinel_pow_ttl time;  challenge-bucket + bypass-cookie TTL (default 3600) */
    { ngx_string("sentinel_pow_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, pow_ttl),
      NULL },

    /* ---- Phase 3: crowdsec decision-feed directives ---- */

    /* sentinel_crowdsec_zone name:size; — main context (declares the shm zone) */
    { ngx_string("sentinel_crowdsec_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_crowdsec_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_fcrdns_zone name:size; — main context (declares the verdict cache) */
    { ngx_string("sentinel_fcrdns_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_fcrdns_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_fcrdns <zone>; — bind a location to a verdict cache + enable */
    { ngx_string("sentinel_fcrdns"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_fcrdns,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_fcrdns_ttl time; — verdict cache TTL (default 3600s) */
    { ngx_string("sentinel_fcrdns_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, fcrdns_ttl),
      NULL },

    /* sentinel_fcrdns_verify_suffix <suffix>...; — allowed PTR-name suffixes */
    { ngx_string("sentinel_fcrdns_verify_suffix"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      ngx_sentinel_set_fcrdns_suffix,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_crowdsec_feed path; — location: feed file (off if unset) */
    { ngx_string("sentinel_crowdsec_feed"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_crowdsec_feed,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_crowdsec_interval time; — refresh tick (default 10s) */
    { ngx_string("sentinel_crowdsec_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_interval),
      NULL },

    /* sentinel_crowdsec_default_ttl time; — TTL for expiry==0 lines */
    { ngx_string("sentinel_crowdsec_default_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_default_ttl),
      NULL },

    /* sentinel_crowdsec_stale_after time; — stale threshold + LRU age-out */
    { ngx_string("sentinel_crowdsec_stale_after"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_stale_after),
      NULL },

    /* sentinel_crowdsec_max_bytes size; — feed size cap */
    { ngx_string("sentinel_crowdsec_max_bytes"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_max_bytes),
      NULL },

    /* sentinel_redis host[:port]; — enable Redis multi-box shared ban state */
    { ngx_string("sentinel_redis"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_redis,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_redis_password <pw>; — optional AUTH password */
    { ngx_string("sentinel_redis_password"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, redis_password),
      NULL },

    /* sentinel_redis_prefix <ns>; — key namespace (default "sentinel") */
    { ngx_string("sentinel_redis_prefix"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, redis_prefix),
      NULL },

    /* sentinel_redis_interval time; — pull/flush tick (default 10s) */
    { ngx_string("sentinel_redis_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, redis_interval),
      NULL },

    /* sentinel_redis_ttl time; — TTL for pushed ban keys (default 3600s) */
    { ngx_string("sentinel_redis_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, redis_ttl),
      NULL },

    /* sentinel_weight_crowdsec N; — base score weight for a crowdsec ban */
    { ngx_string("sentinel_weight_crowdsec"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.crowdsec),
      NULL },

    /* sentinel_cs_sink_path <file>; — export local bans as a CrowdSec
     * file-acquisition decisions file (out-of-band, no network). */
    { ngx_string("sentinel_cs_sink_path"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_cs_sink,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_cs_sink_interval time; — drain/rewrite tick (default 10s) */
    { ngx_string("sentinel_cs_sink_interval"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_sink_interval),
      NULL },

    /* sentinel_cs_sink_ttl time; — decision duration written (default 3600s) */
    { ngx_string("sentinel_cs_sink_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_sink_ttl),
      NULL },

    /* sentinel_cs_sink_scenario <s>; — "scenario" field (default
     * sentinel/http-abuse) */
    { ngx_string("sentinel_cs_sink_scenario"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_sink_scenario),
      NULL },

    /* sentinel_status; — install the Prometheus exposition content handler on
     * this location (operator places it on `location = /sentinel-status` and
     * protects it with allow/deny). */
    { ngx_string("sentinel_status"),
      NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      ngx_sentinel_set_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

/* -------------------------------------------------------------------------
 * Module context
 * ---------------------------------------------------------------------- */

static ngx_http_module_t ngx_sentinel_module_ctx = {
    ngx_sentinel_add_variables,    /* preconfiguration  */
    ngx_sentinel_init,             /* postconfiguration */

    ngx_sentinel_create_main_conf, /* create main configuration */
    NULL,                          /* init main configuration   */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration  */

    ngx_sentinel_create_loc_conf,  /* create location configuration */
    ngx_sentinel_merge_loc_conf    /* merge location configuration  */
};

/* -------------------------------------------------------------------------
 * Module definition
 * ---------------------------------------------------------------------- */

ngx_module_t ngx_http_sentinel_module = {
    NGX_MODULE_V1,
    &ngx_sentinel_module_ctx,   /* module context    */
    ngx_sentinel_commands,      /* module directives */
    NGX_HTTP_MODULE,            /* module type       */
    NULL,                              /* init master       */
    NULL,                              /* init module       */
    ngx_sentinel_init_process,         /* init process      */
    NULL,                       /* init thread       */
    NULL,                       /* exit thread       */
    NULL,                       /* exit process      */
    NULL,                       /* exit master       */
    NGX_MODULE_V1_PADDING
};

/* -------------------------------------------------------------------------
 * Variable registration and getters
 * ---------------------------------------------------------------------- */

static ngx_http_variable_t ngx_sentinel_vars[] = {

    { ngx_string("sentinel_score"),   NULL,
      ngx_sentinel_var_score,   0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_verdict"), NULL,
      ngx_sentinel_var_verdict, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_ja4h"),    NULL,
      ngx_sentinel_var_ja4h,    0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_header_anomaly"), NULL,
      ngx_sentinel_var_header,  0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_honeypot"), NULL,
      ngx_sentinel_var_honeypot, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_velocity"), NULL,
      ngx_sentinel_var_velocity, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_asn"), NULL,
      ngx_sentinel_var_asn, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_ja4"), NULL,
      ngx_sentinel_var_ja4, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_coherence"), NULL,
      ngx_sentinel_var_coherence, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_fcrdns"), NULL,
      ngx_sentinel_var_fcrdns, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_allowlist"), NULL,
      ngx_sentinel_var_allowlist, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_bot"), NULL,
      ngx_sentinel_var_bot, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_shield"), NULL,
      ngx_sentinel_var_shield, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_throttled"), NULL,
      ngx_sentinel_var_throttled, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_pow"), NULL,
      ngx_sentinel_var_pow, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_scanner"), NULL,
      ngx_sentinel_var_scanner, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_errrate"), NULL,
      ngx_sentinel_var_errrate, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_crowdsec"), NULL,
      ngx_sentinel_var_crowdsec, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("sentinel_crowdsec_action"), NULL,
      ngx_sentinel_var_crowdsec_action, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
ngx_sentinel_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;
    ngx_uint_t            i;

    for (i = 0; ngx_sentinel_vars[i].name.len; i++) {
        var = ngx_http_add_variable(cf, &ngx_sentinel_vars[i].name,
                                    ngx_sentinel_vars[i].flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = ngx_sentinel_vars[i].get_handler;
        var->data        = ngx_sentinel_vars[i].data;
    }

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Context getter: compute all signals on first access, cache in ctx.
 * ---------------------------------------------------------------------- */

static ngx_sentinel_ctx_t *
ngx_sentinel_get_ctx(ngx_http_request_t *r)
{
    ngx_sentinel_ctx_t     *ctx;
    ngx_sentinel_loc_conf_t *lcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_sentinel_module);

    if (ctx != NULL) {
        return ctx;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_sentinel_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_sentinel_module);

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_sentinel_module);

    /* Gather all signals. */
    sentinel_ja4h_compute(r, ctx->inputs.ja4h);
    sentinel_errrate_signal(r, lcf, &ctx->inputs);
    sentinel_botua_signal(r, &ctx->inputs);
    sentinel_header_signal(r, &ctx->inputs);
    sentinel_honeypot_signal(r, lcf, &ctx->inputs);
    sentinel_allowlist_signal(r, lcf, &ctx->inputs);
    sentinel_velocity_signal(r, lcf, &ctx->inputs);
    sentinel_asn_signal(r, lcf, &ctx->inputs);
    sentinel_ja4_signal(r, lcf, &ctx->inputs);
    sentinel_coherence_signal(r, &ctx->inputs);
    sentinel_fcrdns_signal(r, lcf, &ctx->inputs);
    sentinel_crowdsec_signal(r, lcf, &ctx->inputs);

    /* Score + verdict (stub returns 0 -> always allow). */
    ctx->score   = sentinel_score_compute(&ctx->inputs, lcf);
    ctx->verdict = sentinel_score_to_verdict(ctx->score, &lcf->threshold);

    ctx->computed = 1;

    return ctx;
}

/* -------------------------------------------------------------------------
 * Variable get handlers
 * ---------------------------------------------------------------------- */

static ngx_int_t
ngx_sentinel_var_score(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    u_char              *p;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len    = (u_int) (ngx_sprintf(p, "%i", (ngx_int_t) ctx->score) - p);
    v->data   = p;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static const char *const verdict_strings[] = {
    "allow",
    "challenge",
    "tarpit",
    "block"
};

static ngx_int_t
ngx_sentinel_var_verdict(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    const char          *vstr;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    vstr  = verdict_strings[ctx->verdict];
    v->len = (u_int) ngx_strlen(vstr);
    v->data = (u_char *) vstr;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_ja4h(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = NGX_SENTINEL_JA4H_HEX_LEN;
    v->data = ctx->inputs.ja4h;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_header(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.header_anomaly ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_honeypot(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.honeypot ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_velocity(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.velocity_exceeded ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_asn(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.datacenter_asn ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_sentinel_var_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.ja4_flagged ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_coherence(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.ua_incoherent ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_fcrdns(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    const char          *s;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->inputs.fcrdns_verified) {
        s = "verified";
    } else if (ctx->inputs.fcrdns_spoofed) {
        s = "spoofed";
    } else {
        s = "pending";   /* disabled / no known_good_ua / no cached verdict */
    }

    v->len  = ngx_strlen(s);
    v->data = (u_char *) s;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_allowlist(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.allowlisted ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_bot(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.bot_ua ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_shield(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->shielded ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 1;   /* set during the request, not at gather time */

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_throttled(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->throttled ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 1;   /* set during the request, not at gather time */

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_pow(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    ngx_str_t            s;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    switch (ctx->pow_state) {
    case NGX_SENTINEL_POW_VERIFIED:  ngx_str_set(&s, "verified");  break;
    case NGX_SENTINEL_POW_CHALLENGE: ngx_str_set(&s, "challenge"); break;
    default:                         ngx_str_set(&s, "off");       break;
    }

    v->len  = s.len;
    v->data = s.data;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_scanner(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.scanner_path ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_errrate(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    u_char              *p;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len    = (u_int) (ngx_sprintf(p, "%ui", ctx->inputs.errrate_count) - p);
    v->data   = p;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_var_crowdsec(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len  = 1;
    v->data = (u_char *) (ctx->inputs.crowdsec_hit ? "1" : "0");
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

/* crowdsec action tier as a stable lowercase token (none|ban|captcha|throttle)
 * for human-readable structured logs; falls back to "none" for unknown tiers. */
static const char *const sentinel_cs_action_strings[] = {
    "none",      /* NGX_SENTINEL_CS_NONE     */
    "ban",       /* NGX_SENTINEL_CS_BAN      */
    "captcha",   /* NGX_SENTINEL_CS_CAPTCHA  */
    "throttle"   /* NGX_SENTINEL_CS_THROTTLE */
};

static ngx_int_t
ngx_sentinel_var_crowdsec_action(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_sentinel_ctx_t  *ctx;
    const char          *s;
    ngx_uint_t           act;

    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    act = (ngx_uint_t) ctx->inputs.crowdsec_action;
    if (act >= (sizeof(sentinel_cs_action_strings)
                / sizeof(sentinel_cs_action_strings[0]))) {
        act = NGX_SENTINEL_CS_NONE;
    }
    s = sentinel_cs_action_strings[act];

    v->len  = (u_int) ngx_strlen(s);
    v->data = (u_char *) s;
    v->valid  = 1;
    v->not_found   = 0;
    v->no_cacheable = 0;

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * PREACCESS handler
 * ---------------------------------------------------------------------- */

static ngx_int_t
ngx_sentinel_preaccess_handler(ngx_http_request_t *r)
{
    ngx_sentinel_loc_conf_t  *lcf;
    ngx_sentinel_ctx_t       *ctx;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_sentinel_module);

    /* 1. sentinel off → pass through immediately. */
    if (!lcf->enabled) {
        return NGX_DECLINED;
    }

    /* 2. Gather signals + compute score/verdict into request ctx. */
    ctx = ngx_sentinel_get_ctx(r);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "sentinel: ctx allocation failed (fail-open)");
        return NGX_DECLINED;
    }

    /* 3. Log score/verdict/ja4h at info level (always, in both modes). */
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "sentinel: score=%i verdict=%s ja4h=%s "
                  "shadow=%i errrate=%ui bot=%i scanner=%i header=%i "
                  "honeypot=%i velocity=%i asn=%i ja4=%i coherence=%i "
                  "fcrdns_verified=%i fcrdns_spoofed=%i "
                  "allowlist=%i crowdsec=%i cs_action=%ui pow=%ui",
                  ctx->score,
                  verdict_strings[ctx->verdict],
                  ctx->inputs.ja4h,
                  (ngx_int_t) lcf->shadow,
                  ctx->inputs.errrate_count,
                  (ngx_int_t) ctx->inputs.bot_ua,
                  (ngx_int_t) ctx->inputs.scanner_path,
                  (ngx_int_t) ctx->inputs.header_anomaly,
                  (ngx_int_t) ctx->inputs.honeypot,
                  (ngx_int_t) ctx->inputs.velocity_exceeded,
                  (ngx_int_t) ctx->inputs.datacenter_asn,
                  (ngx_int_t) ctx->inputs.ja4_flagged,
                  (ngx_int_t) ctx->inputs.ua_incoherent,
                  (ngx_int_t) ctx->inputs.fcrdns_verified,
                  (ngx_int_t) ctx->inputs.fcrdns_spoofed,
                  (ngx_int_t) ctx->inputs.allowlisted,
                  (ngx_int_t) ctx->inputs.crowdsec_hit,
                  (ngx_uint_t) ctx->inputs.crowdsec_action,
                  (ngx_uint_t) ctx->pow_state);

    /* 3b. Record Prometheus counters (both modes). Lock-free, best-effort. */
    sentinel_metrics_record(
        ngx_http_get_module_main_conf(r, ngx_http_sentinel_module),
        ctx, (ngx_uint_t) lcf->shadow);

    /* 4. Shadow mode: compute + log, never enforce → always pass. */
    if (lcf->shadow) {
        return NGX_DECLINED;
    }

    /*
     * 5. Enforce mode: dispatch by verdict.
     *    Phase 1: score stub always returns 0 → verdict always ALLOW.
     *    TODO Phase 2: wire tarpit / challenge bodies here.
     *    TODO Phase 2: wire block (403/444) here.
     */
    switch (ctx->verdict) {
    case NGX_SENTINEL_VERDICT_ALLOW:
        return NGX_DECLINED;

    case NGX_SENTINEL_VERDICT_CHALLENGE:
        /* PoW challenge: serve a stateless hashcash puzzle gated by a signed
         * cookie. Fails open (DECLINED) when disabled / no secret / valid
         * cookie / valid solution; serves the page (NGX_DONE) otherwise. */
        {
            /* dispatch may finalize the request (serve the challenge page) and
             * free the request pool. On NGX_DONE we MUST return immediately
             * without touching r / ctx again (UAF otherwise). Log only on the
             * pass-through path, where r is still alive. */
            ngx_int_t  prc = sentinel_pow_dispatch(r, lcf, ctx);

            if (prc == NGX_DONE) {
                return NGX_DONE;  /* challenge page served, request owned */
            }

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "sentinel: verdict=challenge pow_state=%ui",
                          (ngx_uint_t) ctx->pow_state);
            return NGX_DECLINED;  /* pass through (verified / off) */
        }

    case NGX_SENTINEL_VERDICT_TARPIT:
        {
            ngx_int_t  trc;

            /* Throttle action: instead of a tarpit trap, let the request run
             * but cap egress at throttle_rate bytes/sec via nginx's native
             * rate limiter. No new timers/FDs/conn-cap — bounded by core. */
            if (lcf->throttle_rate > 0) {
                r->limit_rate = lcf->throttle_rate;
                r->limit_rate_after = 0;
                ctx->throttled = 1;
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "sentinel: verdict=tarpit -> throttle %z B/s",
                              lcf->throttle_rate);
                return NGX_DECLINED;
            }

            /* Origin-shield action: instead of tarpitting, let the request
             * proceed but flag it so the operator's proxy block serves
             * cache-only / stale ($sentinel_shield=1) and spares the origin.
             * Takes precedence over the tarpit drip (throttle already returned
             * above if set). The module only raises the signal — no upstream/
             * cache object exists yet at PREACCESS. */
            if (lcf->shield) {
                ctx->shielded = 1;
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "sentinel: verdict=tarpit -> origin-shield");
                return NGX_DECLINED;
            }

            if (lcf->tarpit_max_conns == 0) {
                /* Tarpit disabled — downgrade to immediate 444. */
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "sentinel: tarpit disabled (max_conns=0) -> 444");
                return NGX_HTTP_CLOSE;
            }

            trc = sentinel_tarpit_start(r, lcf);

            if (trc == NGX_DONE) {
                return NGX_DONE;  /* owns the connection */
            }

            if (trc == NGX_HTTP_CLOSE) {
                return NGX_HTTP_CLOSE;  /* at cap -> 444 */
            }

            /* Any setup error: fail-open. */
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "sentinel: tarpit setup error (fail-open)");
            return NGX_DECLINED;
        }

    case NGX_SENTINEL_VERDICT_BLOCK:
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sentinel: verdict=block -> status=%i",
                      lcf->block_status);

        /*
         * TTL soft-ban: persist a self-ban in the errrate zone so subsequent
         * requests from this identity short-circuit (errrate_lookup -> NGX_BUSY
         * -> errrate_blocked -> w_blocked -> re-crosses the block band) for the
         * TTL with no re-evaluation.  Fail-open: skip silently if no zone or on
         * any shm error (the block itself still fires below).
         */
        if (lcf->block_ttl > 0 && lcf->zone != NULL) {
            u_char     digest[NGX_SENTINEL_DIGEST_LEN];
            ngx_str_t  key;

            if (r->connection->addr_text.len != 0) {
                SHA256(r->connection->addr_text.data,
                       r->connection->addr_text.len, digest);
                key.data = digest;
                key.len  = NGX_SENTINEL_DIGEST_LEN;

                if (sentinel_shm_softban_set(lcf->zone, &key, ngx_time(),
                                             (time_t) lcf->block_ttl) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "sentinel: softban persist failed for zone "
                                  "\"%V\" (fail-open)", &lcf->zone->name);
                }
            }
        }

        /*
         * Redis multi-box PUSH: publish this LOCALLY-ORIGINATED ban so peer
         * nodes pick it up on their next pull tick. Ban-loop guard: skip when
         * the block was driven by a CrowdSec hit — those bans are externally
         * sourced (feed or a Redis pull), so re-publishing them would loop.
         * Non-blocking: enqueues into a shm ring drained by the worker timer;
         * NO network I/O here. Fail-open (no-op if Redis is off).
         */
        if (lcf->redis_host.len > 0 && !ctx->inputs.crowdsec_hit
            && r->connection->addr_text.len != 0)
        {
            sentinel_redis_enqueue_ban(lcf, &r->connection->addr_text,
                                       NGX_SENTINEL_CS_BAN,
                                       ngx_time() + (time_t) lcf->redis_ttl);
        }

        /*
         * CrowdSec decision sink: export this LOCALLY-ORIGINATED ban to the
         * decisions file so the rest of a CrowdSec deployment learns about it.
         * Same ban-loop guard as the Redis push (never re-export an externally
         * sourced ban). Non-blocking enqueue; the worker timer writes the file.
         * Fail-open (no-op if the sink is off).
         */
        if (lcf->cs_sink_path.len > 0 && !ctx->inputs.crowdsec_hit
            && r->connection->addr_text.len != 0)
        {
            sentinel_cssink_enqueue_ban(lcf, &r->connection->addr_text,
                                        NGX_SENTINEL_CS_BAN,
                                        ngx_time() + (time_t) lcf->cs_sink_ttl);
        }

        /* 444 -> drop the connection without a response; else finalize with
         * the configured HTTP status (default 403). */
        return lcf->block_status;
    }

    return NGX_DECLINED;
}

/* -------------------------------------------------------------------------
 * LOG-phase handler: record error events into the errrate sliding window.
 *
 * Called after the response is sent.  Only records when status >= 400.
 * (Phase 1b: threshold hardcoded; a configurable status set is a later TODO.)
 * No malloc: SHA-256 digest lives on the stack.  Fail-open on every error.
 * ---------------------------------------------------------------------- */

static ngx_int_t
ngx_sentinel_log_handler(ngx_http_request_t *r)
{
    ngx_sentinel_loc_conf_t  *lcf;
    ngx_sentinel_zone_t      *zone;
    ngx_sentinel_zone_t      *vel_zone;
    u_char                    digest[SHA256_DIGEST_LENGTH];
    ngx_str_t                 key;
    ngx_uint_t                status;
    ngx_uint_t                count;
    time_t                    blocked_until;
    ngx_int_t                 rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_sentinel_module);
    if (!lcf->enabled) {
        return NGX_OK;
    }

    /* Require a client address for any recording. */
    if (r->connection->addr_text.len == 0) {
        return NGX_OK;
    }

    /* Compute digest once; reused by both velocity and errrate records. */
    SHA256(r->connection->addr_text.data, r->connection->addr_text.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

    /*
     * Velocity: record on EVERY completed request (no status filter).
     * Must run before the status<400 early-return below.
     */
    vel_zone = lcf->vel_zone;
    if (vel_zone != NULL) {
        rc = sentinel_shm_errrate_record(vel_zone, &key, ngx_time(),
                                         &count, &blocked_until);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "sentinel: velocity record error for zone \"%V\" "
                          "(fail-open)", &vel_zone->name);
            /* fail-open: continue to errrate check */
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: velocity recorded count=%ui", count);
        }
    }

    /*
     * Errrate: record only on error responses.
     */
    zone = lcf->zone;
    if (zone == NULL) {
        return NGX_OK;
    }

    status = (r->err_status != 0) ? r->err_status : r->headers_out.status;

    if (status < 400) {
        return NGX_OK;
    }

    rc = sentinel_shm_errrate_record(zone, &key, ngx_time(), &count, &blocked_until);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "sentinel: errrate record error for zone \"%V\" (fail-open)",
                      &zone->name);
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: errrate recorded status=%ui count=%ui",
                   status, count);

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Module init: register phase handler
 * ---------------------------------------------------------------------- */

/* sentinel_status; — install the Prometheus content handler on this location. */
static char *
ngx_sentinel_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = sentinel_metrics_status_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_sentinel_init_tarpit_shm(ngx_conf_t *cf, ngx_sentinel_main_conf_t *mcf)
{
    ngx_str_t      name = ngx_string("sentinel_tarpit_conns");
    ngx_shm_zone_t *shm;
    size_t          size;

    /*
     * The zone is slab-managed (ngx_init_zone_pool slab-initializes every
     * shared zone). Size it for the slab header + metadata plus the small
     * NGX_MAX_PROCESSES atomic array. Eight pages clears the slab minimum
     * (slot bitmap + page-table overhead) with comfortable headroom.
     */
    size = 8 * ngx_pagesize;

    shm = ngx_shared_memory_add(cf, &name, size, &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_ERROR;
    }

    /*
     * shm->data holds the current-cycle mcf so the init callback can wire
     * mcf->tarpit_conns. It is only read inside the cycle that set it (never
     * carried across cycles), and the counter array itself is slab-allocated
     * inside the zone and survives reload via shpool->data — see
     * ngx_sentinel_tarpit_shm_init.
     */
    shm->data = mcf;
    shm->init = ngx_sentinel_tarpit_shm_init;

    return NGX_OK;
}

static ngx_int_t
ngx_sentinel_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_sentinel_main_conf_t   *mcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_sentinel_preaccess_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_sentinel_log_handler;

    /* Allocate dedicated shm segment for per-worker tarpit sub-counters. */
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
    if (mcf != NULL) {
        if (ngx_sentinel_init_tarpit_shm(cf, mcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Configuration management
 * ---------------------------------------------------------------------- */

static void *
ngx_sentinel_create_main_conf(ngx_conf_t *cf)
{
    ngx_sentinel_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_sentinel_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&mcf->zones, cf->pool, 4,
                       sizeof(ngx_sentinel_zone_t)) != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&mcf->cs_zones, cf->pool, 2,
                       sizeof(ngx_sentinel_zone_t)) != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&mcf->vel_zones, cf->pool, 2,
                       sizeof(ngx_sentinel_zone_t)) != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&mcf->fcrdns_zones, cf->pool, 2,
                       sizeof(ngx_sentinel_zone_t)) != NGX_OK)
    {
        return NULL;
    }

    return mcf;
}

static void *
ngx_sentinel_create_loc_conf(ngx_conf_t *cf)
{
    ngx_sentinel_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_sentinel_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enabled   = NGX_CONF_UNSET;
    lcf->shadow    = NGX_CONF_UNSET;
    lcf->fail_open = NGX_CONF_UNSET;

    lcf->threshold.challenge = NGX_CONF_UNSET;
    lcf->threshold.tarpit    = NGX_CONF_UNSET;
    lcf->threshold.block     = NGX_CONF_UNSET;

    lcf->weights.errrate = NGX_CONF_UNSET;
    lcf->weights.blocked = NGX_CONF_UNSET;
    lcf->weights.scanner = NGX_CONF_UNSET;
    lcf->weights.bot     = NGX_CONF_UNSET;
    lcf->weights.header  = NGX_CONF_UNSET;
    lcf->weights.honeypot = NGX_CONF_UNSET;
    lcf->weights.crowdsec = NGX_CONF_UNSET;

    lcf->vel_zone        = NGX_CONF_UNSET_PTR;
    lcf->weights.velocity = NGX_CONF_UNSET;

    /* asn_source NULL + asn_list empty via pcalloc; opt-in signal. */
    lcf->weights.asn     = NGX_CONF_UNSET;
    /* ja4_source NULL + ja4_list empty via pcalloc; opt-in signal. */
    lcf->weights.ja4     = NGX_CONF_UNSET;
    lcf->weights.coherence = NGX_CONF_UNSET;

    lcf->cs_zone         = NGX_CONF_UNSET_PTR;
    lcf->cs_interval     = NGX_CONF_UNSET;
    lcf->cs_default_ttl  = NGX_CONF_UNSET;
    lcf->cs_stale_after  = NGX_CONF_UNSET;
    lcf->cs_max_bytes    = NGX_CONF_UNSET_SIZE;

    /* redis_host/password/prefix empty via pcalloc; redis_push_zone NULL.
     * redis enabled iff sentinel_redis sets redis_host. */
    lcf->redis_port      = NGX_CONF_UNSET;
    lcf->redis_interval  = NGX_CONF_UNSET;
    lcf->redis_ttl       = NGX_CONF_UNSET;

    /* cs_sink_path/scenario empty via pcalloc; cs_sink_zone NULL.
     * sink enabled iff sentinel_cs_sink_path sets cs_sink_path. */
    lcf->cs_sink_interval = NGX_CONF_UNSET;
    lcf->cs_sink_ttl      = NGX_CONF_UNSET;

    lcf->tarpit_max_conns    = NGX_CONF_UNSET;
    lcf->tarpit_delay        = NGX_CONF_UNSET;
    lcf->tarpit_bytes        = NGX_CONF_UNSET;
    lcf->tarpit_max_lifetime = NGX_CONF_UNSET;
    lcf->tarpit_maze         = NGX_CONF_UNSET;
    lcf->block_status        = NGX_CONF_UNSET;
    lcf->block_ttl           = NGX_CONF_UNSET;
    lcf->throttle_rate       = NGX_CONF_UNSET_SIZE;
    lcf->shield              = NGX_CONF_UNSET;

    lcf->pow_enabled         = NGX_CONF_UNSET;
    lcf->pow_difficulty      = NGX_CONF_UNSET;
    lcf->pow_ttl             = NGX_CONF_UNSET;
    /* pow_secret empty via pcalloc. */

    lcf->fcrdns_zone = NGX_CONF_UNSET_PTR;
    lcf->fcrdns_ttl  = NGX_CONF_UNSET;
    /* fcrdns_zone_name empty + fcrdns_suffixes empty via pcalloc. */

    return lcf;
}

static char *
ngx_sentinel_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_sentinel_loc_conf_t  *prev = parent;
    ngx_sentinel_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled,   prev->enabled,   0);
    ngx_conf_merge_value(conf->shadow,    prev->shadow,    1);  /* default shadow */
    ngx_conf_merge_value(conf->fail_open, prev->fail_open, 1);  /* default open   */

    ngx_conf_merge_value(conf->threshold.challenge,
                         prev->threshold.challenge,
                         NGX_SENTINEL_DEFAULT_THRESH_CH);
    ngx_conf_merge_value(conf->threshold.tarpit,
                         prev->threshold.tarpit,
                         NGX_SENTINEL_DEFAULT_THRESH_TP);
    ngx_conf_merge_value(conf->threshold.block,
                         prev->threshold.block,
                         NGX_SENTINEL_DEFAULT_THRESH_BK);

    ngx_conf_merge_value(conf->weights.errrate,
                         prev->weights.errrate,
                         NGX_SENTINEL_DEFAULT_W_ERRRATE);
    ngx_conf_merge_value(conf->weights.blocked,
                         prev->weights.blocked,
                         NGX_SENTINEL_DEFAULT_W_BLOCKED);
    ngx_conf_merge_value(conf->weights.scanner,
                         prev->weights.scanner,
                         NGX_SENTINEL_DEFAULT_W_SCANNER);
    ngx_conf_merge_value(conf->weights.bot,
                         prev->weights.bot,
                         NGX_SENTINEL_DEFAULT_W_BOT);
    ngx_conf_merge_value(conf->weights.header,
                         prev->weights.header,
                         NGX_SENTINEL_DEFAULT_W_HEADER);
    ngx_conf_merge_value(conf->weights.honeypot,
                         prev->weights.honeypot,
                         NGX_SENTINEL_DEFAULT_W_HONEYPOT);
    ngx_conf_merge_value(conf->weights.velocity,
                         prev->weights.velocity,
                         NGX_SENTINEL_DEFAULT_W_VELOCITY);
    ngx_conf_merge_value(conf->weights.asn,
                         prev->weights.asn,
                         NGX_SENTINEL_DEFAULT_W_ASN);
    ngx_conf_merge_value(conf->weights.ja4,
                         prev->weights.ja4,
                         NGX_SENTINEL_DEFAULT_W_JA4);
    ngx_conf_merge_value(conf->weights.coherence,
                         prev->weights.coherence,
                         NGX_SENTINEL_DEFAULT_W_COHERENCE);

    /* FCrDNS verify (enabled by binding a zone) + verdict-cache TTL. */
    ngx_conf_merge_value(conf->fcrdns_ttl, prev->fcrdns_ttl,
                         NGX_SENTINEL_FCRDNS_DEFAULT_TTL);
    ngx_conf_merge_ptr_value(conf->fcrdns_zone, prev->fcrdns_zone, NULL);
    if (conf->fcrdns_suffixes.nelts == 0 && prev->fcrdns_suffixes.nelts > 0) {
        conf->fcrdns_suffixes = prev->fcrdns_suffixes;
    }

    /* inherit fcrdns binding name; resolve name -> zone (same merit rule as
     * the velocity zone — an unknown name must error, not inherit silently). */
    if (conf->fcrdns_zone_name.len == 0 && prev->fcrdns_zone_name.len > 0) {
        conf->fcrdns_zone_name = prev->fcrdns_zone_name;
    }
    if (conf->fcrdns_zone_name.len > 0) {
        ngx_sentinel_main_conf_t  *mcf;
        ngx_sentinel_zone_t       *zones;
        ngx_uint_t                 i;

        conf->fcrdns_zone = NULL;
        mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
        zones = mcf->fcrdns_zones.elts;
        for (i = 0; i < mcf->fcrdns_zones.nelts; i++) {
            if (zones[i].name.len == conf->fcrdns_zone_name.len
                && ngx_strncmp(zones[i].name.data, conf->fcrdns_zone_name.data,
                               conf->fcrdns_zone_name.len) == 0)
            {
                conf->fcrdns_zone = &zones[i];
                break;
            }
        }
        if (conf->fcrdns_zone == NULL || conf->fcrdns_zone == NGX_CONF_UNSET_PTR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_fcrdns_zone: unknown zone \"%V\"",
                               &conf->fcrdns_zone_name);
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_ptr_value(conf->vel_zone, prev->vel_zone, NULL);

    /* inherit velocity binding name from parent location */
    if (conf->vel_zone_name.len == 0 && prev->vel_zone_name.len > 0) {
        conf->vel_zone_name = prev->vel_zone_name;
    }
    /* resolve name -> zone pointer */
    if (conf->vel_zone_name.len > 0) {
        ngx_sentinel_main_conf_t  *mcf;
        ngx_sentinel_zone_t       *zones;
        ngx_uint_t                 i;

        /* Drop any inherited pointer: a name MUST resolve on its own merit,
         * otherwise an unknown name silently keeps the parent's zone. */
        conf->vel_zone = NULL;

        mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
        zones = mcf->vel_zones.elts;
        for (i = 0; i < mcf->vel_zones.nelts; i++) {
            if (zones[i].name.len == conf->vel_zone_name.len
                && ngx_strncmp(zones[i].name.data, conf->vel_zone_name.data,
                               conf->vel_zone_name.len) == 0)
            {
                conf->vel_zone = &zones[i];
                break;
            }
        }
        if (conf->vel_zone == NULL || conf->vel_zone == NGX_CONF_UNSET_PTR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_velocity: unknown velocity zone \"%V\"",
                               &conf->vel_zone_name);
            return NGX_CONF_ERROR;
        }
    }

    /* Inherit decoy_paths from parent if not set locally. */
    if (conf->decoy_paths.nelts == 0 && prev->decoy_paths.nelts > 0) {
        conf->decoy_paths = prev->decoy_paths;
    }

    /* Inherit allow_cidrs from parent if not set locally. */
    if (conf->allow_cidrs.nelts == 0 && prev->allow_cidrs.nelts > 0) {
        conf->allow_cidrs = prev->allow_cidrs;
    }

    /* Inherit ASN source + flagged list from parent if not set locally. */
    if (conf->asn_source == NULL) {
        conf->asn_source = prev->asn_source;
    }
    if (conf->asn_list.nelts == 0 && prev->asn_list.nelts > 0) {
        conf->asn_list = prev->asn_list;
    }

    /* Inherit JA4 source + deny list from parent if not set locally. */
    if (conf->ja4_source == NULL) {
        conf->ja4_source = prev->ja4_source;
    }
    if (conf->ja4_list.nelts == 0 && prev->ja4_list.nelts > 0) {
        conf->ja4_list = prev->ja4_list;
    }

    ngx_conf_merge_value(conf->weights.crowdsec,
                         prev->weights.crowdsec,
                         NGX_SENTINEL_DEFAULT_W_CROWDSEC);

    /* Phase 3 — crowdsec feed params. */
    if (conf->cs_feed.len == 0) {
        conf->cs_feed = prev->cs_feed;
    }
    ngx_conf_merge_ptr_value(conf->cs_zone, prev->cs_zone, NULL);
    ngx_conf_merge_value(conf->cs_interval, prev->cs_interval,
                         NGX_SENTINEL_CROWDSEC_DEFAULT_INTERVAL);
    ngx_conf_merge_value(conf->cs_default_ttl, prev->cs_default_ttl,
                         NGX_SENTINEL_CROWDSEC_DEFAULT_TTL);
    ngx_conf_merge_value(conf->cs_stale_after, prev->cs_stale_after,
                         NGX_SENTINEL_CROWDSEC_DEFAULT_STALE);
    ngx_conf_merge_size_value(conf->cs_max_bytes, prev->cs_max_bytes,
                         (size_t) NGX_SENTINEL_CROWDSEC_DEFAULT_MAXBYTES);

    if (conf->weights.crowdsec < 0
        || conf->weights.crowdsec > NGX_SENTINEL_SCORE_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_weight_crowdsec must be 0..%d",
                           NGX_SENTINEL_SCORE_MAX);
        return NGX_CONF_ERROR;
    }
    if (conf->cs_interval < NGX_SENTINEL_CROWDSEC_MIN_INTERVAL
        || conf->cs_interval > NGX_SENTINEL_CROWDSEC_MAX_INTERVAL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_crowdsec_interval must be %d..%d s",
                           NGX_SENTINEL_CROWDSEC_MIN_INTERVAL,
                           NGX_SENTINEL_CROWDSEC_MAX_INTERVAL);
        return NGX_CONF_ERROR;
    }
    if (conf->cs_default_ttl < NGX_SENTINEL_CROWDSEC_MIN_TTL
        || conf->cs_default_ttl > NGX_SENTINEL_CROWDSEC_MAX_TTL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_crowdsec_default_ttl must be %d..%d s",
                           NGX_SENTINEL_CROWDSEC_MIN_TTL,
                           NGX_SENTINEL_CROWDSEC_MAX_TTL);
        return NGX_CONF_ERROR;
    }
    if (conf->cs_stale_after < NGX_SENTINEL_CROWDSEC_MIN_STALE
        || conf->cs_stale_after > NGX_SENTINEL_CROWDSEC_MAX_STALE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_crowdsec_stale_after must be %d..%d s",
                           NGX_SENTINEL_CROWDSEC_MIN_STALE,
                           NGX_SENTINEL_CROWDSEC_MAX_STALE);
        return NGX_CONF_ERROR;
    }
    if (conf->cs_max_bytes < ngx_pagesize
        || conf->cs_max_bytes > (size_t) NGX_SENTINEL_CROWDSEC_MAX_MAXBYTES)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_crowdsec_max_bytes must be %uz..%d",
                           (size_t) ngx_pagesize,
                           NGX_SENTINEL_CROWDSEC_MAX_MAXBYTES);
        return NGX_CONF_ERROR;
    }

    /* Redis multi-box shared state. */
    if (conf->redis_host.len == 0) {
        conf->redis_host = prev->redis_host;
        if (conf->redis_push_zone == NULL) {
            conf->redis_push_zone = prev->redis_push_zone;
        }
    }
    ngx_conf_merge_value(conf->redis_port, prev->redis_port,
                         NGX_SENTINEL_REDIS_DEFAULT_PORT);
    ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
    ngx_conf_merge_str_value(conf->redis_prefix, prev->redis_prefix,
                             NGX_SENTINEL_REDIS_DEFAULT_PREFIX);
    ngx_conf_merge_value(conf->redis_interval, prev->redis_interval,
                         NGX_SENTINEL_REDIS_DEFAULT_INTERVAL);
    ngx_conf_merge_value(conf->redis_ttl, prev->redis_ttl,
                         NGX_SENTINEL_REDIS_DEFAULT_TTL);

    if (conf->redis_host.len > 0) {
        if (conf->redis_interval < NGX_SENTINEL_REDIS_MIN_INTERVAL
            || conf->redis_interval > NGX_SENTINEL_REDIS_MAX_INTERVAL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_redis_interval must be %d..%d s",
                               NGX_SENTINEL_REDIS_MIN_INTERVAL,
                               NGX_SENTINEL_REDIS_MAX_INTERVAL);
            return NGX_CONF_ERROR;
        }
        if (conf->redis_ttl < NGX_SENTINEL_REDIS_MIN_TTL
            || conf->redis_ttl > NGX_SENTINEL_REDIS_MAX_TTL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_redis_ttl must be %d..%d s",
                               NGX_SENTINEL_REDIS_MIN_TTL,
                               NGX_SENTINEL_REDIS_MAX_TTL);
            return NGX_CONF_ERROR;
        }
    }

    /* CrowdSec decision sink. */
    if (conf->cs_sink_path.len == 0) {
        conf->cs_sink_path = prev->cs_sink_path;
        if (conf->cs_sink_zone == NULL) {
            conf->cs_sink_zone = prev->cs_sink_zone;
        }
    }
    ngx_conf_merge_value(conf->cs_sink_interval, prev->cs_sink_interval,
                         NGX_SENTINEL_CSSINK_INTERVAL);
    ngx_conf_merge_value(conf->cs_sink_ttl, prev->cs_sink_ttl,
                         NGX_SENTINEL_CSSINK_TTL);
    ngx_conf_merge_str_value(conf->cs_sink_scenario, prev->cs_sink_scenario,
                             NGX_SENTINEL_CSSINK_SCENARIO);

    if (conf->cs_sink_path.len > 0) {
        if (conf->cs_sink_interval < 1 || conf->cs_sink_interval > 3600) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_cs_sink_interval must be 1..3600 s");
            return NGX_CONF_ERROR;
        }
        if (conf->cs_sink_ttl < 60 || conf->cs_sink_ttl > 86400) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_cs_sink_ttl must be 60..86400 s");
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_value(conf->tarpit_max_conns,
                         prev->tarpit_max_conns, 256);
    ngx_conf_merge_value(conf->tarpit_delay,
                         prev->tarpit_delay, 5000);
    ngx_conf_merge_value(conf->tarpit_bytes,
                         prev->tarpit_bytes, 1024);
    ngx_conf_merge_value(conf->tarpit_max_lifetime,
                         prev->tarpit_max_lifetime, 30000);
    ngx_conf_merge_value(conf->tarpit_maze, prev->tarpit_maze, 0);

    /* Bounds validation (reject out-of-range values that slipped through). */
    if (conf->tarpit_max_conns < 0 || conf->tarpit_max_conns > 65536) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_max_conns must be 0..65536");
        return NGX_CONF_ERROR;
    }
    if (conf->tarpit_delay < 100 || conf->tarpit_delay > 60000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_delay must be 100..60000 ms");
        return NGX_CONF_ERROR;
    }
    if (conf->tarpit_bytes < 1 || conf->tarpit_bytes > 65536) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_bytes must be 1..65536");
        return NGX_CONF_ERROR;
    }
    if (conf->tarpit_max_lifetime < 1000
        || conf->tarpit_max_lifetime > NGX_SENTINEL_TARPIT_MAX_MSEC)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_max_lifetime must be 1000..%d ms",
                           NGX_SENTINEL_TARPIT_MAX_MSEC);
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->block_status, prev->block_status,
                         NGX_SENTINEL_DEFAULT_BLOCK_STATUS);

    /* 444 = special "drop connection" sentinel; otherwise a real HTTP status. */
    if (conf->block_status != NGX_HTTP_CLOSE
        && (conf->block_status < 400 || conf->block_status > 599))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_block_status must be 400..599 or 444");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->block_ttl, prev->block_ttl, 0);

    if (conf->block_ttl < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_block_ttl must be >= 0 (0 = off)");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->throttle_rate, prev->throttle_rate, 0);
    ngx_conf_merge_value(conf->shield, prev->shield, 0);

    ngx_conf_merge_value(conf->pow_enabled, prev->pow_enabled, 0);
    ngx_conf_merge_str_value(conf->pow_secret, prev->pow_secret, "");
    ngx_conf_merge_value(conf->pow_difficulty, prev->pow_difficulty, 16);
    ngx_conf_merge_value(conf->pow_ttl, prev->pow_ttl, 3600);

    if (conf->pow_difficulty < 1 || conf->pow_difficulty > 32) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_pow_difficulty must be 1..32");
        return NGX_CONF_ERROR;
    }
    if (conf->pow_ttl < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_pow_ttl must be >= 1");
        return NGX_CONF_ERROR;
    }

    /* inherit zone pointer from parent if not set locally */
    if (conf->zone == NULL) {
        conf->zone = prev->zone;
    }

    /*
     * Phase 1: single global zone. No per-location zone-binding directive yet,
     * so bind every sentinel location to the one configured sentinel_zone.
     * TODO Phase 3: a per-location `sentinel_zone <name>;` reference for
     * multiple named zones.
     */
    if (conf->zone == NULL) {
        ngx_sentinel_main_conf_t  *mcf;
        ngx_sentinel_zone_t       *zones;

        mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
        if (mcf != NULL && mcf->zones.nelts > 0) {
            zones = mcf->zones.elts;
            conf->zone = &zones[0];
        }
    }

    /*
     * Phase 3: bind to the single declared crowdsec zone if a feed is set but
     * no explicit cs_zone was assigned. Mirrors the errrate single-zone logic.
     * Redis multi-box also lands its pulled bans in the crowdsec zone, so the
     * same auto-bind applies when sentinel_redis is configured.
     */
    if (conf->cs_zone == NULL
        && (conf->cs_feed.len > 0 || conf->redis_host.len > 0))
    {
        ngx_sentinel_main_conf_t  *mcf;

        mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
        if (mcf != NULL && mcf->cs_zones.nelts > 0) {
            ngx_sentinel_zone_t  *zones = mcf->cs_zones.elts;
            conf->cs_zone = &zones[0];
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_crowdsec_feed/sentinel_redis set but "
                               "no sentinel_crowdsec_zone declared");
            return NGX_CONF_ERROR;
        }
    }

    /* The crowdsec zone's LRU age-out interval = stale_after. */
    if (conf->cs_zone != NULL) {
        conf->cs_zone->interval = conf->cs_stale_after;
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Directive handlers
 * ---------------------------------------------------------------------- */

static char *
ngx_sentinel_set_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_main_conf_t  *mcf = conf;
    ngx_sentinel_zone_t       *zone;
    ngx_str_t                 *value;
    ngx_str_t                  name;
    ssize_t                    size;
    u_char                    *colon;
    ngx_shm_zone_t            *shm;

    value = cf->args->elts;

    /* Parse "name:size" */
    colon = ngx_strlchr(value[1].data,
                        value[1].data + value[1].len, ':');
    if (colon == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_zone \"%V\": "
                           "expected name:size", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len  = (size_t) (colon - value[1].data);

    {
        ngx_str_t  sz_str;
        sz_str.data = colon + 1;
        sz_str.len  = value[1].len - name.len - 1;
        size = ngx_parse_size(&sz_str);
    }

    if (size == NGX_ERROR || size < (ssize_t) ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_zone size in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    zone = ngx_array_push(&mcf->zones);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(zone, sizeof(ngx_sentinel_zone_t));

    zone->name.data = ngx_pnalloc(cf->pool, name.len);
    if (zone->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(zone->name.data, name.data, name.len);
    zone->name.len  = name.len;

    zone->interval  = NGX_SENTINEL_DEFAULT_INTERVAL;
    zone->block     = NGX_SENTINEL_DEFAULT_BLOCK;
    zone->threshold = NGX_SENTINEL_MAX_WINDOW_EVENTS;

    shm = ngx_shared_memory_add(cf, &zone->name, (size_t) size,
                                 &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }

    shm->init = sentinel_shm_init_zone;
    shm->data = zone;

    zone->shm_zone = shm;

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_velocity_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_main_conf_t  *mcf = conf;
    ngx_sentinel_zone_t       *zone;
    ngx_str_t                 *value;
    ngx_str_t                  name;
    ssize_t                    size;
    u_char                    *colon;
    ngx_shm_zone_t            *shm;
    ngx_uint_t                 i;

    value = cf->args->elts;

    /* Parse "name:size" */
    colon = ngx_strlchr(value[1].data,
                        value[1].data + value[1].len, ':');
    if (colon == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_velocity_zone \"%V\": "
                           "expected name:size", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len  = (size_t) (colon - value[1].data);

    {
        ngx_str_t  sz_str;
        sz_str.data = colon + 1;
        sz_str.len  = value[1].len - name.len - 1;
        size = ngx_parse_size(&sz_str);
    }

    if (size == NGX_ERROR || size < (ssize_t) ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_velocity_zone size in \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    zone = ngx_array_push(&mcf->vel_zones);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(zone, sizeof(ngx_sentinel_zone_t));

    zone->name.data = ngx_pnalloc(cf->pool, name.len);
    if (zone->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(zone->name.data, name.data, name.len);
    zone->name.len  = name.len;

    zone->threshold = NGX_SENTINEL_VELOCITY_DEFAULT_THRESHOLD;
    zone->interval  = NGX_SENTINEL_VELOCITY_DEFAULT_WINDOW;
    zone->block     = NGX_SENTINEL_DEFAULT_BLOCK;

    /* Parse optional rate=N window=S block=S key=value args */
    for (i = 2; i < cf->args->nelts; i++) {
        ngx_str_t  arg = value[i];
        ngx_int_t  v;

        if (ngx_strncmp(arg.data, "rate=", 5) == 0) {
            ngx_str_t s = { arg.len - 5, arg.data + 5 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR || v < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "sentinel_velocity_zone: rate must be >= 1");
                return NGX_CONF_ERROR;
            }
            zone->threshold = (ngx_uint_t) v;

        } else if (ngx_strncmp(arg.data, "window=", 7) == 0) {
            ngx_str_t s = { arg.len - 7, arg.data + 7 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR || v < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "sentinel_velocity_zone: window must be >= 1");
                return NGX_CONF_ERROR;
            }
            zone->interval = (time_t) v;

        } else if (ngx_strncmp(arg.data, "block=", 6) == 0) {
            ngx_str_t s = { arg.len - 6, arg.data + 6 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR || v < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "sentinel_velocity_zone: block must be >= 1");
                return NGX_CONF_ERROR;
            }
            zone->block = (time_t) v;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_velocity_zone: unknown parameter \"%V\"",
                               &arg);
            return NGX_CONF_ERROR;
        }
    }

    shm = ngx_shared_memory_add(cf, &zone->name, (size_t) size,
                                 &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }

    shm->init = sentinel_shm_init_zone;
    shm->data = zone;

    zone->shm_zone = shm;

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_crowdsec_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_main_conf_t  *mcf = conf;
    ngx_sentinel_zone_t       *zone;
    ngx_str_t                 *value;
    ngx_str_t                  name;
    ssize_t                    size;
    u_char                    *colon;
    ngx_shm_zone_t            *shm;

    value = cf->args->elts;

    colon = ngx_strlchr(value[1].data,
                        value[1].data + value[1].len, ':');
    if (colon == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_crowdsec_zone \"%V\": "
                           "expected name:size", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len  = (size_t) (colon - value[1].data);

    {
        ngx_str_t  sz_str;
        sz_str.data = colon + 1;
        sz_str.len  = value[1].len - name.len - 1;
        size = ngx_parse_size(&sz_str);
    }

    if (size == NGX_ERROR || size < (ssize_t) ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_crowdsec_zone size in \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    zone = ngx_array_push(&mcf->cs_zones);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(zone, sizeof(ngx_sentinel_zone_t));

    zone->name.data = ngx_pnalloc(cf->pool, name.len);
    if (zone->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(zone->name.data, name.data, name.len);
    zone->name.len  = name.len;

    /* crowdsec nodes carry no event ring (threshold==0); block unused. */
    zone->interval  = NGX_SENTINEL_CROWDSEC_DEFAULT_STALE;
    zone->block     = 0;
    zone->threshold = 0;

    shm = ngx_shared_memory_add(cf, &zone->name, (size_t) size,
                                 &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }

    shm->init = sentinel_shm_init_zone;
    shm->data = zone;

    zone->shm_zone = shm;

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_fcrdns_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_main_conf_t  *mcf = conf;
    ngx_sentinel_zone_t       *zone;
    ngx_str_t                 *value;
    ngx_str_t                  name;
    ssize_t                    size;
    u_char                    *colon;
    ngx_shm_zone_t            *shm;

    value = cf->args->elts;

    colon = ngx_strlchr(value[1].data,
                        value[1].data + value[1].len, ':');
    if (colon == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_fcrdns_zone \"%V\": "
                           "expected name:size", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len  = (size_t) (colon - value[1].data);

    {
        ngx_str_t  sz_str;
        sz_str.data = colon + 1;
        sz_str.len  = value[1].len - name.len - 1;
        size = ngx_parse_size(&sz_str);
    }

    if (size == NGX_ERROR || size < (ssize_t) ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_fcrdns_zone size in \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    zone = ngx_array_push(&mcf->fcrdns_zones);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(zone, sizeof(ngx_sentinel_zone_t));

    zone->name.data = ngx_pnalloc(cf->pool, name.len);
    if (zone->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(zone->name.data, name.data, name.len);
    zone->name.len  = name.len;

    /* verdict-cache nodes carry no event ring (threshold==0). interval drives
     * the LRU age-out backstop for abandoned entries. */
    zone->interval  = NGX_SENTINEL_FCRDNS_DEFAULT_TTL;
    zone->block     = 0;
    zone->threshold = 0;

    shm = ngx_shared_memory_add(cf, &zone->name, (size_t) size,
                                 &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }

    shm->init = sentinel_shm_init_zone;
    shm->data = zone;

    zone->shm_zone = shm;

    return NGX_CONF_OK;
}

/* sentinel_fcrdns <zone>;  — bind a location to an FCrDNS verdict-cache zone
 * (also enables the signal). The zone name is resolved to a pointer at merge. */
static char *
ngx_sentinel_set_fcrdns(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value = cf->args->elts;

    if (lcf->fcrdns_zone_name.len != 0) {
        return "is duplicate";
    }
    lcf->fcrdns_zone_name = value[1];
    return NGX_CONF_OK;
}

/* sentinel_fcrdns_verify_suffix <suffix>...;  — restrict accepted PTR names. */
static char *
ngx_sentinel_set_fcrdns_suffix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value = cf->args->elts;
    ngx_str_t                *suf;
    ngx_uint_t                i;

    if (lcf->fcrdns_suffixes.elts == NULL) {
        if (ngx_array_init(&lcf->fcrdns_suffixes, cf->pool, 4,
                           sizeof(ngx_str_t)) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        suf = ngx_array_push(&lcf->fcrdns_suffixes);
        if (suf == NULL) {
            return NGX_CONF_ERROR;
        }
        *suf = value[i];
    }

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_crowdsec_feed(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;

    value = cf->args->elts;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_crowdsec_feed path must be non-empty");
        return NGX_CONF_ERROR;
    }

    /* NUL-terminate for ngx_file_info / ngx_open_file. */
    lcf->cs_feed.len  = value[1].len;
    lcf->cs_feed.data = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (lcf->cs_feed.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(lcf->cs_feed.data, value[1].data, value[1].len);
    lcf->cs_feed.data[value[1].len] = '\0';

    return NGX_CONF_OK;
}

/*
 * sentinel_redis host[:port];
 * Enables Redis multi-box shared state. Parses host (NUL-terminated for hiredis)
 * + optional :port, and declares a dedicated fixed-size push-ring shm zone.
 */
static char *
ngx_sentinel_set_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_str_t                 host, zname;
    u_char                   *colon;
    ngx_int_t                 port;
    ngx_shm_zone_t           *shm;
    size_t                    zsize;

    value = cf->args->elts;

    if (lcf->redis_host.len > 0) {
        return "is duplicate";
    }
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_redis host must be non-empty");
        return NGX_CONF_ERROR;
    }

    host = value[1];
    port = NGX_SENTINEL_REDIS_DEFAULT_PORT;

    /* Split off :port (last colon; bracketless — IPv6 literals use a hostname
     * or DNS name in practice for this directive). */
    colon = ngx_strlchr(value[1].data, value[1].data + value[1].len, ':');
    if (colon != NULL) {
        ngx_str_t  pstr;
        host.len = (size_t) (colon - value[1].data);
        pstr.data = colon + 1;
        pstr.len  = value[1].len - host.len - 1;
        if (pstr.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_redis: empty port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        port = ngx_atoi(pstr.data, pstr.len);
        if (port == NGX_ERROR || port < 1 || port > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_redis: bad port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }
    if (host.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_redis host must be non-empty");
        return NGX_CONF_ERROR;
    }

    /* NUL-terminate host for hiredis. */
    lcf->redis_host.data = ngx_pnalloc(cf->pool, host.len + 1);
    if (lcf->redis_host.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(lcf->redis_host.data, host.data, host.len);
    lcf->redis_host.data[host.len] = '\0';
    lcf->redis_host.len  = host.len;
    lcf->redis_port      = port;

    /* Declare a dedicated push-ring shm zone. One ring per host[:port] endpoint
     * (name derived from host:port so two distinct endpoints get distinct
     * zones; identical endpoints across locations share one ring). Size = the
     * fixed ring struct + slab overhead, rounded up to whole pages. */
    zname.len  = sizeof("sentinel_redis_push_") - 1 + value[1].len;
    zname.data = ngx_pnalloc(cf->pool, zname.len);
    if (zname.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_sprintf(zname.data, "sentinel_redis_push_%V", &value[1]);

    zsize = sizeof(ngx_sentinel_redis_shctx_t) + 4 * ngx_pagesize;
    zsize = ngx_align(zsize, ngx_pagesize);

    shm = ngx_shared_memory_add(cf, &zname, zsize, &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }
    shm->init = sentinel_redis_init_zone;
    shm->data = NULL;

    lcf->redis_push_zone = shm;

    return NGX_CONF_OK;
}


/* sentinel_cs_sink_path <file>; — enable the CrowdSec decision sink and declare
 * its dedicated ring shm zone (one per distinct path). */
static char *
ngx_sentinel_set_cs_sink(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_str_t                 zname;
    ngx_shm_zone_t           *shm;
    size_t                    zsize;

    value = cf->args->elts;

    if (lcf->cs_sink_path.len > 0) {
        return "is duplicate";
    }
    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_cs_sink_path must be non-empty");
        return NGX_CONF_ERROR;
    }

    /* NUL-terminate the path for ngx_open_file/ngx_rename_file. */
    lcf->cs_sink_path.data = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (lcf->cs_sink_path.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(lcf->cs_sink_path.data, value[1].data, value[1].len);
    lcf->cs_sink_path.data[value[1].len] = '\0';
    lcf->cs_sink_path.len = value[1].len;

    /* Dedicated sink-ring shm zone, keyed on the path so two distinct sink
     * files get distinct rings (identical paths across locations share one). */
    zname.len  = sizeof("sentinel_cs_sink_") - 1 + value[1].len;
    zname.data = ngx_pnalloc(cf->pool, zname.len);
    if (zname.data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_sprintf(zname.data, "sentinel_cs_sink_%V", &value[1]);

    zsize = sizeof(ngx_sentinel_cssink_shctx_t) + 4 * ngx_pagesize;
    zsize = ngx_align(zsize, ngx_pagesize);

    shm = ngx_shared_memory_add(cf, &zname, zsize, &ngx_http_sentinel_module);
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }
    shm->init = sentinel_cssink_init_zone;
    shm->data = NULL;

    lcf->cs_sink_zone = shm;

    return NGX_CONF_OK;
}


static char *
ngx_sentinel_set_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "shadow") == 0) {
        lcf->shadow = 1;
    } else if (ngx_strcmp(value[1].data, "enforce") == 0) {
        lcf->shadow = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_mode \"%V\": "
                           "expected shadow or enforce", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_fail(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "open") == 0) {
        lcf->fail_open = 1;
    } else if (ngx_strcmp(value[1].data, "closed") == 0) {
        lcf->fail_open = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_fail \"%V\": "
                           "expected open or closed", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_threshold(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_str_t  arg = value[i];
        ngx_int_t  v;

        if (ngx_strncmp(arg.data, "challenge=", 10) == 0) {
            ngx_str_t s = { arg.len - 10, arg.data + 10 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR) { goto bad; }
            lcf->threshold.challenge = v;

        } else if (ngx_strncmp(arg.data, "tarpit=", 7) == 0) {
            ngx_str_t s = { arg.len - 7, arg.data + 7 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR) { goto bad; }
            lcf->threshold.tarpit = v;

        } else if (ngx_strncmp(arg.data, "block=", 6) == 0) {
            ngx_str_t s = { arg.len - 6, arg.data + 6 };
            v = ngx_atoi(s.data, s.len);
            if (v == NGX_ERROR) { goto bad; }
            lcf->threshold.block = v;

        } else {
            goto bad;
        }

        continue;
bad:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid sentinel_threshold parameter \"%V\"",
                           &arg);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Phase 2 — tarpit directive handlers (bounds validated at parse time).
 * ---------------------------------------------------------------------- */

static char *
ngx_sentinel_set_tarpit_delay(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_int_t                 v;

    value = cf->args->elts;
    v = ngx_atoi(value[1].data, value[1].len);

    if (v == NGX_ERROR || v < 100 || v > 60000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_delay must be 100..60000 ms, got \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->tarpit_delay = v;
    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_tarpit_bytes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_int_t                 v;

    value = cf->args->elts;
    v = ngx_atoi(value[1].data, value[1].len);

    if (v == NGX_ERROR || v < 1 || v > 65536) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_bytes must be 1..65536, got \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->tarpit_bytes = v;
    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_tarpit_lifetime(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_int_t                 v;

    value = cf->args->elts;
    v = ngx_atoi(value[1].data, value[1].len);

    if (v == NGX_ERROR || v < 1000 || v > NGX_SENTINEL_TARPIT_MAX_MSEC) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "sentinel_tarpit_max_lifetime must be 1000..%d ms, "
                           "got \"%V\"",
                           NGX_SENTINEL_TARPIT_MAX_MSEC, &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->tarpit_max_lifetime = v;
    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Honeypot directive handler: push each path arg into lcf->decoy_paths.
 * ---------------------------------------------------------------------- */

static char *
sentinel_conf_honeypot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_str_t                *slot;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_honeypot: empty path argument");
            return NGX_CONF_ERROR;
        }

        if (lcf->decoy_paths.elts == NULL) {
            if (ngx_array_init(&lcf->decoy_paths, cf->pool, 4,
                               sizeof(ngx_str_t)) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(&lcf->decoy_paths);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        *slot = value[i];
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Allowlist directive handler: parse each IP/CIDR arg into lcf->allow_cidrs.
 * ---------------------------------------------------------------------- */

static char *
sentinel_conf_allowlist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_cidr_t               *slot;
    ngx_uint_t                i;
    ngx_int_t                 rc;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_allowlist: empty argument");
            return NGX_CONF_ERROR;
        }

        if (lcf->allow_cidrs.elts == NULL) {
            if (ngx_array_init(&lcf->allow_cidrs, cf->pool, 4,
                               sizeof(ngx_cidr_t)) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(&lcf->allow_cidrs);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        rc = ngx_ptocidr(&value[i], slot);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_allowlist: invalid address \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "sentinel_allowlist: low address bits of \"%V\" "
                               "are meaningful", &value[i]);
        }
    }

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * ASN directive handlers.
 *
 * sentinel_asn <variable>;  — compile the operator-supplied geoip2 ASN source
 *                             into a complex value (evaluated per request).
 * sentinel_datacenter_asn N [N ...];  — flagged ASN list (unsigned).
 * ---------------------------------------------------------------------- */

static char *
sentinel_conf_asn_source(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t           *lcf = conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (lcf->asn_source != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lcf->asn_source = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (lcf->asn_source == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = lcf->asn_source;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
sentinel_conf_datacenter_asn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_uint_t               *slot;
    ngx_uint_t                i;
    ngx_int_t                 v;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        v = ngx_atoi(value[i].data, value[i].len);
        if (v == NGX_ERROR || v <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_datacenter_asn: invalid ASN \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        if (lcf->asn_list.elts == NULL) {
            if (ngx_array_init(&lcf->asn_list, cf->pool, 8,
                               sizeof(ngx_uint_t)) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(&lcf->asn_list);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        *slot = (ngx_uint_t) v;
    }

    return NGX_CONF_OK;
}


/* ----------------------------------------------------------------------
 * sentinel_ja4 <variable>;  — compile the operator-supplied ssl-fingerprint
 *                             JA4 source into a complex value (per request).
 * sentinel_ja4_deny <ja4|hash> [...];  — denied JA4 (TLS) fingerprint list.
 * ---------------------------------------------------------------------- */

static char *
sentinel_conf_ja4_source(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t           *lcf = conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (lcf->ja4_source != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lcf->ja4_source = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (lcf->ja4_source == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = lcf->ja4_source;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
sentinel_conf_ja4_deny(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;
    ngx_str_t                *slot;
    ngx_uint_t                i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_ja4_deny: empty fingerprint");
            return NGX_CONF_ERROR;
        }

        if (lcf->ja4_list.elts == NULL) {
            if (ngx_array_init(&lcf->ja4_list, cf->pool, 8,
                               sizeof(ngx_str_t)) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        slot = ngx_array_push(&lcf->ja4_list);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }

        *slot = value[i];
    }

    return NGX_CONF_OK;
}

static char *
ngx_sentinel_set_velocity_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_sentinel_loc_conf_t  *lcf = conf;
    ngx_str_t                *value;

    value = cf->args->elts;
    lcf->vel_zone_name = value[1];

    return NGX_CONF_OK;
}

/* -------------------------------------------------------------------------
 * Tarpit shm init callback: wire the per-worker counter array into mcf.
 * ---------------------------------------------------------------------- */

static ngx_int_t
ngx_sentinel_tarpit_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_sentinel_main_conf_t  *mcf;
    ngx_slab_pool_t           *shpool;
    ngx_atomic_t              *conns;

    /*
     * shm_zone->data carries the CURRENT cycle's mcf (set in
     * ngx_sentinel_init_tarpit_shm). It is only dereferenced here, within the
     * cycle that owns it, so it is always valid — we never carry a stale conf
     * pointer across cycles. The counter array itself lives inside the slab
     * pool (survives reload via shpool->data), NOT at raw shm.addr: every
     * shared zone is slab-initialized by ngx_init_zone_pool() before this
     * callback runs, so writing raw bytes over shm.addr would clobber the slab
     * pool header (and its mutex, which the master force-unlocks on SIGCHLD →
     * SIGSEGV).
     */
    mcf    = shm_zone->data;
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /*
     * One slab block holds BOTH the tarpit per-worker sub-counters and the
     * Prometheus metrics array, laid out as
     *   [ tarpit_conns: ngx_atomic_t[NGX_MAX_PROCESSES] ]
     *   [ metrics:      ngx_atomic_t[NGX_SENTINEL_M_MAX] ]
     * so the existing piggyback shm carries metrics with no new zone directive.
     */
    if (shm_zone->shm.exists) {
        /* Reload / inherited segment: reuse the existing block. */
        mcf->tarpit_conns = shpool->data;
        mcf->metrics      = (ngx_atomic_t *) shpool->data + NGX_MAX_PROCESSES;
        return NGX_OK;
    }

    conns = ngx_slab_alloc(shpool,
        sizeof(ngx_atomic_t) * (NGX_MAX_PROCESSES + NGX_SENTINEL_M_MAX));
    if (conns == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero((void *) conns,
        sizeof(ngx_atomic_t) * (NGX_MAX_PROCESSES + NGX_SENTINEL_M_MAX));

    shpool->data      = (void *) conns;
    mcf->tarpit_conns = conns;
    mcf->metrics      = conns + NGX_MAX_PROCESSES;

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * init_process: zero this worker's tarpit sub-counter slot.
 * ---------------------------------------------------------------------- */

static ngx_int_t
ngx_sentinel_init_process(ngx_cycle_t *cycle)
{
    ngx_int_t  rc;

    rc = sentinel_tarpit_init_process(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Phase 3: arm per-worker crowdsec feed-refresh timers (compose, don't
     * clobber, the tarpit init). Fail-open: returns NGX_OK on any error. */
    rc = sentinel_crowdsec_init_process(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Redis multi-box: arm the per-worker async sync timer. Fail-open. */
    rc = sentinel_redis_init_process(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    /* CrowdSec decision sink: arm the per-worker drain/rewrite timer.
     * Fail-open. */
    return sentinel_cssink_init_process(cycle);
}
