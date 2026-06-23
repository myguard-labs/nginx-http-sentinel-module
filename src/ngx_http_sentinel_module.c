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

static ngx_sentinel_ctx_t *ngx_sentinel_get_ctx(ngx_http_request_t *r);

/* -------------------------------------------------------------------------
 * Directive table
 * ---------------------------------------------------------------------- */

static ngx_command_t ngx_sentinel_commands[] = {

    /* sentinel on|off; — location context */
    { ngx_string("sentinel"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, enabled),
      NULL },

    /* sentinel_mode shadow|enforce; — location context */
    { ngx_string("sentinel_mode"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
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
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_fail,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_threshold challenge=N tarpit=M block=K; — location context */
    { ngx_string("sentinel_threshold"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      ngx_sentinel_set_threshold,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_weight_errrate N; — per error event in burst window */
    { ngx_string("sentinel_weight_errrate"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.errrate),
      NULL },

    /* sentinel_weight_blocked N; — identity already blocked */
    { ngx_string("sentinel_weight_blocked"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.blocked),
      NULL },

    /* sentinel_weight_scanner N; — scanner-path prefix hit */
    { ngx_string("sentinel_weight_scanner"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.scanner),
      NULL },

    /* sentinel_weight_bot N; — heuristic bot user-agent */
    { ngx_string("sentinel_weight_bot"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.bot),
      NULL },

    /* ---- Phase 2: tarpit directives ---- */

    /* sentinel_tarpit_max_conns N;  default 256; 0=disabled (all TARPIT->444) */
    { ngx_string("sentinel_tarpit_max_conns"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, tarpit_max_conns),
      NULL },

    /* sentinel_tarpit_delay ms;  default 5000; bounds [100, 60000] */
    { ngx_string("sentinel_tarpit_delay"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_delay,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_tarpit_bytes N;  default 1024; bounds [1, 65536] */
    { ngx_string("sentinel_tarpit_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_bytes,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_tarpit_max_lifetime ms;  default 30000; bounds [1000, 600000] */
    { ngx_string("sentinel_tarpit_max_lifetime"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_tarpit_lifetime,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* ---- Phase 3: crowdsec decision-feed directives ---- */

    /* sentinel_crowdsec_zone name:size; — main context (declares the shm zone) */
    { ngx_string("sentinel_crowdsec_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_crowdsec_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_crowdsec_feed path; — location: feed file (off if unset) */
    { ngx_string("sentinel_crowdsec_feed"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_sentinel_set_crowdsec_feed,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* sentinel_crowdsec_interval time; — refresh tick (default 10s) */
    { ngx_string("sentinel_crowdsec_interval"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_interval),
      NULL },

    /* sentinel_crowdsec_default_ttl time; — TTL for expiry==0 lines */
    { ngx_string("sentinel_crowdsec_default_ttl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_default_ttl),
      NULL },

    /* sentinel_crowdsec_stale_after time; — stale threshold + LRU age-out */
    { ngx_string("sentinel_crowdsec_stale_after"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_stale_after),
      NULL },

    /* sentinel_crowdsec_max_bytes size; — feed size cap */
    { ngx_string("sentinel_crowdsec_max_bytes"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, cs_max_bytes),
      NULL },

    /* sentinel_weight_crowdsec N; — base score weight for a crowdsec ban */
    { ngx_string("sentinel_weight_crowdsec"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_sentinel_loc_conf_t, weights.crowdsec),
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

    /* Gather all three signals. */
    sentinel_ja4h_compute(r, ctx->inputs.ja4h);
    sentinel_errrate_signal(r, lcf, &ctx->inputs);
    sentinel_botua_signal(r, &ctx->inputs);
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
                  "shadow=%i errrate=%ui bot=%i scanner=%i "
                  "crowdsec=%i cs_action=%ui",
                  ctx->score,
                  verdict_strings[ctx->verdict],
                  ctx->inputs.ja4h,
                  (ngx_int_t) lcf->shadow,
                  ctx->inputs.errrate_count,
                  (ngx_int_t) ctx->inputs.bot_ua,
                  (ngx_int_t) ctx->inputs.scanner_path,
                  (ngx_int_t) ctx->inputs.crowdsec_hit,
                  (ngx_uint_t) ctx->inputs.crowdsec_action);

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
        /* TODO Phase 2: redirect to challenge URI / js-challenge handoff */
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sentinel: verdict=challenge (enforce deferred Phase 2)");
        return NGX_DECLINED;

    case NGX_SENTINEL_VERDICT_TARPIT:
        {
            ngx_int_t  trc;

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
        /* TODO Phase 2: return 403 / 444 */
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sentinel: verdict=block (enforce deferred Phase 2)");
        return NGX_DECLINED;
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

    zone = lcf->zone;
    if (zone == NULL) {
        return NGX_OK;  /* no zone configured — fail-open */
    }

    /*
     * Determine response status.  Check err_status first (set by nginx
     * internally for error pages), matching the access-log module convention.
     */
    status = (r->err_status != 0) ? r->err_status : r->headers_out.status;

    /* Only record error responses. (TODO: make configurable in a later phase.) */
    if (status < 400) {
        return NGX_OK;
    }

    /* Build identity: SHA-256($addr_text) — same derivation as errrate_signal. */
    if (r->connection->addr_text.len == 0) {
        return NGX_OK;  /* no client address — fail-open */
    }

    SHA256(r->connection->addr_text.data, r->connection->addr_text.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

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
    lcf->weights.crowdsec = NGX_CONF_UNSET;

    lcf->cs_zone         = NGX_CONF_UNSET_PTR;
    lcf->cs_interval     = NGX_CONF_UNSET;
    lcf->cs_default_ttl  = NGX_CONF_UNSET;
    lcf->cs_stale_after  = NGX_CONF_UNSET;
    lcf->cs_max_bytes    = NGX_CONF_UNSET_SIZE;

    lcf->tarpit_max_conns    = NGX_CONF_UNSET;
    lcf->tarpit_delay        = NGX_CONF_UNSET;
    lcf->tarpit_bytes        = NGX_CONF_UNSET;
    lcf->tarpit_max_lifetime = NGX_CONF_UNSET;

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

    ngx_conf_merge_value(conf->tarpit_max_conns,
                         prev->tarpit_max_conns, 256);
    ngx_conf_merge_value(conf->tarpit_delay,
                         prev->tarpit_delay, 5000);
    ngx_conf_merge_value(conf->tarpit_bytes,
                         prev->tarpit_bytes, 1024);
    ngx_conf_merge_value(conf->tarpit_max_lifetime,
                         prev->tarpit_max_lifetime, 30000);

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
     */
    if (conf->cs_zone == NULL && conf->cs_feed.len > 0) {
        ngx_sentinel_main_conf_t  *mcf;

        mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sentinel_module);
        if (mcf != NULL && mcf->cs_zones.nelts > 0) {
            ngx_sentinel_zone_t  *zones = mcf->cs_zones.elts;
            conf->cs_zone = &zones[0];
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sentinel_crowdsec_feed set but no "
                               "sentinel_crowdsec_zone declared");
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

    if (shm_zone->shm.exists) {
        /* Reload / inherited segment: reuse the existing array. */
        mcf->tarpit_conns = shpool->data;
        return NGX_OK;
    }

    conns = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t) * NGX_MAX_PROCESSES);
    if (conns == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero((void *) conns, sizeof(ngx_atomic_t) * NGX_MAX_PROCESSES);

    shpool->data      = (void *) conns;
    mcf->tarpit_conns = conns;

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
    return sentinel_crowdsec_init_process(cycle);
}
