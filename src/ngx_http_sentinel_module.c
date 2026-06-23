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
    NULL,                       /* init master       */
    NULL,                       /* init module       */
    NULL,                       /* init process      */
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
                  "shadow=%i errrate=%ui bot=%i scanner=%i",
                  ctx->score,
                  verdict_strings[ctx->verdict],
                  ctx->inputs.ja4h,
                  (ngx_int_t) lcf->shadow,
                  ctx->inputs.errrate_count,
                  (ngx_int_t) ctx->inputs.bot_ua,
                  (ngx_int_t) ctx->inputs.scanner_path);

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
        /* TODO Phase 2: tarpit drip write, connection cap */
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "sentinel: verdict=tarpit (enforce deferred Phase 2)");
        return NGX_DECLINED;

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
ngx_sentinel_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

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
