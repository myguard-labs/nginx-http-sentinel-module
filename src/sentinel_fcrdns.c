/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_fcrdns.c — Forward-Confirmed reverse-DNS verification for
 *                     self-declaring crawlers (Googlebot, Bingbot, ...).
 *
 * A `User-Agent: Googlebot` header is trivially spoofable; sentinel_botua.c
 * sets inputs->known_good_ua on the substring alone, and the score lets that
 * short-circuit the in-module heuristics. That is an auth-bypass risk. FCrDNS
 * closes it: when enabled, a known_good_ua request triggers an ASYNCHRONOUS
 * PTR lookup of the client IP, then a forward (A/AAAA) lookup of the resolved
 * name, and only treats the crawler claim as genuine if the forward result
 * contains the original client IP (optionally with a configured PTR-name
 * suffix, e.g. ".googlebot.com").
 *
 * The verdict (VERIFIED / FAILED) is cached per-IP in a dedicated shm zone for
 * fcrdns_ttl seconds. The DNS work NEVER blocks the request path: the first
 * request from an IP fails open (verdict PENDING → known_good_ua keeps its
 * legacy documented-spoofable behavior for that one request) and kicks the
 * async resolve; the cached verdict governs every subsequent request.
 *
 * Lifetime: the request may finalize long before the resolver callbacks fire,
 * so the resolve carrier (a copy of the IP key + zone + resolver + ttl + log)
 * is heap-allocated with ngx_alloc and freed only in the terminal callback —
 * NOT taken from the request pool (that would be a use-after-free).
 *
 * Fail-open everywhere: no resolver configured, lookup error/timeout, NXDOMAIN,
 * allocation failure, zone error → the verdict is left FAILED only on a
 * positive disproof; transient failures cache nothing and simply retry later.
 */

#include "sentinel.h"


/* ---------------------------------------------------------------------------
 * shm verdict cache — mirrors the crowdsec node store (cs_action carries the
 * verdict tier, blocked_until carries the cache-entry expiry).
 * ------------------------------------------------------------------------- */

ngx_uint_t
sentinel_shm_fcrdns_get(ngx_sentinel_zone_t *zone, ngx_str_t *key, time_t now)
{
    u_char      action;
    ngx_int_t   rc;

    /* Reuse the crowdsec lookup machinery: it returns NGX_BUSY + *action when an
     * unexpired entry exists, NGX_OK otherwise. Here "action" is our verdict. */
    rc = sentinel_shm_crowdsec_lookup(zone, key, now, &action);
    if (rc != NGX_BUSY) {
        return NGX_SENTINEL_FCRDNS_PENDING;
    }
    return (ngx_uint_t) action;
}


ngx_int_t
sentinel_shm_fcrdns_set(ngx_sentinel_zone_t *zone, ngx_str_t *key,
    ngx_uint_t verdict, time_t now, time_t ttl)
{
    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&zone->shpool->mutex);
    /* generation 0: FCrDNS never sweeps by generation (TTL/LRU only). */
    {
        ngx_int_t rc = sentinel_shm_crowdsec_upsert(zone, key, now + ttl,
                                                    (u_char) verdict, 0, now, 0);
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return rc;
    }
}


/* ---------------------------------------------------------------------------
 * Async resolver chain
 * ------------------------------------------------------------------------- */

typedef struct {
    ngx_sentinel_zone_t  *zone;       /* verdict-cache zone (shm)            */
    ngx_resolver_t       *resolver;   /* core resolver                       */
    ngx_msec_t            timeout;    /* per-lookup timeout                  */
    ngx_log_t            *log;        /* cycle log (outlives the request)    */
    time_t                ttl;        /* verdict cache TTL                   */
    ngx_array_t          *suffixes;   /* allowed PTR-name suffixes (or NULL) */

    /* The client IP we are confirming, in both shm-key and sockaddr form. */
    u_char                key[NGX_SENTINEL_DIGEST_LEN];
    size_t                key_len;
    struct sockaddr_storage  ss;
    socklen_t             ss_len;

    /* PTR result name (heap copy) carried into the forward lookup. */
    ngx_str_t             ptr_name;
} sentinel_fcrdns_carrier_t;


static void sentinel_fcrdns_ptr_handler(ngx_resolver_ctx_t *ctx);
static void sentinel_fcrdns_fwd_handler(ngx_resolver_ctx_t *ctx);


/* Cache the verdict and release the carrier. */
static void
sentinel_fcrdns_finish(sentinel_fcrdns_carrier_t *c, ngx_uint_t verdict,
    time_t now)
{
    ngx_str_t  key;

    key.data = c->key;
    key.len  = c->key_len;

    if (verdict != NGX_SENTINEL_FCRDNS_PENDING) {
        (void) sentinel_shm_fcrdns_set(c->zone, &key, verdict, now, c->ttl);
    }

    if (c->ptr_name.data) {
        ngx_free(c->ptr_name.data);
    }
    ngx_free(c);
}


/* Does `name` end with one of the configured suffixes? Empty list = accept. */
static int
sentinel_fcrdns_suffix_ok(sentinel_fcrdns_carrier_t *c, ngx_str_t *name)
{
    ngx_str_t   *suf;
    ngx_uint_t   i;

    if (c->suffixes == NULL || c->suffixes->nelts == 0) {
        return 1;
    }

    suf = c->suffixes->elts;
    for (i = 0; i < c->suffixes->nelts; i++) {
        if (name->len >= suf[i].len
            && ngx_strncasecmp(name->data + (name->len - suf[i].len),
                               suf[i].data, suf[i].len) == 0)
        {
            return 1;
        }
    }
    return 0;
}


void
sentinel_fcrdns_resolve_start(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_resolver_t *resolver,
    ngx_str_t *key)
{
    sentinel_fcrdns_carrier_t  *c;
    ngx_resolver_ctx_t         *rctx;
    struct sockaddr            *sa;
    socklen_t                   salen;

    sa    = r->connection->sockaddr;
    salen = r->connection->socklen;
    if (sa == NULL || salen == 0 || salen > (socklen_t) sizeof(c->ss)) {
        return;   /* fail-open: cannot form the PTR target */
    }

    /* Heap carrier — must outlive the request (see file header). */
    c = ngx_alloc(sizeof(sentinel_fcrdns_carrier_t), ngx_cycle->log);
    if (c == NULL) {
        return;   /* fail-open */
    }
    ngx_memzero(c, sizeof(*c));

    c->zone     = lcf->fcrdns_zone;
    c->resolver = resolver;
    c->timeout  = NGX_SENTINEL_FCRDNS_RESOLVE_MSEC;
    c->log      = ngx_cycle->log;
    c->ttl      = (lcf->fcrdns_ttl > 0)
                  ? lcf->fcrdns_ttl : NGX_SENTINEL_FCRDNS_DEFAULT_TTL;
    c->suffixes = (lcf->fcrdns_suffixes.nelts > 0)
                  ? &lcf->fcrdns_suffixes : NULL;
    c->key_len  = ngx_min(key->len, (size_t) NGX_SENTINEL_DIGEST_LEN);
    ngx_memcpy(c->key, key->data, c->key_len);
    ngx_memcpy(&c->ss, sa, salen);
    c->ss_len   = salen;

    rctx = ngx_resolve_start(resolver, NULL);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        ngx_free(c);
        return;   /* fail-open: no resolver */
    }

    rctx->addr.sockaddr = (struct sockaddr *) &c->ss;
    rctx->addr.socklen  = c->ss_len;
    rctx->handler       = sentinel_fcrdns_ptr_handler;
    rctx->data          = c;
    rctx->timeout       = c->timeout;

    if (ngx_resolve_addr(rctx) != NGX_OK) {
        ngx_free(c);   /* rctx is released by ngx_resolve_addr on failure */
    }
}


/* PTR callback: validate the resolved name, then forward-confirm it. */
static void
sentinel_fcrdns_ptr_handler(ngx_resolver_ctx_t *ctx)
{
    sentinel_fcrdns_carrier_t  *c = ctx->data;
    ngx_resolver_ctx_t         *fctx;
    time_t                      now;

    now = ngx_time();

    if (ctx->state != NGX_OK || ctx->name.len == 0) {
        /* No PTR / lookup error — cannot confirm; do NOT cache a FAILED on a
         * transient error, just release (retry on next request). */
        ngx_resolve_addr_done(ctx);
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_PENDING, now);
        return;
    }

    /* Suffix gate (e.g. ".googlebot.com"): a wrong-domain PTR is a positive
     * disproof of the crawler claim → cache FAILED. */
    if (!sentinel_fcrdns_suffix_ok(c, &ctx->name)) {
        ngx_resolve_addr_done(ctx);
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_FAILED, now);
        return;
    }

    /* Copy the PTR name onto the carrier heap for the forward lookup. */
    c->ptr_name.data = ngx_alloc(ctx->name.len, c->log);
    if (c->ptr_name.data == NULL) {
        ngx_resolve_addr_done(ctx);
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_PENDING, now);
        return;
    }
    ngx_memcpy(c->ptr_name.data, ctx->name.data, ctx->name.len);
    c->ptr_name.len = ctx->name.len;

    ngx_resolve_addr_done(ctx);

    /* Forward lookup of the PTR name. */
    fctx = ngx_resolve_start(c->resolver, NULL);
    if (fctx == NULL || fctx == NGX_NO_RESOLVER) {
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_PENDING, now);
        return;
    }

    fctx->name    = c->ptr_name;
    fctx->handler = sentinel_fcrdns_fwd_handler;
    fctx->data    = c;
    fctx->timeout = c->timeout;

    if (ngx_resolve_name(fctx) != NGX_OK) {
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_PENDING, now);
    }
}


/* Forward callback: confirm the original client IP appears in the A/AAAA set. */
static void
sentinel_fcrdns_fwd_handler(ngx_resolver_ctx_t *ctx)
{
    sentinel_fcrdns_carrier_t  *c = ctx->data;
    ngx_uint_t                  i;
    int                         match = 0;
    struct sockaddr            *orig = (struct sockaddr *) &c->ss;
    time_t                      now;

    now = ngx_time();

    if (ctx->state != NGX_OK || ctx->naddrs == 0) {
        ngx_resolve_name_done(ctx);
        sentinel_fcrdns_finish(c, NGX_SENTINEL_FCRDNS_PENDING, now);
        return;
    }

    for (i = 0; i < ctx->naddrs; i++) {
        struct sockaddr *a = ctx->addrs[i].sockaddr;

        if (a->sa_family != orig->sa_family) {
            continue;
        }

        if (a->sa_family == AF_INET) {
            struct sockaddr_in *a4 = (struct sockaddr_in *) a;
            struct sockaddr_in *o4 = (struct sockaddr_in *) orig;
            if (a4->sin_addr.s_addr == o4->sin_addr.s_addr) {
                match = 1;
                break;
            }
#if (NGX_HAVE_INET6)
        } else if (a->sa_family == AF_INET6) {
            struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) a;
            struct sockaddr_in6 *o6 = (struct sockaddr_in6 *) orig;
            if (ngx_memcmp(&a6->sin6_addr, &o6->sin6_addr,
                           sizeof(struct in6_addr)) == 0)
            {
                match = 1;
                break;
            }
#endif
        }
    }

    ngx_resolve_name_done(ctx);

    /* Forward-confirmed = VERIFIED; resolved-but-no-match = FAILED (the PTR
     * pointed somewhere that does not own this IP — a spoof). */
    sentinel_fcrdns_finish(c,
        match ? NGX_SENTINEL_FCRDNS_VERIFIED : NGX_SENTINEL_FCRDNS_FAILED,
        now);
}


/* ---------------------------------------------------------------------------
 * Request-path signal (preaccess)
 * ------------------------------------------------------------------------- */

void
sentinel_fcrdns_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_resolver_t            *resolver;
    ngx_str_t                  key;
    u_char                     digest[NGX_SENTINEL_DIGEST_LEN];
    ngx_uint_t                 verdict;
    time_t                     now;

    inputs->fcrdns_verified = 0;
    inputs->fcrdns_spoofed  = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    /* Only confirm self-declared crawlers; everything else is out of scope.
     * FCrDNS is enabled iff a verdict-cache zone is bound (sentinel_fcrdns
     * <zone>;). No bound zone → signal off → fail-open. */
    if (lcf->fcrdns_zone == NULL || lcf->fcrdns_zone == NGX_CONF_UNSET_PTR) {
        return;
    }
    if (!inputs->known_good_ua) {
        return;
    }

    if (r->connection == NULL || r->connection->addr_text.len == 0) {
        return;
    }

    /* Identity key = SHA-256 of $binary_remote_addr (same scheme as errrate). */
    {
        struct sockaddr *sa = r->connection->sockaddr;
        size_t           alen;
        u_char          *abin;

        if (sa == NULL) {
            return;
        }
        if (sa->sa_family == AF_INET) {
            abin = (u_char *) &((struct sockaddr_in *) sa)->sin_addr;
            alen = sizeof(struct in_addr);
#if (NGX_HAVE_INET6)
        } else if (sa->sa_family == AF_INET6) {
            abin = (u_char *) &((struct sockaddr_in6 *) sa)->sin6_addr;
            alen = sizeof(struct in6_addr);
#endif
        } else {
            return;   /* unknown family — fail-open */
        }
        SHA256(abin, alen, digest);
        key.data = digest;
        key.len  = NGX_SENTINEL_DIGEST_LEN;
    }

    now = ngx_time();

    verdict = sentinel_shm_fcrdns_get(lcf->fcrdns_zone, &key, now);

    if (verdict == NGX_SENTINEL_FCRDNS_VERIFIED) {
        inputs->fcrdns_verified = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: fcrdns verdict=verified");
        return;
    }

    if (verdict == NGX_SENTINEL_FCRDNS_FAILED) {
        inputs->fcrdns_spoofed = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: fcrdns verdict=spoofed (PTR/forward mismatch)");
        return;
    }

    /* PENDING: fail-open this request and kick the async resolve (if a resolver
     * is configured). Both flags stay 0 — known_good_ua keeps legacy behavior. */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    resolver = (clcf != NULL) ? clcf->resolver : NULL;

    if (resolver == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: fcrdns pending but no resolver configured");
        return;   /* fail-open */
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: fcrdns pending → starting async PTR resolve");
    sentinel_fcrdns_resolve_start(r, lcf, resolver, &key);
}
