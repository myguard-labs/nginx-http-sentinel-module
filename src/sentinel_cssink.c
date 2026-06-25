/*
 * sentinel_cssink.c — CrowdSec decision feedback (out-of-band file sink).
 *
 * Sentinel already INGESTS CrowdSec decisions (file feed + Redis pull) into the
 * crowdsec shm zone, feeding the w_crowdsec scoring tier. This is the reverse
 * direction: sentinel's OWN block decisions are exported as a CrowdSec
 * file-acquisition decisions file so the rest of a CrowdSec deployment (cscli,
 * other bouncers, the LAPI) learns about abuse that nginx detected locally.
 *
 * There is NO network in nginx. The request path only enqueues a
 * locally-originated ban (BLOCK in enforce, !crowdsec_hit — same ban-loop guard
 * as the Redis push) into a dedicated shm ring. A per-worker timer drains it.
 * Only WORKER 0 owns the file: it maintains an in-memory decision set (upsert
 * by IP, evict on expiry) and atomically rewrites the decisions file every tick
 * (write <path>.tmp, rename over <path>) so an importer never sees a partial
 * file. Other workers still enqueue, but skip the file write (avoids cross-
 * worker rewrite races). Fail-open on any FS error.
 *
 * File format = CrowdSec file-acquisition JSON, one decision object per line:
 *   {"value":"1.2.3.4","scope":"Ip","duration":"3600s",
 *    "scenario":"sentinel/http-abuse","origin":"sentinel"}
 * Operator imports it (`cscli decisions import -i <path> --format json`) or
 * points a CrowdSec file acquisition at it.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "sentinel.h"


/* An active decision held by the worker-0 file owner. */
typedef struct {
    u_char   ip[NGX_SOCKADDR_STRLEN];
    u_short  ip_len;
    time_t   expiry;        /* absolute epoch; 0 = empty slot */
} sentinel_cssink_decision_t;

typedef struct {
    ngx_log_t                    *log;
    ngx_sentinel_loc_conf_t      *lcf;
    ngx_sentinel_cssink_shctx_t  *ring;     /* shared sink ring */
    ngx_slab_pool_t              *ring_pool;/* ring shpool (own mutex) */
    ngx_event_t                   timer;

    unsigned                      owner:1;  /* worker 0: owns the file write */

    /* Worker-0 in-memory decision set (fixed cap = ring size). */
    sentinel_cssink_decision_t   *set;
    ngx_uint_t                    set_cap;
    ngx_uint_t                    set_count;
} sentinel_cssink_ctx_t;

/* The single per-worker instance (armed in init_process). NULL = feature off. */
static sentinel_cssink_ctx_t  *sentinel_cssink;


/* =========================================================================
 * Decision line formatting (exposed for unit tests)
 * ========================================================================= */

size_t
sentinel_cssink_format_decision(u_char *buf, size_t cap,
    u_char *ip, size_t ip_len, const char *scenario, ngx_int_t duration_s)
{
    u_char  *p, *last;

    if (buf == NULL || ip == NULL || ip_len == 0
        || ip_len >= NGX_SOCKADDR_STRLEN || duration_s <= 0)
    {
        return 0;
    }

    /*
     * The IP comes from nginx's canonical addr_text (only [0-9a-fA-F:.]) and
     * the scenario is operator config of the form "a/b" — neither can contain a
     * JSON metacharacter (", \, control char), so no escaping is required. We
     * still bound every field via ngx_snprintf, which truncates rather than
     * overflows; a truncated (return >= cap) line is rejected by the caller.
     */
    p    = buf;
    last = buf + cap;

    p = ngx_snprintf(p, (size_t) (last - p),
                     "{\"value\":\"%*s\",\"scope\":\"Ip\","
                     "\"duration\":\"%is\",\"scenario\":\"%s\","
                     "\"origin\":\"sentinel\"}\n",
                     ip_len, ip, duration_s, scenario);

    if (p >= last) {
        return 0;       /* truncated — caller drops the entry */
    }
    return (size_t) (p - buf);
}


/* =========================================================================
 * Request-path enqueue (called from BLOCK enforcement)
 * ========================================================================= */

void
sentinel_cssink_enqueue_ban(ngx_sentinel_loc_conf_t *lcf, ngx_str_t *ip,
    u_char action, time_t expiry)
{
    sentinel_cssink_ctx_t        *sc = sentinel_cssink;
    ngx_sentinel_cssink_shctx_t  *ring;
    ngx_uint_t                    slot;

    /* Accept any location that shares the armed sink's ring (the shm zone is
     * keyed on the sink path, so sibling locations writing the same file share
     * one ring). */
    if (sc == NULL || sc->ring == NULL || sc->ring_pool == NULL
        || lcf->cs_sink_zone == NULL
        || lcf->cs_sink_zone->data != sc->ring)
    {
        return;     /* feature off / different sink */
    }
    if (ip == NULL || ip->len == 0 || ip->len >= NGX_SOCKADDR_STRLEN) {
        return;
    }

    ring = sc->ring;

    ngx_shmtx_lock(&sc->ring_pool->mutex);

    if (ring->head - ring->tail >= NGX_SENTINEL_CSSINK_RING) {
        ring->dropped++;
        ngx_shmtx_unlock(&sc->ring_pool->mutex);
        return;
    }

    slot = ring->head % NGX_SENTINEL_CSSINK_RING;
    ngx_memcpy(ring->ring[slot].ip, ip->data, ip->len);
    ring->ring[slot].ip_len = (u_short) ip->len;
    ring->ring[slot].action = action;
    ring->ring[slot].expiry = expiry;
    ring->head++;

    ngx_shmtx_unlock(&sc->ring_pool->mutex);
}


/* =========================================================================
 * Worker-0 decision set + file rewrite
 * ========================================================================= */

/* Upsert one drained entry into the in-memory set (refresh expiry if the IP is
 * already present; else take a free/empty slot). Drops silently when full
 * (fail-open — the ring already bounds inflow). */
static void
sentinel_cssink_set_upsert(sentinel_cssink_ctx_t *sc,
    u_char *ip, u_short ip_len, time_t expiry)
{
    ngx_uint_t                   i, free_slot = sc->set_cap;
    sentinel_cssink_decision_t  *d;

    for (i = 0; i < sc->set_cap; i++) {
        d = &sc->set[i];
        if (d->expiry == 0) {
            if (free_slot == sc->set_cap) {
                free_slot = i;
            }
            continue;
        }
        if (d->ip_len == ip_len && ngx_memcmp(d->ip, ip, ip_len) == 0) {
            d->expiry = expiry;     /* refresh */
            return;
        }
    }

    if (free_slot == sc->set_cap) {
        return;     /* full — drop (fail-open) */
    }
    d = &sc->set[free_slot];
    ngx_memcpy(d->ip, ip, ip_len);
    d->ip_len = ip_len;
    d->expiry = expiry;
    sc->set_count++;
}


/* Drop expired decisions from the set. Returns the live count. */
static ngx_uint_t
sentinel_cssink_set_expire(sentinel_cssink_ctx_t *sc, time_t now)
{
    ngx_uint_t  i, live = 0;

    for (i = 0; i < sc->set_cap; i++) {
        if (sc->set[i].expiry == 0) {
            continue;
        }
        if (sc->set[i].expiry <= now) {
            sc->set[i].expiry = 0;
            if (sc->set_count > 0) {
                sc->set_count--;
            }
            continue;
        }
        live++;
    }
    return live;
}


/* Atomically rewrite the decisions file from the current set. <path>.tmp is
 * written then renamed over <path>. Fail-open: any error logs once and returns
 * (the in-memory set is retained for the next tick). */
static void
sentinel_cssink_rewrite(sentinel_cssink_ctx_t *sc, time_t now)
{
    u_char       *tmp;
    size_t        plen;
    ngx_fd_t      fd;
    ngx_uint_t    i;
    u_char        line[NGX_SOCKADDR_STRLEN + 160];
    size_t        n;
    ssize_t       w;
    ngx_int_t     ttl;

    plen = sc->lcf->cs_sink_path.len;
    tmp  = ngx_alloc(plen + sizeof(".tmp"), sc->log);   /* + NUL */
    if (tmp == NULL) {
        return;
    }
    ngx_memcpy(tmp, sc->lcf->cs_sink_path.data, plen);
    ngx_memcpy(tmp + plen, ".tmp", sizeof(".tmp"));     /* includes NUL */

    fd = ngx_open_file(tmp, NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_WARN, sc->log, ngx_errno,
                      "sentinel: cs_sink open \"%s\" failed (fail-open)", tmp);
        ngx_free(tmp);
        return;
    }

    for (i = 0; i < sc->set_cap; i++) {
        if (sc->set[i].expiry == 0 || sc->set[i].expiry <= now) {
            continue;
        }
        ttl = (ngx_int_t) (sc->set[i].expiry - now);
        n = sentinel_cssink_format_decision(line, sizeof(line),
                sc->set[i].ip, sc->set[i].ip_len,
                (const char *) sc->lcf->cs_sink_scenario.data, ttl);
        if (n == 0) {
            continue;
        }
        w = ngx_write_fd(fd, line, n);
        if (w < 0 || (size_t) w != n) {
            ngx_log_error(NGX_LOG_WARN, sc->log, ngx_errno,
                          "sentinel: cs_sink write failed (fail-open)");
            (void) ngx_close_file(fd);
            (void) ngx_delete_file(tmp);
            ngx_free(tmp);
            return;
        }
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, sc->log, ngx_errno,
                      "sentinel: cs_sink close failed (fail-open)");
        (void) ngx_delete_file(tmp);
        ngx_free(tmp);
        return;
    }

    if (ngx_rename_file(tmp, sc->lcf->cs_sink_path.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, sc->log, ngx_errno,
                      "sentinel: cs_sink rename -> \"%V\" failed (fail-open)",
                      &sc->lcf->cs_sink_path);
        (void) ngx_delete_file(tmp);
    }

    ngx_free(tmp);
}


/* =========================================================================
 * Timer + init
 * ========================================================================= */

static void
sentinel_cssink_timer_handler(ngx_event_t *ev)
{
    sentinel_cssink_ctx_t        *sc = ev->data;
    ngx_sentinel_cssink_shctx_t  *ring = sc->ring;
    time_t                        now = ngx_time();
    ngx_uint_t                    drained = 0;

    /*
     * ONLY the owner (worker 0) drains the ring — it is the sole consumer, so
     * every enqueued ban is observed exactly once and lands in the decision
     * set. A non-owner must NOT dequeue (it would discard the entry the owner
     * needs). Non-owners only re-arm so they cheaply no-op; the file + set are
     * owner-private. (Workers enqueue from every worker; the single consumer is
     * worker 0.)
     */
    if (!sc->owner) {
        ngx_add_timer(&sc->timer,
                      (ngx_msec_t) sc->lcf->cs_sink_interval * 1000);
        return;
    }

    if (ring != NULL && sc->ring_pool != NULL) {
        for ( ;; ) {
            ngx_sentinel_cssink_entry_t  entry;

            ngx_shmtx_lock(&sc->ring_pool->mutex);
            if (ring->tail == ring->head) {
                ngx_shmtx_unlock(&sc->ring_pool->mutex);
                break;
            }
            entry = ring->ring[ring->tail % NGX_SENTINEL_CSSINK_RING];
            ring->tail++;
            ngx_shmtx_unlock(&sc->ring_pool->mutex);

            if (entry.ip_len > 0 && entry.ip_len < NGX_SOCKADDR_STRLEN
                && entry.expiry > now)
            {
                sentinel_cssink_set_upsert(sc, entry.ip, entry.ip_len,
                                           entry.expiry);
            }

            if (++drained >= NGX_SENTINEL_CSSINK_RING) {
                break;          /* full-ring bound per tick */
            }
        }
    }

    sentinel_cssink_set_expire(sc, now);
    sentinel_cssink_rewrite(sc, now);

    ngx_add_timer(&sc->timer,
                  (ngx_msec_t) sc->lcf->cs_sink_interval * 1000);
}


/* shm init for the sink ring zone (zeroed by slab on first map). */
ngx_int_t
sentinel_cssink_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t              *shpool;
    ngx_sentinel_cssink_shctx_t  *sh;

    if (data) {                 /* reload: inherit existing ring */
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    sh = ngx_slab_calloc(shpool, sizeof(ngx_sentinel_cssink_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data   = sh;
    shm_zone->data = sh;
    return NGX_OK;
}


/* Recursively walk the location tree for the first sentinel location with
 * `sentinel_cs_sink_path` configured. Mirrors the redis collector. */
static ngx_sentinel_loc_conf_t *
sentinel_cssink_scan_loc(ngx_http_location_tree_node_t *node)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_sentinel_loc_conf_t   *lcf;
    ngx_sentinel_loc_conf_t   *found;

    if (node == NULL) {
        return NULL;
    }

    if (node->exact) {
        clcf = node->exact;
        lcf  = clcf->loc_conf[ngx_http_sentinel_module.ctx_index];
        if (lcf != NULL && lcf->cs_sink_path.len > 0
            && lcf->cs_sink_zone != NULL)
        {
            return lcf;
        }
    }
    if (node->inclusive) {
        clcf = node->inclusive;
        lcf  = clcf->loc_conf[ngx_http_sentinel_module.ctx_index];
        if (lcf != NULL && lcf->cs_sink_path.len > 0
            && lcf->cs_sink_zone != NULL)
        {
            return lcf;
        }
    }

    if ((found = sentinel_cssink_scan_loc(node->left)) != NULL) {
        return found;
    }
    if ((found = sentinel_cssink_scan_loc(node->tree)) != NULL) {
        return found;
    }
    return sentinel_cssink_scan_loc(node->right);
}

static ngx_sentinel_loc_conf_t *
sentinel_cssink_find_loc(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_conf_ctx_t        *ctx;
    ngx_sentinel_loc_conf_t    *lcf;
    ngx_uint_t                  s;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (ctx == NULL) {
        return NULL;
    }
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    if (cmcf == NULL) {
        return NULL;
    }

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        lcf = cscfp[s]->ctx->loc_conf[ngx_http_sentinel_module.ctx_index];
        if (lcf != NULL && lcf->cs_sink_path.len > 0
            && lcf->cs_sink_zone != NULL)
        {
            return lcf;
        }
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        if (clcf != NULL && clcf->static_locations) {
            lcf = sentinel_cssink_scan_loc(clcf->static_locations);
            if (lcf != NULL) {
                return lcf;
            }
        }
    }
    return NULL;
}


ngx_int_t
sentinel_cssink_init_process(ngx_cycle_t *cycle)
{
    ngx_sentinel_loc_conf_t  *lcf;
    sentinel_cssink_ctx_t    *sc;

    sentinel_cssink = NULL;

    lcf = sentinel_cssink_find_loc(cycle);
    if (lcf == NULL) {
        return NGX_OK;          /* feature off */
    }

    sc = ngx_pcalloc(cycle->pool, sizeof(sentinel_cssink_ctx_t));
    if (sc == NULL) {
        return NGX_OK;          /* fail-open */
    }

    sc->log   = cycle->log;
    sc->lcf   = lcf;
    sc->owner = (ngx_worker == 0);

    if (lcf->cs_sink_zone == NULL || lcf->cs_sink_zone->data == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "sentinel: cs_sink ring unavailable (sink disabled)");
        return NGX_OK;
    }
    sc->ring      = lcf->cs_sink_zone->data;
    sc->ring_pool = (ngx_slab_pool_t *) lcf->cs_sink_zone->shm.addr;

    if (sc->owner) {
        sc->set_cap = NGX_SENTINEL_CSSINK_RING;
        sc->set = ngx_pcalloc(cycle->pool,
                              sizeof(sentinel_cssink_decision_t) * sc->set_cap);
        if (sc->set == NULL) {
            return NGX_OK;      /* fail-open: enqueue still works, no file */
        }
    }

    sc->timer.handler = sentinel_cssink_timer_handler;
    sc->timer.data    = sc;
    sc->timer.log     = cycle->log;

    sentinel_cssink = sc;

    /* First tick soon so an empty/initial file appears promptly. */
    ngx_add_timer(&sc->timer, 1000);

    return NGX_OK;
}
