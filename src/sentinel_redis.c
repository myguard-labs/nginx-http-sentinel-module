/*
 * sentinel_redis.c — Redis multi-box shared ban state.
 *
 * Shares ban state across nginx hosts through a single Redis instance. BOTH
 * directions are strictly OUT-OF-BAND: a per-worker ngx_event timer drives an
 * async hiredis connection that is bound to nginx's own event loop. There is
 * NEVER any synchronous network I/O in the request path — the request path only
 * ever touches per-host shared memory (the crowdsec zone + the push ring).
 *
 *   PULL  (timer): SCAN `<prefix>:ban:*`, GET each, upsert into the bound
 *                  crowdsec shm zone with node->redis_pulled = 1. This feeds the
 *                  existing w_crowdsec scoring tier — no new weight / zone.
 *   PUSH  (timer): drain the shm push ring (filled by the BLOCK enforcement
 *                  path) and `SET <prefix>:ban:<ip> <action> EX <ttl>`.
 *
 * Ban-loop guard: a node carrying redis_pulled == 1 is never enqueued for PUSH;
 * only locally-originated block decisions are published.
 *
 * Fail-OPEN throughout: if Redis is unreachable, every operation is a no-op and
 * the module degrades cleanly to per-host shm. Connection loss schedules an
 * exponential-backoff reconnect; it never blocks a worker or a request.
 *
 * The hiredis <-> nginx event adapter (the ev.addRead / addWrite / delRead /
 * delWrite / cleanup hooks) wraps the hiredis socket fd in an ngx_connection_t
 * and routes readiness through ngx_handle_read_event / ngx_handle_write_event,
 * calling redisAsyncHandleRead / redisAsyncHandleWrite from the nginx handlers.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "sentinel.h"

#include <hiredis/hiredis.h>
#include <hiredis/async.h>


/* -------------------------------------------------------------------------
 * Connection states.
 * ---------------------------------------------------------------------- */
typedef enum {
    SENTINEL_REDIS_DOWN = 0,   /* no context; waiting for next (re)connect tick */
    SENTINEL_REDIS_CONNECTING, /* async connect issued, awaiting connect cb     */
    SENTINEL_REDIS_UP          /* connected (and AUTH'd if needed)              */
} sentinel_redis_state_e;


/* Per-worker Redis sync state. One instance per worker; if multiple sentinel
 * locations configure Redis, the FIRST distinct endpoint wins (documented).   */
typedef struct {
    ngx_event_t                 timer;     /* periodic pull/flush + reconnect   */
    ngx_log_t                  *log;
    ngx_sentinel_loc_conf_t    *lcf;       /* config (host/port/ttl/prefix/...) */
    ngx_sentinel_zone_t        *cs_zone;   /* crowdsec zone to upsert pulls into */
    ngx_sentinel_redis_shctx_t *push;      /* shared push ring                  */
    ngx_slab_pool_t            *push_pool; /* push-ring shpool (own mutex)      */

    redisAsyncContext          *ac;        /* hiredis async context (NULL=down) */
    ngx_connection_t           *conn;      /* nginx wrapper around ac's fd      */

    sentinel_redis_state_e      state;
    ngx_msec_t                  backoff;   /* current reconnect backoff (ms)    */

    unsigned long long          scan_cursor;   /* SCAN cursor across pull steps */
    ngx_flag_t                  pull_inflight; /* a SCAN/GET chain is running   */
    ngx_flag_t                  auth_pending;  /* AUTH issued, not yet replied  */
} sentinel_redis_ctx_t;


/* The single per-worker instance (armed in init_process). NULL = feature off. */
static sentinel_redis_ctx_t  *sentinel_redis;


/* Parse a decimal SCAN cursor string (bounded, no libc). Non-digits stop the
 * scan; overflow saturates to 0 (treated as "end of scan", safe). */
static unsigned long long
sentinel_redis_parse_cursor(const char *s, size_t len)
{
    unsigned long long  v = 0;
    size_t              i;

    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            break;
        }
        if (v > (unsigned long long) -1 / 10) {
            return 0;   /* overflow -> end the scan */
        }
        v = v * 10 + (unsigned long long) (s[i] - '0');
    }
    return v;
}


/* Forward decls. */
static void sentinel_redis_timer_handler(ngx_event_t *ev);
static void sentinel_redis_connect(sentinel_redis_ctx_t *rc);
static void sentinel_redis_teardown(sentinel_redis_ctx_t *rc);
static void sentinel_redis_schedule_reconnect(sentinel_redis_ctx_t *rc);
static void sentinel_redis_pull_step(sentinel_redis_ctx_t *rc);
static void sentinel_redis_flush_push(sentinel_redis_ctx_t *rc);


/* =========================================================================
 * hiredis <-> nginx event adapter
 *
 * hiredis owns the socket fd; we wrap it in an ngx_connection_t purely to ride
 * nginx's event loop. We DO NOT let nginx close the fd (hiredis owns it) —
 * cleanup detaches the connection without closing the fd.
 * ========================================================================= */

static void
sentinel_redis_read_event(ngx_event_t *ev)
{
    ngx_connection_t      *c = ev->data;
    sentinel_redis_ctx_t  *rc = c->data;

    if (rc->ac == NULL) {
        return;
    }
    /* Re-arm level/edge readiness for epoll-style methods. */
    if (ngx_handle_read_event(ev, 0) != NGX_OK) {
        /* fall through; hiredis read will surface the error */
    }
    redisAsyncHandleRead(rc->ac);
}


static void
sentinel_redis_write_event(ngx_event_t *ev)
{
    ngx_connection_t      *c = ev->data;
    sentinel_redis_ctx_t  *rc = c->data;

    if (rc->ac == NULL) {
        return;
    }
    redisAsyncHandleWrite(rc->ac);
}


static void
sentinel_redis_add_read(void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;

    if (rc->conn == NULL) {
        return;
    }
    (void) ngx_handle_read_event(rc->conn->read, 0);
}


static void
sentinel_redis_del_read(void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;

    if (rc->conn == NULL || rc->conn->read == NULL) {
        return;
    }
    if (rc->conn->read->active) {
        (void) ngx_del_event(rc->conn->read, NGX_READ_EVENT, 0);
    }
}


static void
sentinel_redis_add_write(void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;

    ngx_event_t  *wev;

    if (rc->conn == NULL) {
        return;
    }
    wev = rc->conn->write;

    /* If the socket is already writable, nginx won't fire a fresh write event
     * (no EPOLLOUT registered), so hiredis's buffered command would never get
     * pumped. Post the write handler to run at the end of this event cycle. */
    if (wev->ready) {
        if (!wev->posted) {
            ngx_post_event(wev, &ngx_posted_events);
        }
        return;
    }
    (void) ngx_handle_write_event(wev, 0);
}


static void
sentinel_redis_del_write(void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;

    if (rc->conn == NULL || rc->conn->write == NULL) {
        return;
    }
    if (rc->conn->write->active) {
        (void) ngx_del_event(rc->conn->write, NGX_WRITE_EVENT, 0);
    }
}


/* hiredis cleanup: detach the nginx connection WITHOUT closing the fd (hiredis
 * closes its own fd in redisAsyncFree). Idempotent. */
static void
sentinel_redis_ev_cleanup(void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;
    ngx_connection_t      *c = rc->conn;

    if (c == NULL) {
        return;
    }
    rc->conn = NULL;

    if (c->read->active) {
        (void) ngx_del_event(c->read, NGX_READ_EVENT, 0);
    }
    if (c->write->active) {
        (void) ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
    }

    /* Drop any pending posted events for this connection (the add_write pump
     * may have queued the write event); otherwise the posted handler would
     * deref the freed connection — a use-after-free. */
    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }
    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    /* Mark fd invalid so ngx_free_connection / ngx_close_connection logic that
     * we DON'T call won't touch the hiredis-owned socket. We free only the
     * connection slot. */
    c->fd = (ngx_socket_t) -1;
    c->read->closed = 1;
    c->write->closed = 1;
    ngx_free_connection(c);
}


/* Attach hiredis's fd to an nginx connection slot and wire the ev hooks. */
static ngx_int_t
sentinel_redis_attach(sentinel_redis_ctx_t *rc)
{
    redisAsyncContext  *ac = rc->ac;
    ngx_connection_t   *c;
    ngx_event_t        *rev, *wev;
    ngx_socket_t        fd;

    fd = (ngx_socket_t) ac->c.fd;
    if (fd == (ngx_socket_t) -1) {
        return NGX_ERROR;
    }

    c = ngx_get_connection(fd, rc->log);
    if (c == NULL) {
        return NGX_ERROR;
    }

    rc->conn = c;
    c->data  = rc;

    rev = c->read;
    wev = c->write;

    rev->handler = sentinel_redis_read_event;
    wev->handler = sentinel_redis_write_event;
    rev->log = rc->log;
    wev->log = rc->log;

    /* nginx's connection events default to level-triggered registration via the
     * add hooks below; mark them non-instant. */
    rev->ready = 0;
    wev->ready = 0;

    /* Install the hiredis adapter hooks. */
    ac->ev.data      = rc;
    ac->ev.addRead   = sentinel_redis_add_read;
    ac->ev.delRead   = sentinel_redis_del_read;
    ac->ev.addWrite  = sentinel_redis_add_write;
    ac->ev.delWrite  = sentinel_redis_del_write;
    ac->ev.cleanup   = sentinel_redis_ev_cleanup;

    return NGX_OK;
}


/* =========================================================================
 * Connection lifecycle
 * ========================================================================= */

static void
sentinel_redis_on_connect(const redisAsyncContext *ac, int status)
{
    sentinel_redis_ctx_t  *rc = ac->data;

    if (rc == NULL) {
        return;
    }
    if (status != REDIS_OK) {
        ngx_log_error(NGX_LOG_WARN, rc->log, 0,
                      "sentinel: redis connect failed: %s",
                      ac->errstr ? ac->errstr : "unknown");
        /* hiredis frees the context after this returns; teardown resets us. */
        rc->ac = NULL;
        sentinel_redis_teardown(rc);
        sentinel_redis_schedule_reconnect(rc);
        return;
    }

    rc->state   = SENTINEL_REDIS_UP;
    rc->backoff = NGX_SENTINEL_REDIS_BACKOFF_MIN_MS;   /* reset on success */
    ngx_log_error(NGX_LOG_INFO, rc->log, 0,
                  "sentinel: redis connected to %V:%i",
                  &rc->lcf->redis_host, rc->lcf->redis_port);
}


static void
sentinel_redis_on_disconnect(const redisAsyncContext *ac, int status)
{
    sentinel_redis_ctx_t  *rc = ac->data;

    if (rc == NULL) {
        return;
    }
    if (status != REDIS_OK) {
        ngx_log_error(NGX_LOG_WARN, rc->log, 0,
                      "sentinel: redis disconnected: %s",
                      ac->errstr ? ac->errstr : "peer closed");
    }
    /* hiredis frees ac itself after the disconnect callback. Drop our handle so
     * teardown does not double-free, and arm a reconnect. */
    rc->ac = NULL;
    sentinel_redis_teardown(rc);
    sentinel_redis_schedule_reconnect(rc);
}


/* AUTH reply: promote to UP only after a successful AUTH (if a password set). */
static void
sentinel_redis_auth_reply(redisAsyncContext *ac, void *reply, void *privdata)
{
    sentinel_redis_ctx_t  *rc = privdata;
    redisReply            *r  = reply;

    (void) ac;
    if (rc == NULL) {
        return;
    }
    rc->auth_pending = 0;

    if (r == NULL || r->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, rc->log, 0,
                      "sentinel: redis AUTH failed: %s",
                      (r && r->str) ? r->str : "no reply");
        /* Fail-open: tear down; do not retry tight. */
        sentinel_redis_teardown(rc);
        sentinel_redis_schedule_reconnect(rc);
    }
}


static void
sentinel_redis_connect(sentinel_redis_ctx_t *rc)
{
    redisAsyncContext  *ac;
    redisOptions        opt;

    if (rc->state != SENTINEL_REDIS_DOWN) {
        return;
    }

    ngx_memzero(&opt, sizeof(redisOptions));
    REDIS_OPTIONS_SET_TCP(&opt,
                          (const char *) rc->lcf->redis_host.data,
                          (int) rc->lcf->redis_port);
    /* Connect timeout — bounds the async connect attempt; hiredis still does
     * the connect non-blocking, this only caps how long the half-open lingers. */
    {
        static struct timeval tv;
        tv.tv_sec  = 2;
        tv.tv_usec = 0;
        opt.connect_timeout = &tv;
    }

    ac = redisAsyncConnectWithOptions(&opt);
    if (ac == NULL || ac->err) {
        if (ac) {
            ngx_log_error(NGX_LOG_WARN, rc->log, 0,
                          "sentinel: redis async connect error: %s", ac->errstr);
            redisAsyncFree(ac);
        }
        sentinel_redis_schedule_reconnect(rc);
        return;
    }

    rc->ac    = ac;
    ac->data  = rc;
    rc->state = SENTINEL_REDIS_CONNECTING;

    if (sentinel_redis_attach(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, rc->log, 0,
                      "sentinel: redis fd attach failed (fail-open)");
        redisAsyncFree(ac);     /* triggers cleanup; on_disconnect resets us */
        rc->ac = NULL;
        rc->state = SENTINEL_REDIS_DOWN;
        sentinel_redis_schedule_reconnect(rc);
        return;
    }

    redisAsyncSetConnectCallback(ac, sentinel_redis_on_connect);
    redisAsyncSetDisconnectCallback(ac, sentinel_redis_on_disconnect);

    /* Optional AUTH — issued immediately; the command is buffered until the
     * socket connects, then flushed by hiredis. */
    if (rc->lcf->redis_password.len > 0) {
        rc->auth_pending = 1;
        if (redisAsyncCommand(ac, sentinel_redis_auth_reply, rc, "AUTH %b",
                              rc->lcf->redis_password.data,
                              (size_t) rc->lcf->redis_password.len) != REDIS_OK)
        {
            ngx_log_error(NGX_LOG_WARN, rc->log, 0,
                          "sentinel: redis AUTH enqueue failed");
            sentinel_redis_teardown(rc);
            sentinel_redis_schedule_reconnect(rc);
        }
    }
}


/* Drop the async context + nginx connection. Safe to call repeatedly. Does NOT
 * schedule a reconnect (caller decides). */
static void
sentinel_redis_teardown(sentinel_redis_ctx_t *rc)
{
    redisAsyncContext  *ac = rc->ac;

    rc->state         = SENTINEL_REDIS_DOWN;
    rc->pull_inflight = 0;
    rc->auth_pending  = 0;
    rc->scan_cursor   = 0;

    if (ac != NULL) {
        rc->ac = NULL;
        /* redisAsyncFree calls our ev.cleanup (detaches rc->conn) and closes
         * the hiredis-owned fd. */
        redisAsyncFree(ac);
    } else if (rc->conn != NULL) {
        /* No context but a dangling connection (shouldn't happen) — detach. */
        sentinel_redis_ev_cleanup(rc);
    }
}


static void
sentinel_redis_schedule_reconnect(sentinel_redis_ctx_t *rc)
{
    if (rc->backoff < NGX_SENTINEL_REDIS_BACKOFF_MIN_MS) {
        rc->backoff = NGX_SENTINEL_REDIS_BACKOFF_MIN_MS;
    }
    if (rc->timer.timer_set) {
        ngx_del_timer(&rc->timer);
    }
    ngx_add_timer(&rc->timer, rc->backoff);

    /* Exponential backoff, capped. */
    rc->backoff <<= 1;
    if (rc->backoff > NGX_SENTINEL_REDIS_BACKOFF_MAX_MS) {
        rc->backoff = NGX_SENTINEL_REDIS_BACKOFF_MAX_MS;
    }
}


/* =========================================================================
 * PULL: SCAN <prefix>:ban:* -> GET each -> upsert into crowdsec zone
 * ========================================================================= */

/* Map a stored action string back to a CS tier. */
static u_char
sentinel_redis_action(const char *s, size_t len)
{
    if (len == 3 && ngx_strncmp(s, "ban", 3) == 0) {
        return NGX_SENTINEL_CS_BAN;
    }
    if (len == 7 && ngx_strncmp(s, "captcha", 7) == 0) {
        return NGX_SENTINEL_CS_CAPTCHA;
    }
    if (len == 8 && ngx_strncmp(s, "throttle", 8) == 0) {
        return NGX_SENTINEL_CS_THROTTLE;
    }
    return NGX_SENTINEL_CS_BAN;   /* default to ban for any unknown value */
}


/* GETEX reply for one ban key: value = "<action> <expiry_epoch>". Upsert into
 * the crowdsec zone keyed on SHA-256(canonical-IP), redis_pulled = 1. */
static void
sentinel_redis_get_reply(redisAsyncContext *ac, void *reply, void *privdata)
{
    sentinel_redis_ctx_t  *rc = sentinel_redis;
    redisReply            *r  = reply;
    u_char                *ipdata;       /* heap copy of the canonical IP key */
    ngx_str_t              key, ip;
    u_char                 digest[NGX_SENTINEL_DIGEST_LEN];
    u_char                *sp;
    u_char                 action;
    time_t                 expiry, now;

    (void) ac;

    /* privdata is the malloc'd canonical-IP string we attached at GET time. */
    ipdata = privdata;
    if (ipdata == NULL) {
        return;
    }
    ip.data = ipdata;
    ip.len  = ngx_strlen(ipdata);

    if (rc == NULL || rc->cs_zone == NULL || r == NULL
        || r->type != REDIS_REPLY_STRING || r->len == 0)
    {
        ngx_free(ipdata);
        return;
    }

    now = ngx_time();

    /* Parse "<action> <expiry>". */
    sp = memchr((u_char *) r->str, ' ', (size_t) r->len);
    if (sp == NULL) {
        ngx_free(ipdata);
        return;
    }
    action = sentinel_redis_action(r->str, (size_t) (sp - (u_char *) r->str));

    {
        u_char     *estr = sp + 1;
        size_t      elen = (size_t) ((u_char *) r->str + r->len - estr);
        ngx_int_t   e = ngx_atoi(estr, elen);
        if (e == NGX_ERROR || e <= (ngx_int_t) now) {
            ngx_free(ipdata);    /* expired or malformed — skip */
            return;
        }
        expiry = (time_t) e;
    }

    /* Derive the shm key = SHA-256(canonical IP), matching errrate/feed. */
    SHA256(ip.data, ip.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

    ngx_shmtx_lock(&rc->cs_zone->shpool->mutex);
    (void) sentinel_shm_crowdsec_upsert(rc->cs_zone, &key, expiry, action,
                                        rc->cs_zone->sh->cs_generation, now,
                                        1 /* redis_pulled */);
    ngx_shmtx_unlock(&rc->cs_zone->shpool->mutex);

    ngx_free(ipdata);
}


/* SCAN reply: ["cursor", [key, key, ...]]. Issue a GET for each key, then either
 * continue scanning (cursor != 0) or finish. */
static void
sentinel_redis_scan_reply(redisAsyncContext *ac, void *reply, void *privdata)
{
    sentinel_redis_ctx_t  *rc = sentinel_redis;
    redisReply            *r  = reply;
    redisReply            *cur, *keys;
    ngx_uint_t             i;
    size_t                 plen;

    (void) ac;
    (void) privdata;

    if (rc == NULL) {
        return;
    }

    if (r == NULL || r->type != REDIS_REPLY_ARRAY || r->elements != 2) {
        rc->pull_inflight = 0;
        return;
    }

    cur  = r->element[0];
    keys = r->element[1];

    /* Advance cursor. */
    if (cur != NULL && cur->type == REDIS_REPLY_STRING && cur->str != NULL) {
        rc->scan_cursor = sentinel_redis_parse_cursor(cur->str,
                                                      (size_t) cur->len);
    } else {
        rc->scan_cursor = 0;
    }

    plen = rc->lcf->redis_prefix.len + sizeof(":ban:") - 1;

    if (keys != NULL && keys->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < keys->elements; i++) {
            redisReply  *k = keys->element[i];
            u_char      *ipcopy;
            size_t       iplen;

            if (k == NULL || k->type != REDIS_REPLY_STRING
                || (size_t) k->len <= plen)
            {
                continue;
            }
            /* The IP is the key suffix after "<prefix>:ban:". */
            iplen = (size_t) k->len - plen;
            if (iplen == 0 || iplen >= NGX_SOCKADDR_STRLEN) {
                continue;
            }
            ipcopy = ngx_alloc(iplen + 1, rc->log);
            if (ipcopy == NULL) {
                continue;
            }
            ngx_memcpy(ipcopy, k->str + plen, iplen);
            ipcopy[iplen] = '\0';

            if (redisAsyncCommand(rc->ac, sentinel_redis_get_reply, ipcopy,
                                  "GET %s", k->str) != REDIS_OK)
            {
                ngx_free(ipcopy);
            }
        }
    }

    /* Continue the SCAN if there's more; else the pass is done. */
    if (rc->scan_cursor != 0) {
        sentinel_redis_pull_step(rc);
    } else {
        rc->pull_inflight = 0;
    }
}


static void
sentinel_redis_pull_step(sentinel_redis_ctx_t *rc)
{
    u_char  cursor[32];
    u_char  match[NGX_SOCKADDR_STRLEN + 64];

    if (rc->ac == NULL || rc->state != SENTINEL_REDIS_UP) {
        rc->pull_inflight = 0;
        return;
    }

    /* hiredis printf-style formatting supports only %s/%b/%d/... — build the
     * cursor + MATCH pattern as NUL-terminated strings ourselves (redis_prefix
     * comes from ngx_conf_set_str_slot and is NOT NUL-terminated). */
    ngx_snprintf(cursor, sizeof(cursor), "%uL%Z", (uint64_t) rc->scan_cursor);
    ngx_snprintf(match, sizeof(match), "%V:ban:*%Z", &rc->lcf->redis_prefix);

    if (redisAsyncCommand(rc->ac, sentinel_redis_scan_reply, NULL,
                          "SCAN %s MATCH %s COUNT %d",
                          (const char *) cursor,
                          (const char *) match,
                          NGX_SENTINEL_REDIS_SCAN_COUNT) != REDIS_OK)
    {
        rc->pull_inflight = 0;
    }
}


/* =========================================================================
 * PUSH: drain the shm ring -> SET <prefix>:ban:<ip> "<action> <expiry>" EX ttl
 * ========================================================================= */

/* SET reply: only logged on error; nothing to free. */
static void
sentinel_redis_set_reply(redisAsyncContext *ac, void *reply, void *privdata)
{
    redisReply  *r = reply;

    (void) ac;
    (void) privdata;
    if (r != NULL && r->type == REDIS_REPLY_ERROR && sentinel_redis != NULL) {
        ngx_log_error(NGX_LOG_WARN, sentinel_redis->log, 0,
                      "sentinel: redis SET error: %s", r->str ? r->str : "?");
    }
}


static const char *
sentinel_redis_action_str(u_char action)
{
    switch (action) {
    case NGX_SENTINEL_CS_CAPTCHA:  return "captcha";
    case NGX_SENTINEL_CS_THROTTLE: return "throttle";
    default:                       return "ban";
    }
}


static void
sentinel_redis_flush_push(sentinel_redis_ctx_t *rc)
{
    ngx_sentinel_redis_shctx_t *push = rc->push;
    ngx_uint_t                  drained = 0;
    time_t                      now;

    if (push == NULL || rc->push_pool == NULL
        || rc->ac == NULL || rc->state != SENTINEL_REDIS_UP)
    {
        return;
    }

    now = ngx_time();

    /* Drain the ring under the push-ring's own shpool lock. Copy each entry out
     * under the lock, then issue the SET after unlocking to keep the critical
     * section short. */
    for ( ;; ) {
        ngx_sentinel_redis_push_t  entry;
        ngx_int_t                  ttl;
        char                       value[64];
        char                       key[NGX_SOCKADDR_STRLEN + 64];
        int                        klen, vlen;

        ngx_shmtx_lock(&rc->push_pool->mutex);
        if (push->tail == push->head) {
            ngx_shmtx_unlock(&rc->push_pool->mutex);
            break;
        }
        entry = push->ring[push->tail % NGX_SENTINEL_REDIS_PUSH_RING];
        push->tail++;
        ngx_shmtx_unlock(&rc->push_pool->mutex);

        if (entry.ip_len == 0 || entry.ip_len >= NGX_SOCKADDR_STRLEN) {
            continue;
        }
        ttl = (ngx_int_t) (entry.expiry - now);
        if (ttl <= 0) {
            continue;       /* already expired by flush time */
        }

        klen = ngx_snprintf((u_char *) key, sizeof(key), "%V:ban:%*s",
                            &rc->lcf->redis_prefix,
                            (size_t) entry.ip_len, entry.ip)
               - (u_char *) key;
        vlen = ngx_snprintf((u_char *) value, sizeof(value), "%s %T",
                            sentinel_redis_action_str(entry.action),
                            entry.expiry)
               - (u_char *) value;

        if (redisAsyncCommand(rc->ac, sentinel_redis_set_reply, NULL,
                              "SET %b %b EX %d",
                              key, (size_t) klen,
                              value, (size_t) vlen,
                              (int) ttl) != REDIS_OK)
        {
            break;          /* connection trouble; remaining entries dropped */
        }

        if (++drained >= NGX_SENTINEL_REDIS_PUSH_RING) {
            break;          /* full-ring bound per tick */
        }
    }
}


/* =========================================================================
 * Request-path enqueue (called from BLOCK enforcement)
 * ========================================================================= */

void
sentinel_redis_enqueue_ban(ngx_sentinel_loc_conf_t *lcf, ngx_str_t *ip,
    u_char action, time_t expiry)
{
    sentinel_redis_ctx_t       *rc = sentinel_redis;
    ngx_sentinel_redis_shctx_t *push;
    ngx_uint_t                  slot;

    /* Accept any location that shares the armed endpoint's push ring (the shm
     * zone is keyed on host:port, so sibling locations with the same Redis
     * target share one ring — don't require pointer-identical lcf). */
    if (rc == NULL || rc->push == NULL || rc->push_pool == NULL
        || lcf->redis_push_zone == NULL
        || lcf->redis_push_zone->data != rc->push)
    {
        return;     /* feature off / different endpoint */
    }
    if (ip == NULL || ip->len == 0 || ip->len >= NGX_SOCKADDR_STRLEN) {
        return;
    }

    push = rc->push;

    ngx_shmtx_lock(&rc->push_pool->mutex);

    /* Ring full? drop (fail-open) and count. */
    if (push->head - push->tail >= NGX_SENTINEL_REDIS_PUSH_RING) {
        push->dropped++;
        ngx_shmtx_unlock(&rc->push_pool->mutex);
        return;
    }

    slot = push->head % NGX_SENTINEL_REDIS_PUSH_RING;
    ngx_memcpy(push->ring[slot].ip, ip->data, ip->len);
    push->ring[slot].ip_len = (u_short) ip->len;
    push->ring[slot].action = action;
    push->ring[slot].expiry = expiry;
    push->head++;

    ngx_shmtx_unlock(&rc->push_pool->mutex);
}


/* =========================================================================
 * Timer + init
 * ========================================================================= */

static void
sentinel_redis_timer_handler(ngx_event_t *ev)
{
    sentinel_redis_ctx_t  *rc = ev->data;

    switch (rc->state) {

    case SENTINEL_REDIS_DOWN:
        sentinel_redis_connect(rc);
        break;

    case SENTINEL_REDIS_CONNECTING:
        /* still waiting on the connect callback — nothing to do this tick */
        break;

    case SENTINEL_REDIS_UP:
        if (rc->auth_pending) {
            break;      /* don't issue work until AUTH settles */
        }
        /* Flush local bans first (publish), then pull remote bans. */
        sentinel_redis_flush_push(rc);
        if (!rc->pull_inflight) {
            rc->pull_inflight = 1;
            rc->scan_cursor   = 0;
            sentinel_redis_pull_step(rc);
        }
        break;
    }

    /* Re-arm the periodic tick UNLESS a reconnect timer was just scheduled
     * (schedule_reconnect owns the timer when DOWN). */
    if (rc->state == SENTINEL_REDIS_UP
        || rc->state == SENTINEL_REDIS_CONNECTING)
    {
        ngx_add_timer(&rc->timer, (ngx_msec_t) rc->lcf->redis_interval * 1000);
    }
}


/* shm init for the push ring zone (zeroed by slab on first map). */
ngx_int_t
sentinel_redis_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_sentinel_redis_shctx_t  *sh;

    if (data) {                 /* reload: inherit existing ring */
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    sh = ngx_slab_calloc(shpool, sizeof(ngx_sentinel_redis_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data    = sh;
    shm_zone->data  = sh;
    return NGX_OK;
}


/* Recursively walk the location tree for the first sentinel location with
 * `sentinel_redis` configured + a bound crowdsec zone. Mirrors the feed
 * collector — location directives live in the location tree, NOT the server's
 * merged loc_conf. */
static ngx_sentinel_loc_conf_t *
sentinel_redis_scan_loc(ngx_http_location_tree_node_t *node)
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
        if (lcf != NULL && lcf->redis_host.len > 0 && lcf->cs_zone != NULL) {
            return lcf;
        }
    }
    if (node->inclusive) {
        clcf = node->inclusive;
        lcf  = clcf->loc_conf[ngx_http_sentinel_module.ctx_index];
        if (lcf != NULL && lcf->redis_host.len > 0 && lcf->cs_zone != NULL) {
            return lcf;
        }
    }

    if ((found = sentinel_redis_scan_loc(node->left)) != NULL) {
        return found;
    }
    if ((found = sentinel_redis_scan_loc(node->tree)) != NULL) {
        return found;
    }
    return sentinel_redis_scan_loc(node->right);
}

static ngx_sentinel_loc_conf_t *
sentinel_redis_find_loc(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_conf_ctx_t        *ctx;
    ngx_sentinel_loc_conf_t    *lcf;
    ngx_uint_t                  s;

    ctx = (ngx_http_conf_ctx_t *)
              cycle->conf_ctx[ngx_http_module.index];
    if (ctx == NULL) {
        return NULL;
    }
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    if (cmcf == NULL) {
        return NULL;
    }

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        if (clcf == NULL) {
            continue;
        }
        /* server-level loc_conf (a directive directly in server{}). The
         * conf ctx — NOT the core loc_conf — owns the per-module loc_conf
         * array. */
        lcf = cscfp[s]->ctx->loc_conf[ngx_http_sentinel_module.ctx_index];
        if (lcf != NULL && lcf->redis_host.len > 0 && lcf->cs_zone != NULL) {
            return lcf;
        }
        if (clcf->static_locations) {
            lcf = sentinel_redis_scan_loc(clcf->static_locations);
            if (lcf != NULL) {
                return lcf;
            }
        }
    }
    return NULL;
}


ngx_int_t
sentinel_redis_init_process(ngx_cycle_t *cycle)
{
    ngx_sentinel_loc_conf_t  *lcf;
    sentinel_redis_ctx_t     *rc;

    sentinel_redis = NULL;

    lcf = sentinel_redis_find_loc(cycle);
    if (lcf == NULL) {
        return NGX_OK;          /* feature off */
    }

    rc = ngx_pcalloc(cycle->pool, sizeof(sentinel_redis_ctx_t));
    if (rc == NULL) {
        return NGX_OK;          /* fail-open */
    }

    rc->log     = cycle->log;
    rc->lcf     = lcf;
    rc->cs_zone = lcf->cs_zone;
    rc->state   = SENTINEL_REDIS_DOWN;
    rc->backoff = NGX_SENTINEL_REDIS_BACKOFF_MIN_MS;

    /* The push ring lives in its own dedicated shm zone (created by the
     * sentinel_redis directive). Resolve its shctx + shpool here. */
    if (lcf->redis_push_zone == NULL
        || lcf->redis_push_zone->data == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "sentinel: redis push zone unavailable (push disabled)");
    } else {
        rc->push      = lcf->redis_push_zone->data;
        rc->push_pool = (ngx_slab_pool_t *) lcf->redis_push_zone->shm.addr;
    }

    rc->timer.handler = sentinel_redis_timer_handler;
    rc->timer.data    = rc;
    rc->timer.log     = cycle->log;

    sentinel_redis = rc;

    /* First tick soon — establishes the async connection. */
    ngx_add_timer(&rc->timer, 1000);

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "sentinel: redis multi-box armed (%V:%i, interval %is)",
                  &lcf->redis_host, lcf->redis_port, lcf->redis_interval);

    return NGX_OK;
}
