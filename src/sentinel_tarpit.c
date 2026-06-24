/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_tarpit.c — Phase 2 tarpit: drip-write connection holder.
 *
 * Design invariants (see phase2-tarpit-spec.md):
 *  - One CAS-reserve at entry; cleanup-driven single decrement on every exit.
 *  - Per-worker sub-counter array in dedicated shm; zeroed at init_process.
 *  - Fixed process-global static drip buffer (no malloc in hot path).
 *  - NGX_AGAIN waits on write event; never busy-loops.
 *  - Hard max_lifetime deadline checked at top of every tick.
 *  - At cap: 444 (NGX_HTTP_CLOSE), no queue.
 *  - Shadow mode: log + NGX_DECLINED, never reserve.
 *  - Fail-open on any setup error.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Process-global static drip buffer (shared read-only across all tarpit
 * connections in this worker; filled once at module load with spaces+newlines).
 * ---------------------------------------------------------------------- */

static u_char      ngx_sentinel_drip_buf[NGX_SENTINEL_TARPIT_TICK_MAX];
static ngx_uint_t  ngx_sentinel_drip_buf_ready;  /* 1 after first fill */

/* -------------------------------------------------------------------------
 * Tarpit context (allocated once per request from r->pool at entry).
 * buf and chain are reused every tick — no per-tick alloc.
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_msec_t          deadline;     /* absolute ms timestamp for force-close  */
    ngx_uint_t          bytes_sent;   /* total bytes dripped so far             */
    ngx_uint_t          bytes_total;  /* tarpit_bytes cap (from lcf)            */
    ngx_msec_t          delay_ms;     /* inter-tick delay (from lcf)            */
    ngx_atomic_t       *slot;         /* pointer to this worker's sub-counter   */
    ngx_buf_t           buf;          /* reused every tick, no alloc            */
    ngx_chain_t         chain;        /* ditto                                  */
    uint32_t            rng;          /* per-ctx LCG state for maze hrefs        */
    u_char              maze_frag[NGX_SENTINEL_TARPIT_MAZE_FRAG]; /* per-tick scratch */
    unsigned            counted:1;    /* 1 = slot has been incremented          */
    unsigned            maze:1;       /* 1 = drip HTML link-soup                 */
} ngx_sentinel_tarpit_ctx_t;

/* -------------------------------------------------------------------------
 * Pool-cleanup: the ONE AND ONLY decrement site.
 * ---------------------------------------------------------------------- */

static void
sentinel_tarpit_cleanup(void *data)
{
    ngx_sentinel_tarpit_ctx_t  *tctx = data;

    if (!tctx->counted) {
        return;  /* idempotent guard */
    }

    tctx->counted = 0;
    (void) ngx_atomic_fetch_add(tctx->slot, (ngx_atomic_int_t) -1);
}

/* -------------------------------------------------------------------------
 * Sum per-worker sub-counters (global cap check).
 * Reads of individual atomics are safe without a mutex; worst case we
 * slightly over- or under-count momentarily, which is fine here.
 * ---------------------------------------------------------------------- */

static ngx_uint_t
sentinel_tarpit_sum(ngx_sentinel_main_conf_t *mcf)
{
    ngx_uint_t    i;
    ngx_uint_t    sum = 0;

    if (mcf->tarpit_conns == NULL) {
        return 0;
    }

    for (i = 0; i < NGX_MAX_PROCESSES; i++) {
        sum += mcf->tarpit_conns[i];
    }

    return sum;
}

/* -------------------------------------------------------------------------
 * Reserve one slot via CAS loop on this worker's sub-counter.
 *
 * Returns:
 *   NGX_OK         — slot reserved; *slot_out set
 *   NGX_HTTP_CLOSE — sum >= max_conns (at cap)
 *   NGX_ERROR      — tarpit disabled (max_conns == 0) or shm not ready
 * ---------------------------------------------------------------------- */

static ngx_int_t
sentinel_tarpit_reserve(ngx_sentinel_main_conf_t *mcf, ngx_uint_t max_conns,
    ngx_atomic_t **slot_out)
{
    ngx_atomic_t   cur, old_slot, new_slot;
    ngx_atomic_t  *slot;
    ngx_uint_t     worker;

    if (max_conns == 0 || mcf->tarpit_conns == NULL) {
        return NGX_ERROR;  /* tarpit disabled */
    }

    worker = (ngx_uint_t) ngx_worker;
    if (worker >= NGX_MAX_PROCESSES) {
        worker = 0;
    }
    slot      = &mcf->tarpit_conns[worker];
    *slot_out = slot;

    /*
     * CAS loop: atomically increment our own slot after verifying the global
     * sum is still under the cap.  Another worker may change another slot
     * between our sum read and our CAS, meaning we could theoretically
     * overshoot by at most (worker_processes - 1) — acceptable for a
     * soft cap that prevents runaway tarpitting, not a hard security boundary.
     * The CAS on our own slot prevents double-counting from the same worker.
     */
    for ( ;; ) {
        cur = sentinel_tarpit_sum(mcf);

        if (cur >= (ngx_atomic_t) max_conns) {
            return NGX_HTTP_CLOSE;  /* at cap */
        }

        old_slot = *slot;
        new_slot = old_slot + 1;

        if (ngx_atomic_cmp_set(slot, old_slot, new_slot)) {
            break;  /* reserved */
        }
        /* Retry: our slot changed under us (e.g., cleanup ran concurrently). */
    }

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Drip write handler: called on each timer tick (and on NGX_AGAIN writability).
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Finish a tarpitted request: send the final (empty, last_buf) chain so the
 * response is complete, drop the extra reference we took in
 * sentinel_tarpit_start (r->main->count++), then finalize so nginx actually
 * closes the connection.
 *
 * Why this dance: we hold an extra count reference across timer ticks. A bare
 * ngx_http_finalize_request(NGX_DONE) only drops that reference (leaving the
 * base reference, so the socket lingers), while NGX_HTTP_CLOSE while the
 * response is not yet "complete" (no last_buf and no Content-Length) makes
 * nginx wait for the output to finish before terminating. Sending last_buf
 * marks the response done; ngx_http_finalize_request(NGX_DONE) then both drops
 * our reference and runs the normal finalize/close path immediately.
 * ---------------------------------------------------------------------- */

static void
sentinel_tarpit_finish(ngx_http_request_t *r)
{
    /*
     * Drop the extra reference taken at start (r->main->count++) so the single
     * finalize below brings the count to zero and nginx tears the connection
     * down immediately. We do NOT try to flush a graceful last_buf: a tarpitted
     * client typically never drains its socket, so a graceful close would
     * linger waiting for output that can never complete. NGX_HTTP_CLOSE on the
     * last reference closes the connection abruptly — which is exactly what the
     * max_lifetime / byte-cap ceiling wants.
     */
    r->main->count--;
    ngx_http_finalize_request(r, NGX_HTTP_CLOSE);
}

/* -------------------------------------------------------------------------
 * Maze mode: synthesize one decoy crawl-link line into the per-ctx scratch
 * buffer, e.g.  <a href="/1a2b3c4d5e6f7a8b/">x</a>\n
 *
 * The href path is a 16-hex-digit token from a per-ctx LCG (deterministic per
 * connection, varied per tick) — every link is unique and points back into the
 * same handler, so a link-following crawler keeps requesting fresh tarpit URLs.
 * No malloc, no global state mutation; returns the fragment length.
 * ---------------------------------------------------------------------- */

static ngx_uint_t
sentinel_tarpit_maze_fragment(ngx_sentinel_tarpit_ctx_t *tctx)
{
    static const u_char  hex[] = "0123456789abcdef";
    u_char              *p;
    ngx_uint_t           i;
    uint32_t             rng;

    rng = tctx->rng;
    p   = tctx->maze_frag;

    p = ngx_cpymem(p, "<a href=\"/", sizeof("<a href=\"/") - 1);

    for (i = 0; i < 16; i++) {
        /* Numerical Recipes LCG; deterministic, cheap, no global RNG. */
        rng = rng * 1664525u + 1013904223u;
        *p++ = hex[(rng >> 24) & 0x0f];
    }
    tctx->rng = rng;

    p = ngx_cpymem(p, "/\">x</a>\n", sizeof("/\">x</a>\n") - 1);

    return (ngx_uint_t) (p - tctx->maze_frag);
}

static void
sentinel_tarpit_write_handler(ngx_http_request_t *r)
{
    ngx_connection_t           *c;
    ngx_sentinel_tarpit_ctx_t  *tctx;
    ngx_int_t                   rc;
    ngx_uint_t                  tick_bytes;
    ngx_msec_t                  wait;

    c    = r->connection;
    tctx = ngx_http_get_module_ctx(r, ngx_http_sentinel_module);

    if (tctx == NULL) {
        /* Defensive: should not happen. The handler is only armed after the
         * ctx is set and the extra reference taken, so balance it here too. */
        sentinel_tarpit_finish(r);
        return;
    }

    /* 1. Deadline / byte-budget check (hard lifetime ceiling). */
    if (ngx_current_msec >= tctx->deadline
        || tctx->bytes_sent >= tctx->bytes_total)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "sentinel: tarpit expired (sent=%ui deadline=%M now=%M)",
                      tctx->bytes_sent, tctx->deadline, ngx_current_msec);
        sentinel_tarpit_finish(r);
        return;
    }

    /* 2. Connection-dead check. */
    if (c->error || c->write->error || c->close) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "sentinel: tarpit client gone");
        sentinel_tarpit_finish(r);
        return;
    }

    /* 3. Build buf. Maze mode drips a fresh decoy-link line from the per-ctx
     *    scratch buffer; plain mode points at the global static space buffer. */
    tick_bytes = tctx->bytes_total - tctx->bytes_sent;

    /* Reuse the buf/chain fields in ctx — no per-tick alloc. */
    ngx_memzero(&tctx->buf, sizeof(ngx_buf_t));

    if (tctx->maze) {
        ngx_uint_t  frag_len = sentinel_tarpit_maze_fragment(tctx);

        if (tick_bytes > frag_len) {
            tick_bytes = frag_len;
        }
        tctx->buf.pos  = tctx->maze_frag;
        tctx->buf.last = tctx->maze_frag + tick_bytes;

    } else {
        if (tick_bytes > NGX_SENTINEL_TARPIT_TICK_BYTES) {
            tick_bytes = NGX_SENTINEL_TARPIT_TICK_BYTES;
        }
        tctx->buf.pos  = ngx_sentinel_drip_buf;
        tctx->buf.last = ngx_sentinel_drip_buf + tick_bytes;
    }

    tctx->buf.memory = 1;
    tctx->buf.flush  = 1;

    tctx->chain.buf  = &tctx->buf;
    tctx->chain.next = NULL;

    rc = ngx_http_output_filter(r, &tctx->chain);

    if (rc == NGX_ERROR) {
        r->main->count--;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        /*
         * Socket buffer full — client is slow (good, or it never drains at all).
         * Leave the write event registered so nginx re-invokes us on
         * writability. We do NOT busy-loop and we do NOT account bytes (they
         * were not fully sent).
         *
         * We MUST still arm a timer, though: a client that never reads will
         * never become writable, so without a timer the deadline check at the
         * top of the tick would never run and max_lifetime would not be
         * enforced (connection held indefinitely). Arm a timer bounded by the
         * time remaining to the deadline so the hard lifetime ceiling always
         * fires — whichever happens first (writability or this timer)
         * re-invokes the handler, and the deadline guard then force-closes.
         */
        r->write_event_handler = sentinel_tarpit_write_handler;
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            r->main->count--;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        if (ngx_current_msec >= tctx->deadline) {
            wait = tctx->delay_ms;
        } else {
            wait = tctx->deadline - ngx_current_msec;
            if (wait > tctx->delay_ms) {
                wait = tctx->delay_ms;
            }
        }
        ngx_add_timer(c->write, wait);
        return;
    }

    /* NGX_OK: bytes sent. */
    tctx->bytes_sent += tick_bytes;

    /* 4. Post-tick limits check. */
    if (tctx->bytes_sent >= tctx->bytes_total
        || ngx_current_msec >= tctx->deadline)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "sentinel: tarpit complete (sent=%ui)", tctx->bytes_sent);
        sentinel_tarpit_finish(r);
        return;
    }

    /* 5. Schedule next tick, bounded by the remaining time to the deadline so
     *    a long delay can never overshoot max_lifetime. */
    r->write_event_handler = sentinel_tarpit_write_handler;

    if (ngx_current_msec >= tctx->deadline) {
        wait = tctx->delay_ms;
    } else {
        wait = tctx->deadline - ngx_current_msec;
        if (wait > tctx->delay_ms) {
            wait = tctx->delay_ms;
        }
    }
    ngx_add_timer(c->write, wait);
}

/* -------------------------------------------------------------------------
 * Timer event handler wrapper: nginx calls c->write->handler when the timer
 * fires (or on writability). We route to the request-level write handler and
 * then drain posted requests.
 *
 * The posted-requests drain is essential: when we finalize with
 * NGX_HTTP_CLOSE, ngx_http_terminate_request() POSTS a terminal request (it
 * does not close inline, because our write_event_handler is set). Posted
 * requests are only run by ngx_http_run_posted_requests(), which the normal
 * request entry point (ngx_http_request_handler) calls after the event handler
 * returns. Because we are invoked directly from the connection's write/timer
 * event — bypassing ngx_http_request_handler — we must run them ourselves, or
 * the connection lingers until some unrelated event (or a client timeout)
 * eventually drains the queue. This is what made max_lifetime appear not to
 * fire.
 * ---------------------------------------------------------------------- */

static void
sentinel_tarpit_timer_handler(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = wev->data;
    r = c->data;

    sentinel_tarpit_write_handler(r);

    ngx_http_run_posted_requests(c);
}

/* -------------------------------------------------------------------------
 * sentinel_tarpit_start — public entry point called from preaccess handler.
 *
 * Returns:
 *   NGX_DONE        — tarpit running; caller must return NGX_DONE
 *   NGX_HTTP_CLOSE  — at cap; caller should return NGX_HTTP_CLOSE (444)
 *   NGX_DECLINED    — fail-open (setup error); caller allows the request
 * ---------------------------------------------------------------------- */

ngx_int_t
sentinel_tarpit_start(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf)
{
    ngx_connection_t           *c;
    ngx_sentinel_main_conf_t   *mcf;
    ngx_sentinel_tarpit_ctx_t  *tctx;
    ngx_pool_cleanup_t         *cln;
    ngx_int_t                   rc;
    ngx_atomic_t               *slot;

    /* Ensure static drip buffer is filled (idempotent after first call). */
    if (!ngx_sentinel_drip_buf_ready) {
        ngx_memset(ngx_sentinel_drip_buf, ' ', NGX_SENTINEL_TARPIT_TICK_MAX - 1);
        ngx_sentinel_drip_buf[NGX_SENTINEL_TARPIT_TICK_MAX - 1] = '\n';
        ngx_sentinel_drip_buf_ready = 1;
    }

    c   = r->connection;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_sentinel_module);

    if (mcf == NULL) {
        return NGX_DECLINED;  /* fail-open */
    }

    /* 1. Reserve slot (CAS loop + global cap check). */
    rc = sentinel_tarpit_reserve(mcf, (ngx_uint_t) lcf->tarpit_max_conns, &slot);

    if (rc == NGX_HTTP_CLOSE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "sentinel: tarpit at cap (%uA/%ui) -> 444",
                      sentinel_tarpit_sum(mcf),
                      (ngx_uint_t) lcf->tarpit_max_conns);
        return NGX_HTTP_CLOSE;
    }

    if (rc == NGX_ERROR) {
        /* tarpit disabled (max_conns == 0) or shm not ready. */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "sentinel: tarpit disabled (max_conns=0), falling back");
        return NGX_DECLINED;
    }

    /*
     * Slot is now reserved. From this point, any early return MUST release
     * it — either by decrementing manually (before cleanup is registered)
     * or by letting the cleanup do it (after cleanup is registered).
     */

    /* 2. Allocate tarpit ctx from request pool (ONE alloc; no per-tick alloc). */
    tctx = ngx_pcalloc(r->pool, sizeof(ngx_sentinel_tarpit_ctx_t));
    if (tctx == NULL) {
        /* Release manually — cleanup not yet registered. */
        (void) ngx_atomic_fetch_add(slot, (ngx_atomic_int_t) -1);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "sentinel: tarpit ctx alloc failed (fail-open)");
        return NGX_DECLINED;
    }

    tctx->slot        = slot;
    tctx->bytes_total = (ngx_uint_t) lcf->tarpit_bytes;
    tctx->delay_ms    = (ngx_msec_t) lcf->tarpit_delay;
    tctx->deadline    = ngx_current_msec + (ngx_msec_t) lcf->tarpit_max_lifetime;
    tctx->bytes_sent  = 0;
    tctx->maze        = lcf->tarpit_maze ? 1 : 0;
    /* Seed the maze LCG from cheap per-connection entropy (no global RNG):
     * current ms + the connection fd + ctx address low bits. */
    tctx->rng = (uint32_t) ngx_current_msec
              ^ (uint32_t) (uintptr_t) c->fd
              ^ (uint32_t) (uintptr_t) tctx;
    /* tctx->counted set AFTER cleanup registration. */

    /* 3. Register pool cleanup — the ONE AND ONLY decrement site.
     *    Must be registered before arming any timer. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        /* Release manually. */
        (void) ngx_atomic_fetch_add(slot, (ngx_atomic_int_t) -1);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "sentinel: tarpit cleanup alloc failed (fail-open)");
        return NGX_DECLINED;
    }

    cln->handler = sentinel_tarpit_cleanup;
    cln->data    = tctx;
    tctx->counted = 1;  /* slot is reserved; cleanup is now responsible for decrement */

    /* 4. Send response headers.
     *    Status 200, Content-Type: text/plain, no Content-Length, Connection: close.
     *    No Content-Length means chunked / open-ended — client keeps waiting. */
    r->keepalive = 0;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = -1;

    if (tctx->maze) {
        r->headers_out.content_type.len  = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html";
    } else {
        r->headers_out.content_type.len  = sizeof("text/plain") - 1;
        r->headers_out.content_type.data = (u_char *) "text/plain";
    }
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR) {
        /* tctx->counted=1 so pool cleanup will decrement. Finalize the request. */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "sentinel: tarpit header send error (fail-open)");
        ngx_http_finalize_request(r, NGX_ERROR);
        return NGX_DONE;  /* request ownership transferred */
    }

    if (rc > NGX_OK) {
        /* Header-only response (e.g., HEAD request). Finalize cleanly. */
        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }

    /* 5. Store ctx so the write handler can retrieve it. */
    ngx_http_set_ctx(r, tctx, ngx_http_sentinel_module);

    /* 6. Hold the request alive across timer ticks. */
    r->main->count++;

    /* 7. Arm first tick. */
    r->write_event_handler = sentinel_tarpit_write_handler;
    c->write->handler      = sentinel_tarpit_timer_handler;

    ngx_add_timer(c->write, tctx->delay_ms);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "sentinel: tarpitting (delay=%Mms bytes=%ui lifetime=%Mms maze=%ui)",
                  tctx->delay_ms, tctx->bytes_total,
                  (ngx_msec_t) lcf->tarpit_max_lifetime,
                  (ngx_uint_t) tctx->maze);

    return NGX_DONE;
}

/* -------------------------------------------------------------------------
 * sentinel_tarpit_init_process — zero this worker's sub-counter slot.
 * Hooked into the module's init_process callback; self-heals after hard kills.
 * ---------------------------------------------------------------------- */

ngx_int_t
sentinel_tarpit_init_process(ngx_cycle_t *cycle)
{
    ngx_sentinel_main_conf_t  *mcf;
    ngx_uint_t                 worker;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_sentinel_module);
    if (mcf == NULL || mcf->tarpit_conns == NULL) {
        return NGX_OK;
    }

    worker = (ngx_uint_t) ngx_worker;
    if (worker >= NGX_MAX_PROCESSES) {
        worker = 0;
    }

    /* Zero our slot: reclaims any count stranded by a previous hard kill. */
    mcf->tarpit_conns[worker] = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "sentinel: tarpit slot[%ui] zeroed at init_process", worker);

    return NGX_OK;
}
