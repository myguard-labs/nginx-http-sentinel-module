/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_feed.c — Phase 3 CrowdSec decision-feed loader + request-path read.
 *
 * Implements DESIGN decisions #1 (no network I/O in the request path) and #6
 * (CrowdSec consumed out-of-band, not via live LAPI). See phase3-crowdsec-spec.md.
 *
 * Two halves:
 *   1. Out-of-band loader — a per-worker ngx_event timer (armed in init_process)
 *      that stat-gates the feed file, size-caps + reads it into a transient
 *      pool, validates a self-describing trailer (record count + CRC32) BEFORE
 *      touching shm, then mark-and-sweeps the verified decisions into the
 *      crowdsec shm zone in lock-batched chunks under a generation counter.
 *      Fail-open everywhere: any error keeps the last-good table + TTL age-out.
 *   2. Request-path read — sentinel_crowdsec_signal(): an O(1) locked lookup,
 *      no allocation in the hot path.
 *
 * Feed grammar (hand-rolled byte scan, NO regex, NO JSON):
 *
 *   # sentinel-crowdsec-feed v1          <- header line 1 (version sentinel)
 *   # generated <iso8601> count=<N>      <- header line 2 (informational)
 *   <ip> <action> <expiry-epoch>         <- one decision per line
 *   ...
 *   %%EOF <N> <crc32hex>                 <- trailer (record count + CRC32 hex)
 *
 * <ip>     dotted IPv4 or canonical IPv6 (exact host; CIDR skipped + logged).
 * <action> one of: ban | captcha | throttle (unknown => malformed line).
 * <expiry> absolute unix seconds; 0 => now + default_ttl.
 *
 * Key normalization mirrors errrate exactly: validate the feed IP with
 * ngx_inet_addr/ngx_inet6_addr, re-render it to canonical text with
 * ngx_sock_ntop, then key = SHA-256(canonical text). This guarantees the
 * loader and the request path (which hashes r->connection->addr_text) produce
 * byte-identical digests.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Per-worker loader state (one ngx_event timer per configured feed location).
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_event_t               ev;
    ngx_sentinel_loc_conf_t  *lcf;
    ngx_log_t                *log;
    time_t                    last_mtime;     /* mtime of last successful load */
    ngx_flag_t                missing_logged; /* edge-trigger WARN suppression */
    ngx_flag_t                stale_logged;
} sentinel_feed_timer_t;

/* All timers armed in this worker (so init_process can register one per feed
 * location without losing them). Bounded by the number of sentinel locations
 * with a crowdsec feed — config-time bounded, never request-driven. */
#define SENTINEL_FEED_MAX_TIMERS  256
static sentinel_feed_timer_t  *sentinel_feed_timers;
static ngx_uint_t              sentinel_feed_timer_count;

/* -------------------------------------------------------------------------
 * Identity digest = SHA-256(text) — shared derivation with errrate.
 * ---------------------------------------------------------------------- */

static void
sentinel_feed_digest(u_char *text, size_t len, u_char *out /* 32 bytes */)
{
    SHA256(text, len, out);
}

/* -------------------------------------------------------------------------
 * Byte-scan helpers (no regex, no allocation).
 * ---------------------------------------------------------------------- */

/* Map an action token to a tier. Returns NGX_SENTINEL_CS_NONE if unknown. */
static u_char
sentinel_feed_action(u_char *p, size_t len)
{
    if (len == 3 && ngx_strncmp(p, "ban", 3) == 0) {
        return NGX_SENTINEL_CS_BAN;
    }
    if (len == 7 && ngx_strncmp(p, "captcha", 7) == 0) {
        return NGX_SENTINEL_CS_CAPTCHA;
    }
    if (len == 8 && ngx_strncmp(p, "throttle", 8) == 0) {
        return NGX_SENTINEL_CS_THROTTLE;
    }
    return NGX_SENTINEL_CS_NONE;
}

/*
 * Validate + canonicalize an IP token into `canon` (must be >= NGX_SOCKADDR_STRLEN).
 * Returns the canonical length, or 0 if the token is not a bare host IP
 * (CIDR, malformed, etc.).
 */
static size_t
sentinel_feed_canon_ip(u_char *p, size_t len, u_char *canon)
{
    u_char            tmp[64];
    in_addr_t         inaddr;
    struct in_addr    v4;
    struct in6_addr   v6;

    /* Reject CIDR / overlong tokens up front (Phase 3: exact host only). */
    if (len == 0 || len >= sizeof(tmp)) {
        return 0;
    }
    if (memchr(p, '/', len) != NULL) {
        return 0;   /* CIDR — caller logs + skips */
    }

    ngx_memcpy(tmp, p, len);
    tmp[len] = '\0';

    inaddr = ngx_inet_addr(tmp, len);
    if (inaddr != INADDR_NONE) {
        v4.s_addr = inaddr;
        return ngx_inet_ntop(AF_INET, &v4, canon, NGX_SOCKADDR_STRLEN);
    }

    if (ngx_inet6_addr(tmp, len, v6.s6_addr) == NGX_OK) {
        return ngx_inet6_ntop(v6.s6_addr, canon, NGX_SOCKADDR_STRLEN);
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Trailer validation: %%EOF <N> <crc32hex>
 *
 * `body` spans the decision-line region (after the header lines, up to the
 * trailer). `count` is the number of decision lines the caller parsed and
 * `crc` is ngx_crc32 over `body`. Returns NGX_OK if the trailer matches.
 * ---------------------------------------------------------------------- */

static ngx_int_t
sentinel_feed_check_trailer(u_char *trailer, size_t tlen,
    ngx_uint_t count, uint32_t crc)
{
    u_char     *p, *end;
    ngx_int_t   n;
    uint32_t    file_crc;
    u_char      c;

    if (tlen < sizeof("%%EOF 0 0") - 1) {
        return NGX_DECLINED;
    }
    if (ngx_strncmp(trailer, "%%EOF ", 6) != 0) {
        return NGX_DECLINED;
    }

    p   = trailer + 6;
    end = trailer + tlen;

    /* record count */
    {
        u_char *cstart = p;
        while (p < end && *p != ' ') {
            p++;
        }
        if (p == cstart || p >= end) {
            return NGX_DECLINED;
        }
        n = ngx_atoi(cstart, (size_t) (p - cstart));
        if (n == NGX_ERROR || (ngx_uint_t) n != count) {
            return NGX_DECLINED;
        }
        p++;  /* skip the space */
    }

    /* crc32 hex (lowercase, up to 8 nibbles) */
    file_crc = 0;
    if (p >= end) {
        return NGX_DECLINED;
    }
    for (; p < end; p++) {
        c = *p;
        if (c >= '0' && c <= '9') {
            file_crc = (file_crc << 4) | (uint32_t) (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            file_crc = (file_crc << 4) | (uint32_t) (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            file_crc = (file_crc << 4) | (uint32_t) (c - 'A' + 10);
        } else {
            return NGX_DECLINED;
        }
    }

    return (file_crc == crc) ? NGX_OK : NGX_DECLINED;
}

/* -------------------------------------------------------------------------
 * Parser + apply.
 *
 * One pass over the buffer. Header must be present (first line equals
 * NGX_SENTINEL_FEED_HEADER). The decision-line region runs until the %%EOF
 * trailer; CRC32 is taken over exactly those bytes. The whole file is validated
 * (count + CRC) before any shm mutation. Apply = lock-batched mark-and-sweep
 * under a fresh generation.
 * ---------------------------------------------------------------------- */

ngx_int_t
sentinel_feed_parse(ngx_sentinel_zone_t *zone, ngx_log_t *log,
    u_char *data, size_t len, ngx_int_t default_ttl, time_t now)
{
    u_char       *p, *end, *line, *nl;
    u_char       *body_start, *trailer;
    size_t        body_len;
    ngx_uint_t    count, malformed, applied;
    ngx_uint_t    generation;
    uint32_t      crc;

    if (zone == NULL || zone->sh == NULL || zone->shpool == NULL) {
        return NGX_ERROR;
    }
    if (data == NULL || len == 0) {
        return NGX_DECLINED;
    }

    p   = data;
    end = data + len;

    /* --- Header line 1 must be the version sentinel. --- */
    nl = memchr(p, '\n', (size_t) (end - p));
    {
        size_t hl = (nl != NULL) ? (size_t) (nl - p) : (size_t) (end - p);
        size_t want = sizeof(NGX_SENTINEL_FEED_HEADER) - 1;
        if (hl != want || ngx_strncmp(p, NGX_SENTINEL_FEED_HEADER, want) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sentinel: crowdsec feed bad/missing header "
                          "(fail-open, keeping last-good table)");
            return NGX_DECLINED;
        }
    }
    if (nl == NULL) {
        return NGX_DECLINED;   /* header only, no body/trailer */
    }
    p = nl + 1;

    /*
     * The decision-line region begins after the header line and ends at the
     * trailer line. CRC32 covers exactly the bytes between body_start and the
     * trailer start. We first count + validate by scanning, locating the
     * trailer, then re-scan for the apply pass.
     */
    body_start = p;
    trailer    = NULL;

    /* Locate the %%EOF trailer line. */
    {
        u_char *q = body_start;
        while (q < end) {
            u_char *e = memchr(q, '\n', (size_t) (end - q));
            size_t  ll = (e != NULL) ? (size_t) (e - q) : (size_t) (end - q);
            if (ll >= 6 && ngx_strncmp(q, "%%EOF ", 6) == 0) {
                trailer = q;
                break;
            }
            if (e == NULL) {
                break;
            }
            q = e + 1;
        }
    }

    if (trailer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed missing %%%%EOF trailer "
                      "(truncated? fail-open)");
        return NGX_DECLINED;
    }

    body_len = (size_t) (trailer - body_start);
    crc      = ngx_crc32_long(body_start, body_len);

    /* --- Counting / validation pass (NO shm mutation). --- */
    count     = 0;
    malformed = 0;

    p = body_start;
    while (p < trailer) {
        nl = memchr(p, '\n', (size_t) (trailer - p));
        line = p;
        {
            size_t  ll = (nl != NULL) ? (size_t) (nl - p) : (size_t) (trailer - p);
            p = (nl != NULL) ? nl + 1 : trailer;

            /* blank / comment line: ignore (not a decision, not malformed). */
            if (ll == 0 || line[0] == '#') {
                continue;
            }
            /* tolerate a trailing \r. */
            if (ll > 0 && line[ll - 1] == '\r') {
                ll--;
            }
            if (ll == 0) {
                continue;
            }

            /* Field 1: IP (up to first space). */
            {
                u_char  *f1 = line, *f1end = line;
                u_char  *f2, *f2end, *f3, *f3end;
                u_char   canon[NGX_SOCKADDR_STRLEN];
                size_t   clen;
                u_char   act;
                ngx_int_t expiry;

                while (f1end < line + ll && *f1end != ' ') {
                    f1end++;
                }
                if (f1end >= line + ll) { malformed++; continue; }

                f2 = f1end + 1;
                f2end = f2;
                while (f2end < line + ll && *f2end != ' ') {
                    f2end++;
                }
                if (f2end >= line + ll) { malformed++; continue; }

                f3 = f2end + 1;
                f3end = line + ll;
                if (f3 >= f3end) { malformed++; continue; }

                clen = sentinel_feed_canon_ip(f1, (size_t) (f1end - f1), canon);
                if (clen == 0) {
                    /* CIDR / bad IP: log + skip (counts as malformed). */
                    malformed++;
                    continue;
                }

                act = sentinel_feed_action(f2, (size_t) (f2end - f2));
                if (act == NGX_SENTINEL_CS_NONE) {
                    malformed++;
                    continue;
                }

                expiry = ngx_atoi(f3, (size_t) (f3end - f3));
                if (expiry == NGX_ERROR) {
                    malformed++;
                    continue;
                }

                (void) act;
                (void) expiry;
                count++;
            }
        }
    }

    /* Trailer count + CRC must match the decision lines we accepted. */
    {
        size_t  tlen;
        u_char *te = memchr(trailer, '\n', (size_t) (end - trailer));
        tlen = (te != NULL) ? (size_t) (te - trailer) : (size_t) (end - trailer);
        if (tlen > 0 && trailer[tlen - 1] == '\r') {
            tlen--;
        }
        if (sentinel_feed_check_trailer(trailer, tlen, count, crc) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sentinel: crowdsec feed trailer/CRC/count mismatch "
                          "(count=%ui crc=%08xD) -> reject, keep last-good",
                          count, crc);
            return NGX_DECLINED;
        }
    }

    /* Malformed-fraction guard: too many bad lines => treat as torn file. */
    if (malformed > 0
        && malformed * NGX_SENTINEL_FEED_MALFORMED_DENOM > (count + malformed))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed too many malformed lines "
                      "(%ui/%ui) -> reject, keep last-good",
                      malformed, count + malformed);
        return NGX_DECLINED;
    }
    if (malformed > 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed %ui malformed/skipped lines "
                      "(accepting %ui valid)", malformed, count);
    }

    /*
     * --- Apply pass: lock-batched mark-and-sweep under a new generation. ---
     * Validation passed; now mutate shm. Bump generation under the lock first.
     */
    ngx_shmtx_lock(&zone->shpool->mutex);
    zone->sh->cs_generation++;
    generation = zone->sh->cs_generation;
    ngx_shmtx_unlock(&zone->shpool->mutex);

    applied = 0;
    p = body_start;

    ngx_shmtx_lock(&zone->shpool->mutex);
    while (p < trailer) {
        nl = memchr(p, '\n', (size_t) (trailer - p));
        line = p;
        {
            size_t  ll = (nl != NULL) ? (size_t) (nl - p) : (size_t) (trailer - p);
            p = (nl != NULL) ? nl + 1 : trailer;

            if (ll == 0 || line[0] == '#') { continue; }
            if (line[ll - 1] == '\r') { ll--; }
            if (ll == 0) { continue; }

            {
                u_char   *f1 = line, *f1end = line, *f2, *f2end, *f3, *f3end;
                u_char    canon[NGX_SOCKADDR_STRLEN];
                u_char    digest[NGX_SENTINEL_DIGEST_LEN];
                ngx_str_t key;
                size_t    clen;
                u_char    act;
                ngx_int_t expiry;
                time_t    exp;

                while (f1end < line + ll && *f1end != ' ') { f1end++; }
                if (f1end >= line + ll) { continue; }
                f2 = f1end + 1; f2end = f2;
                while (f2end < line + ll && *f2end != ' ') { f2end++; }
                if (f2end >= line + ll) { continue; }
                f3 = f2end + 1; f3end = line + ll;
                if (f3 >= f3end) { continue; }

                clen = sentinel_feed_canon_ip(f1, (size_t) (f1end - f1), canon);
                if (clen == 0) { continue; }
                act = sentinel_feed_action(f2, (size_t) (f2end - f2));
                if (act == NGX_SENTINEL_CS_NONE) { continue; }
                expiry = ngx_atoi(f3, (size_t) (f3end - f3));
                if (expiry == NGX_ERROR) { continue; }

                exp = (time_t) expiry;
                if (exp == 0) {
                    exp = now + default_ttl;
                }
                /* Already-expired decision => effectively a deletion: skip. */
                if (exp <= now) {
                    continue;
                }

                sentinel_feed_digest(canon, clen, digest);
                key.data = digest;
                key.len  = NGX_SENTINEL_DIGEST_LEN;

                if (sentinel_shm_crowdsec_upsert(zone, &key, exp, act,
                                                 generation, now, 0) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                  "sentinel: crowdsec zone full, partial load "
                                  "(%ui applied)", applied);
                    /* Stop inserting; what fit stays. Sweep below still runs. */
                    p = trailer;
                    break;
                }

                applied++;

                /* Lock-batch: release + re-take so readers see progress and a
                 * huge feed never monopolizes the lock. */
                if ((applied % NGX_SENTINEL_FEED_APPLY_BATCH) == 0) {
                    ngx_shmtx_unlock(&zone->shpool->mutex);
                    ngx_shmtx_lock(&zone->shpool->mutex);
                }
            }
        }
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);

    /* Mark-and-sweep deletions: nodes not stamped with this generation are
     * absent from the new feed => removed upstream => drop them. Batched. */
    for ( ;; ) {
        ngx_uint_t  d;
        ngx_shmtx_lock(&zone->shpool->mutex);
        d = sentinel_shm_crowdsec_sweep(zone, generation,
                                        NGX_SENTINEL_FEED_APPLY_BATCH);
        ngx_shmtx_unlock(&zone->shpool->mutex);
        if (d == 0) {
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "sentinel: crowdsec feed applied gen=%ui entries=%ui",
                  generation, applied);

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Out-of-band loader tick.
 * ---------------------------------------------------------------------- */

static void
sentinel_feed_do_load(sentinel_feed_timer_t *t)
{
    ngx_sentinel_loc_conf_t  *lcf = t->lcf;
    ngx_log_t                *log = t->log;
    ngx_file_info_t           fi;
    ngx_fd_t                  fd;
    ngx_file_t                file;
    ngx_pool_t               *pool;
    u_char                   *buf;
    ssize_t                   n;
    size_t                    fsize;
    time_t                    now, mtime;

    now = ngx_time();

    if (lcf->cs_feed.len == 0 || lcf->cs_zone == NULL) {
        return;   /* feature off */
    }

    /* --- stat gate --- */
    if (ngx_file_info(lcf->cs_feed.data, &fi) == NGX_FILE_ERROR) {
        if (!t->missing_logged) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "sentinel: crowdsec feed \"%V\" stat failed "
                          "(fail-open, keeping last-good table)", &lcf->cs_feed);
            t->missing_logged = 1;
        }
        return;
    }
    t->missing_logged = 0;

    mtime = ngx_file_mtime(&fi);
    fsize = (size_t) ngx_file_size(&fi);

    /* --- stale detection (mtime-age) --- */
    if (now - mtime > lcf->cs_stale_after) {
        if (!t->stale_logged) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sentinel: crowdsec feed \"%V\" stale "
                          "(mtime age %T s > %i s); keeping entries, TTL age-out",
                          &lcf->cs_feed, (time_t) (now - mtime),
                          lcf->cs_stale_after);
            t->stale_logged = 1;
        }
        /* Do NOT wipe — natural per-entry expiry handles a dead sidecar. */
        return;
    }
    t->stale_logged = 0;

    /* --- mtime unchanged since last successful load => skip (cheap idle) --- */
    if (t->last_mtime != 0 && mtime == t->last_mtime) {
        return;
    }

    /* --- size cap (before read) --- */
    if (fsize == 0) {
        return;
    }
    if (fsize > lcf->cs_max_bytes) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed \"%V\" oversized (%uz > %uz) "
                      "-> reject (fail-open)", &lcf->cs_feed, fsize,
                      lcf->cs_max_bytes);
        /* Do not advance last_mtime so a shrunk replacement is retried. */
        return;
    }

    /* --- transient pool (out-of-band malloc OK; freed at end of tick) --- */
    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed pool alloc failed (fail-open)");
        return;
    }

    fd = ngx_open_file(lcf->cs_feed.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "sentinel: crowdsec feed \"%V\" open failed (fail-open)",
                      &lcf->cs_feed);
        ngx_destroy_pool(pool);
        return;
    }

    buf = ngx_palloc(pool, fsize);
    if (buf == NULL) {
        ngx_close_file(fd);
        ngx_destroy_pool(pool);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed buffer alloc failed (fail-open)");
        return;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd   = fd;
    file.name = lcf->cs_feed;
    file.log  = log;

    /* Single bounded read (size-capped above): out-of-band, acceptable. */
    n = ngx_read_file(&file, buf, fsize, 0);
    ngx_close_file(fd);

    if (n == NGX_ERROR || (size_t) n < fsize) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed \"%V\" short/failed read "
                      "(%z/%uz) -> reject (fail-open)",
                      &lcf->cs_feed, n, fsize);
        ngx_destroy_pool(pool);
        return;
    }

    if (sentinel_feed_parse(lcf->cs_zone, log, buf, (size_t) n,
                            lcf->cs_default_ttl, now) == NGX_OK)
    {
        t->last_mtime = mtime;   /* only advance on a verified, applied feed */
    }

    ngx_destroy_pool(pool);
}

static void
sentinel_feed_timer_handler(ngx_event_t *ev)
{
    sentinel_feed_timer_t  *t = ev->data;

    sentinel_feed_do_load(t);

    /* Do NOT re-arm during shutdown/reload. nginx will not auto-cancel a
     * self-re-arming module timer, so an unconditional re-arm keeps the
     * worker's timer tree non-empty and the worker never exits gracefully
     * (leaked old workers on `nginx -s reload`). Bail on exit/terminate. */
    if (ngx_exiting || ngx_terminate) {
        return;
    }

    ngx_add_timer(ev, (ngx_msec_t) t->lcf->cs_interval * 1000);
}

/* -------------------------------------------------------------------------
 * init_process: walk every http loc-conf, arm one timer per crowdsec feed.
 * ---------------------------------------------------------------------- */

static ngx_int_t
sentinel_feed_collect(ngx_cycle_t *cycle, ngx_array_t *out);

ngx_int_t
sentinel_crowdsec_init_process(ngx_cycle_t *cycle)
{
    ngx_array_t   feeds;
    ngx_uint_t    i;
    ngx_sentinel_loc_conf_t  **lcfp;

    if (ngx_array_init(&feeds, cycle->pool, 8,
                       sizeof(ngx_sentinel_loc_conf_t *)) != NGX_OK)
    {
        return NGX_OK;   /* fail-open */
    }

    if (sentinel_feed_collect(cycle, &feeds) != NGX_OK || feeds.nelts == 0) {
        return NGX_OK;
    }

    if (feeds.nelts > SENTINEL_FEED_MAX_TIMERS) {
        feeds.nelts = SENTINEL_FEED_MAX_TIMERS;
    }

    sentinel_feed_timers = ngx_pcalloc(cycle->pool,
                              sizeof(sentinel_feed_timer_t) * feeds.nelts);
    if (sentinel_feed_timers == NULL) {
        return NGX_OK;
    }
    sentinel_feed_timer_count = feeds.nelts;

    lcfp = feeds.elts;
    for (i = 0; i < feeds.nelts; i++) {
        sentinel_feed_timer_t  *t = &sentinel_feed_timers[i];

        t->lcf  = lcfp[i];
        t->log  = cycle->log;
        t->ev.handler = sentinel_feed_timer_handler;
        t->ev.data    = t;
        t->ev.log     = cycle->log;

        /* First tick soon (1s) so a present feed loads promptly. */
        ngx_add_timer(&t->ev, 1000);
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "sentinel: armed %ui crowdsec feed timer(s)", feeds.nelts);

    return NGX_OK;
}

/*
 * Collect the distinct (feed-path,zone) loc-confs. We walk the http core
 * module's server/location tree. To keep it simple and dependency-free we
 * deduplicate by (cs_feed,cs_zone) pointer pair.
 */
static void
sentinel_feed_collect_loc(ngx_http_location_tree_node_t *node,
    ngx_array_t *out);

static ngx_int_t
sentinel_feed_collect(ngx_cycle_t *cycle, ngx_array_t *out)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_conf_ctx_t        *ctx;
    ngx_uint_t                  s;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (ctx == NULL) {
        return NGX_OK;
    }

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    if (cmcf == NULL) {
        return NGX_OK;
    }

    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        if (clcf == NULL) {
            continue;
        }
        if (clcf->static_locations) {
            sentinel_feed_collect_loc(clcf->static_locations, out);
        }
    }

    return NGX_OK;
}

static void
sentinel_feed_add(ngx_array_t *out, ngx_sentinel_loc_conf_t *lcf)
{
    ngx_sentinel_loc_conf_t  **existing, **slot;
    ngx_uint_t                 i;

    if (lcf == NULL || lcf->cs_feed.len == 0 || lcf->cs_zone == NULL) {
        return;
    }

    existing = out->elts;
    for (i = 0; i < out->nelts; i++) {
        if (existing[i] == lcf
            || (existing[i]->cs_zone == lcf->cs_zone
                && existing[i]->cs_feed.len == lcf->cs_feed.len
                && ngx_strncmp(existing[i]->cs_feed.data,
                               lcf->cs_feed.data, lcf->cs_feed.len) == 0))
        {
            return;   /* dedup */
        }
    }

    slot = ngx_array_push(out);
    if (slot == NULL) {
        return;
    }
    *slot = lcf;
}

static void
sentinel_feed_collect_loc(ngx_http_location_tree_node_t *node,
    ngx_array_t *out)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_sentinel_loc_conf_t   *lcf;

    if (node == NULL) {
        return;
    }

    if (node->exact) {
        clcf = node->exact;
        lcf  = clcf->loc_conf[ngx_http_sentinel_module.ctx_index];
        sentinel_feed_add(out, lcf);
    }
    if (node->inclusive) {
        clcf = node->inclusive;
        lcf  = clcf->loc_conf[ngx_http_sentinel_module.ctx_index];
        sentinel_feed_add(out, lcf);
    }

    sentinel_feed_collect_loc(node->left, out);
    sentinel_feed_collect_loc(node->tree, out);
    sentinel_feed_collect_loc(node->right, out);
}

/* -------------------------------------------------------------------------
 * Request-path read.
 * ---------------------------------------------------------------------- */

void
sentinel_crowdsec_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_sentinel_zone_t  *zone;
    u_char                digest[NGX_SENTINEL_DIGEST_LEN];
    ngx_str_t             key;
    ngx_str_t             addr;
    u_char                action;
    time_t                now;
    ngx_int_t             rc;

    inputs->crowdsec_hit    = 0;
    inputs->crowdsec_action = NGX_SENTINEL_CS_NONE;

    zone = lcf->cs_zone;
    if (zone == NULL) {
        return;   /* feature off — fail-open */
    }

    addr.data = r->connection->addr_text.data;
    addr.len  = r->connection->addr_text.len;
    if (addr.len == 0) {
        return;
    }

    /* SHA-256 over the request's canonical addr_text — same derivation the
     * loader applies to the feed IP, so the digests match byte-for-byte. */
    sentinel_feed_digest(addr.data, addr.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

    now = ngx_time();
    rc  = sentinel_shm_crowdsec_lookup(zone, &key, now, &action);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "sentinel: crowdsec zone \"%V\" lookup error (fail-open)",
                      &zone->name);
        return;
    }

    if (rc == NGX_BUSY) {
        inputs->crowdsec_hit    = 1;
        inputs->crowdsec_action = action;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: crowdsec hit=%i action=%ui",
                   (ngx_int_t) inputs->crowdsec_hit,
                   (ngx_uint_t) inputs->crowdsec_action);
}
