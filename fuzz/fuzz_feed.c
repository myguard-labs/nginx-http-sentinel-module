/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * fuzz_feed.c -- libFuzzer target for the CrowdSec feed parser.
 *
 * Fuzz surface: sentinel_feed_parse() — takes arbitrary bytes as a feed
 * file and exercises the full parse path: header check, decision-line scan,
 * %%EOF trailer validation (count + CRC32), and the IP/action helpers.
 *
 * Approach: sentinel_feed.c contains both the parser (sentinel_feed_parse
 * and its static helpers) AND the out-of-band loader (sentinel_feed_do_load,
 * the timer handlers, sentinel_feed_collect, etc.) which needs the full nginx
 * type surface.  We cannot include the whole file without that surface.
 *
 * Solution: include ONLY the static parse-helper functions and
 * sentinel_feed_parse itself, verbatim (they are reproduced below via
 * FUZZ_FEED_PARSE_ONLY guard defined before the include).  A small set of
 * nginx-type stubs covers everything those functions touch.  The shm-mutation
 * calls (upsert, sweep, shmtx lock) are no-op stubs — we are fuzzing the
 * parser, not the shared-memory layer.
 *
 * Build: see fuzz/build.sh
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* -------------------------------------------------------------------------
 * Minimal nginx type stubs — only what the parser functions use.
 * ---------------------------------------------------------------------- */

typedef unsigned char   u_char;
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef int             ngx_flag_t;
typedef unsigned short  u_short;
typedef long            ngx_atomic_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -2
#define NGX_BUSY     -3

#define ngx_inline inline

typedef struct {
    u_char  *data;
    size_t   len;
} ngx_str_t;

/* Logging: discard. */
#define ngx_log_error(level, log, err, fmt, ...)  ((void)0)
typedef void ngx_log_t;

#define ngx_strncmp(s1, s2, n)   strncmp((char *)(s1), (char *)(s2), (n))
#define ngx_memcpy(dst, src, n)  memcpy((dst), (src), (n))

static ngx_int_t
ngx_atoi(u_char *p, size_t len)
{
    ngx_uint_t  val;

    if (len == 0) {
        return NGX_ERROR;
    }
    for (val = 0; len--; p++) {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }
        val = val * 10 + (*p - '0');
        if (val > 0x7fffffff) {
            return NGX_ERROR;
        }
    }
    return (ngx_int_t) val;
}

static in_addr_t
ngx_inet_addr(u_char *text, size_t len)
{
    u_char  tmp[16];

    if (len == 0 || len >= sizeof(tmp)) {
        return INADDR_NONE;
    }
    memcpy(tmp, text, len);
    tmp[len] = '\0';
    return inet_addr((char *) tmp);
}

static ngx_int_t
ngx_inet6_addr(u_char *p, size_t len, u_char *addr)
{
    u_char  tmp[INET6_ADDRSTRLEN + 1];

    if (len == 0 || len >= sizeof(tmp)) {
        return NGX_ERROR;
    }
    memcpy(tmp, p, len);
    tmp[len] = '\0';
    return (inet_pton(AF_INET6, (char *) tmp, addr) == 1) ? NGX_OK : NGX_ERROR;
}

#define NGX_SOCKADDR_STRLEN  128

static size_t
ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    if (inet_ntop(family, addr, (char *) text, (socklen_t) len) == NULL) {
        return 0;
    }
    return strlen((char *) text);
}

static size_t
ngx_inet6_ntop(u_char *p, u_char *text, size_t len)
{
    if (inet_ntop(AF_INET6, p, (char *) text, (socklen_t) len) == NULL) {
        return 0;
    }
    return strlen((char *) text);
}

/* CRC32 matching nginx's ngx_crc32_long (ISO 3309 / Ethernet polynomial). */
static uint32_t
ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;
    while (len--) {
        uint32_t  b = *p++;
        uint32_t  k;
        for (k = 0; k < 8; k++) {
            uint32_t  bit = (crc ^ b) & 1;
            crc >>= 1;
            if (bit) {
                crc ^= 0xedb88320;
            }
            b >>= 1;
        }
    }
    return crc ^ 0xffffffff;
}

/* -------------------------------------------------------------------------
 * Sentinel constants (must match sentinel.h exactly).
 * ---------------------------------------------------------------------- */

#define NGX_SENTINEL_CS_NONE      0
#define NGX_SENTINEL_CS_BAN       1
#define NGX_SENTINEL_CS_CAPTCHA   2
#define NGX_SENTINEL_CS_THROTTLE  3

#define NGX_SENTINEL_DIGEST_LEN   32

#define NGX_SENTINEL_FEED_HEADER          "# sentinel-crowdsec-feed v1"
#define NGX_SENTINEL_FEED_MALFORMED_DENOM 4
#define NGX_SENTINEL_FEED_APPLY_BATCH     256

/* -------------------------------------------------------------------------
 * Minimal shm stubs (no-ops: we test the parser, not shm).
 * ---------------------------------------------------------------------- */

typedef struct { long lock; } ngx_shmtx_t;

static void ngx_shmtx_lock(ngx_shmtx_t *m)   { (void) m; }
static void ngx_shmtx_unlock(ngx_shmtx_t *m) { (void) m; }

typedef struct {
    ngx_shmtx_t  mutex;
} ngx_slab_pool_t;

typedef struct {
    ngx_uint_t  cs_generation;
} ngx_sentinel_shctx_t;

typedef struct {
    ngx_str_t              name;
    void                  *shm_zone;
    ngx_sentinel_shctx_t  *sh;
    ngx_slab_pool_t       *shpool;
    long                   interval;
    long                   block;
    ngx_uint_t             threshold;
} ngx_sentinel_zone_t;

static ngx_int_t
sentinel_shm_crowdsec_upsert(ngx_sentinel_zone_t *zone,
    ngx_str_t *key, long expiry, u_char action, ngx_uint_t generation,
    long now)
{
    (void) zone; (void) key; (void) expiry;
    (void) action; (void) generation; (void) now;
    return NGX_OK;
}

static ngx_uint_t
sentinel_shm_crowdsec_sweep(ngx_sentinel_zone_t *zone,
    ngx_uint_t generation, ngx_uint_t batch)
{
    (void) zone; (void) generation; (void) batch;
    return 0;
}

/* SHA256 stub: the digest is only used as a shm key for upsert (no-op above).
 * A trivial stub is sufficient. */
#define SHA256_DIGEST_LENGTH 32
static u_char *
SHA256(const u_char *d, size_t n, u_char *md)
{
    (void) d; (void) n;
    memset(md, 0, SHA256_DIGEST_LENGTH);
    return md;
}

/* -------------------------------------------------------------------------
 * Inline the parse-only portion of sentinel_feed.c.
 *
 * sentinel_feed.c is split into two parts:
 *   - Parse helpers + sentinel_feed_parse (lines ~65-488)
 *   - Out-of-band loader (lines ~492+, needs full nginx surface)
 *
 * We define FUZZ_FEED_PARSE_ONLY before including so the loader section
 * (guarded by #ifndef FUZZ_FEED_PARSE_ONLY) is skipped.
 *
 * Since we cannot modify sentinel_feed.c, we replicate only the parse
 * functions here.  They are exact copies of the source; any divergence
 * from the canonical source is a maintenance risk — check on updates.
 * ---------------------------------------------------------------------- */

/* ---- sentinel_feed_digest (SHA-256 wrapper) ----------------------------- */
static void
sentinel_feed_digest(u_char *text, size_t len, u_char *out)
{
    SHA256(text, len, out);
}

/* ---- sentinel_feed_action ----------------------------------------------- */
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

/* ---- sentinel_feed_canon_ip --------------------------------------------- */
static size_t
sentinel_feed_canon_ip(u_char *p, size_t len, u_char *canon)
{
    u_char            tmp[64];
    in_addr_t         inaddr;
    struct in_addr    v4;
    struct in6_addr   v6;

    if (len == 0 || len >= sizeof(tmp)) {
        return 0;
    }
    if (memchr(p, '/', len) != NULL) {
        return 0;
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

/* ---- sentinel_feed_check_trailer ---------------------------------------- */
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
        p++;
    }

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

/* ---- sentinel_feed_parse ------------------------------------------------ */
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

    nl = memchr(p, '\n', (size_t) (end - p));
    {
        size_t hl = (nl != NULL) ? (size_t) (nl - p) : (size_t) (end - p);
        size_t want = sizeof(NGX_SENTINEL_FEED_HEADER) - 1;
        if (hl != want || ngx_strncmp(p, NGX_SENTINEL_FEED_HEADER, want) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sentinel: crowdsec feed bad/missing header");
            return NGX_DECLINED;
        }
    }
    if (nl == NULL) {
        return NGX_DECLINED;
    }
    p = nl + 1;

    body_start = p;
    trailer    = NULL;

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
                      "sentinel: crowdsec feed missing %%%%EOF trailer");
        return NGX_DECLINED;
    }

    body_len = (size_t) (trailer - body_start);
    crc      = ngx_crc32_long(body_start, body_len);

    count     = 0;
    malformed = 0;

    p = body_start;
    while (p < trailer) {
        nl = memchr(p, '\n', (size_t) (trailer - p));
        line = p;
        {
            size_t  ll = (nl != NULL) ? (size_t) (nl - p) : (size_t) (trailer - p);
            p = (nl != NULL) ? nl + 1 : trailer;

            if (ll == 0 || line[0] == '#') {
                continue;
            }
            if (ll > 0 && line[ll - 1] == '\r') {
                ll--;
            }
            if (ll == 0) {
                continue;
            }

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

    {
        size_t  tlen;
        u_char *te = memchr(trailer, '\n', (size_t) (end - trailer));
        tlen = (te != NULL) ? (size_t) (te - trailer) : (size_t) (end - trailer);
        if (tlen > 0 && trailer[tlen - 1] == '\r') {
            tlen--;
        }
        if (sentinel_feed_check_trailer(trailer, tlen, count, crc) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "sentinel: crowdsec feed trailer/CRC/count mismatch");
            return NGX_DECLINED;
        }
    }

    if (malformed > 0
        && malformed * NGX_SENTINEL_FEED_MALFORMED_DENOM > (count + malformed))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "sentinel: crowdsec feed too many malformed lines");
        return NGX_DECLINED;
    }

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
                ngx_int_t expiry_val;
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
                expiry_val = ngx_atoi(f3, (size_t) (f3end - f3));
                if (expiry_val == NGX_ERROR) { continue; }

                exp = (time_t) expiry_val;
                if (exp == 0) {
                    exp = now + default_ttl;
                }
                if (exp <= now) {
                    continue;
                }

                sentinel_feed_digest(canon, clen, digest);
                key.data = digest;
                key.len  = NGX_SENTINEL_DIGEST_LEN;

                if (sentinel_shm_crowdsec_upsert(zone, &key, exp, act,
                                                 generation, now) != NGX_OK) {
                    p = trailer;
                    break;
                }

                applied++;

                if ((applied % NGX_SENTINEL_FEED_APPLY_BATCH) == 0) {
                    ngx_shmtx_unlock(&zone->shpool->mutex);
                    ngx_shmtx_lock(&zone->shpool->mutex);
                }
            }
        }
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);

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

    (void) applied;
    return NGX_OK;
}

/* Suppress "NGX_LOG_WARN" undefined — we only use it in ngx_log_error which
 * is a no-op macro, but the compiler still evaluates the argument. */
#ifndef NGX_LOG_WARN
#define NGX_LOG_WARN 4
#endif

/* -------------------------------------------------------------------------
 * libFuzzer entry point.
 * ---------------------------------------------------------------------- */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static ngx_sentinel_shctx_t  shctx;
    static ngx_slab_pool_t       shpool;
    static ngx_sentinel_zone_t   zone;
    static int                   initialized;

    if (!initialized) {
        memset(&shctx,  0, sizeof(shctx));
        memset(&shpool, 0, sizeof(shpool));
        memset(&zone,   0, sizeof(zone));
        zone.sh     = &shctx;
        zone.shpool = &shpool;
        initialized = 1;
    }

    u_char *buf = (u_char *) malloc(size + 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    (void) sentinel_feed_parse(&zone, NULL, buf, size,
                               3600, 1700000000);

    free(buf);
    return 0;
}
