/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * fuzz_ja4h_canon.c -- libFuzzer target for the JA4H canonical-string builder.
 *
 * Fuzz surface: sentinel_ja4h_compute() with a synthetic ngx_http_request_t
 * whose header list is populated from the fuzzer input.
 *
 * What is fuzzed:
 *   The code paths in sentinel_ja4h_compute() that:
 *     - Walk r->headers_in.headers (list parts)
 *     - Sort header names (ngx_qsort)
 *     - Build the canonical string via the CANAPPEND_* macros
 *     - Handle overflow / accept-language first-tag extraction
 *   The fuzzer drives header count, header-name content, cookie/referer
 *   presence, and accept-language value by splitting the input buffer into
 *   a configurable set of headers.
 *
 * Standalone compilation:
 *   sentinel_ja4h_compute is tightly coupled to ngx_http_request_t (it reads
 *   r->method, r->http_version, r->headers_in.*).  Rather than isolating a
 *   sub-function (no cleanly separable pure helper exists), we provide minimal
 *   stubs for all nginx types the function touches and include the .c directly.
 *   SHA256 is provided by -lssl (linked in build.sh).
 *
 * Build: see fuzz/build.sh
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

/* -------------------------------------------------------------------------
 * Minimal nginx type stubs.
 * ---------------------------------------------------------------------- */

typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef int            ngx_flag_t;

#define NGX_OK    0
#define NGX_ERROR (-1)

#define ngx_inline inline
#define ngx_string(str)  { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string  { 0, NULL }

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* Logging: discard. */
#define ngx_log_error(level, log, err, fmt, ...)  ((void)0)
#define ngx_log_debug2(level, log, err, fmt, ...) ((void)0)
typedef void ngx_log_t;

#define ngx_strncmp(s1, s2, n)      strncmp((char *)(s1), (char *)(s2), (n))
#define ngx_strncasecmp(s1, s2, n)  strncasecmp((char *)(s1), (char *)(s2), (n))
#define ngx_tolower(c)              (u_char) tolower((int)(c))
#define ngx_memcpy(d, s, n)         memcpy((d), (s), (n))
#define ngx_memset(d, c, n)         memset((d), (c), (n))
#define ngx_qsort                   qsort

#include <ctype.h>
#include <strings.h>

/* -------------------------------------------------------------------------
 * Sentinel / JA4H constants (must match sentinel.h exactly).
 * ---------------------------------------------------------------------- */

#define NGX_SENTINEL_JA4H_BIN_LEN   12
#define NGX_SENTINEL_JA4H_HEX_LEN   (NGX_SENTINEL_JA4H_BIN_LEN * 2)
#define NGX_SENTINEL_JA4H_CANLEN    4096

/* -------------------------------------------------------------------------
 * Minimal request type stubs — only what sentinel_ja4h_compute touches.
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_uint_t  hash;
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_table_elt_t;

/*
 * ngx_list_part_t: nginx header list node.
 * We use a single flat array of table entries; next == NULL terminates.
 */
typedef struct ngx_list_part_s {
    void                   *elts;
    ngx_uint_t              nelts;
    struct ngx_list_part_s *next;
} ngx_list_part_t;

typedef struct {
    ngx_list_part_t   part;
    /* We ignore the rest of ngx_list_t fields. */
} ngx_list_t;

typedef struct {
    ngx_list_t         headers;
    ngx_table_elt_t   *accept_language;
    ngx_table_elt_t   *user_agent;       /* not used by ja4h, here for padding */
} ngx_http_headers_in_t;

typedef struct { void *log; } ngx_connection_t;

/* HTTP method constants (match nginx's ngx_http_request.h). */
#define NGX_HTTP_GET     0x0002
#define NGX_HTTP_POST    0x0008
#define NGX_HTTP_PUT     0x0004
#define NGX_HTTP_DELETE  0x0010
#define NGX_HTTP_HEAD    0x0020
#define NGX_HTTP_OPTIONS 0x0200
#define NGX_HTTP_PATCH   0x4000

/* HTTP version constants. */
#define NGX_HTTP_VERSION_11  1001
#define NGX_HTTP_VERSION_20  2000

typedef struct {
    ngx_uint_t              method;
    ngx_uint_t              http_version;
    ngx_http_headers_in_t   headers_in;
    ngx_connection_t       *connection;
} ngx_http_request_t;

/* -------------------------------------------------------------------------
 * Include implementation directly.
 * ---------------------------------------------------------------------- */

#define SENTINEL_H
#include "../src/sentinel_ja4h.c"

/* -------------------------------------------------------------------------
 * Fuzzer helpers.
 * ---------------------------------------------------------------------- */

/*
 * Maximum headers we inject from the fuzzer input.
 * Intentionally exceeds NGX_SENTINEL_JA4H_MAX_HDRS (64) to exercise the cap.
 */
#define FUZZ_MAX_HDRS  80

/*
 * Interpret the fuzzer input as a structured blob:
 *
 *   byte 0:  method selector (mod 8)
 *   byte 1:  http_version selector (mod 3)
 *   byte 2:  number of headers to inject (mod FUZZ_MAX_HDRS)
 *   byte 3:  accept-language length (0 = no accept-language)
 *   bytes 4+: header name bytes interleaved with a 1-byte length prefix per
 *             header, then accept-language bytes if any
 *
 * This layout gives the fuzzer structured control over all fields JA4H reads
 * while remaining a simple flat byte stream (no separate corpus format).
 */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const ngx_uint_t methods[] = {
        NGX_HTTP_GET, NGX_HTTP_POST, NGX_HTTP_PUT, NGX_HTTP_DELETE,
        NGX_HTTP_HEAD, NGX_HTTP_OPTIONS, NGX_HTTP_PATCH, 0x0001 /* unknown */
    };
    static const ngx_uint_t versions[] = {
        NGX_HTTP_VERSION_11 - 1,  /* 10xx */
        NGX_HTTP_VERSION_11,
        NGX_HTTP_VERSION_20
    };

    if (size < 4) {
        return 0;
    }

    ngx_http_request_t   r;
    ngx_connection_t     conn;
    ngx_table_elt_t      hdrs[FUZZ_MAX_HDRS];
    ngx_table_elt_t      al_hdr;
    ngx_list_part_t      part;
    u_char               out[NGX_SENTINEL_JA4H_HEX_LEN + 1];

    memset(&r,    0, sizeof(r));
    memset(&conn, 0, sizeof(conn));
    memset(hdrs,  0, sizeof(hdrs));
    memset(&al_hdr, 0, sizeof(al_hdr));
    memset(&part, 0, sizeof(part));

    r.connection = &conn;

    r.method       = methods[data[0] % 8];
    r.http_version = versions[data[1] % 3];

    ngx_uint_t nhdr = (ngx_uint_t) (data[2] % FUZZ_MAX_HDRS);
    size_t     al_len = (size_t) data[3];

    const uint8_t *p   = data + 4;
    const uint8_t *end = data + size;

    /*
     * Inject up to nhdr headers.  Each header uses a 1-byte length prefix for
     * the name.  We point .data directly into the fuzzer buffer (read-only
     * throughout the call) to avoid allocation.
     */
    ngx_uint_t  injected = 0;
    ngx_uint_t  has_cookie = 0;
    ngx_uint_t  has_referer = 0;

    while (injected < nhdr && p < end) {
        size_t  nlen = (size_t) *p++;
        if (nlen == 0) {
            nlen = 1;
        }
        if ((size_t)(end - p) < nlen) {
            nlen = (size_t)(end - p);
        }
        if (nlen == 0) {
            break;
        }

        hdrs[injected].hash      = 1;   /* non-zero => active */
        hdrs[injected].key.data  = (u_char *) p;
        hdrs[injected].key.len   = nlen;
        hdrs[injected].value.data = (u_char *) "";
        hdrs[injected].value.len  = 0;

        /* Track cookie/referer so we can add explicit entries too. */
        if (nlen == 6 && strncasecmp((char *) p, "Cookie", 6) == 0) {
            has_cookie = 1;
        }
        if (nlen == 7 && strncasecmp((char *) p, "Referer", 7) == 0) {
            has_referer = 1;
        }

        p += nlen;
        injected++;
    }

    /* Accept-Language from remaining bytes if al_len > 0. */
    if (al_len > 0 && p < end) {
        size_t avail = (size_t)(end - p);
        if (al_len > avail) {
            al_len = avail;
        }
        al_hdr.value.data        = (u_char *) p;
        al_hdr.value.len         = al_len;
        r.headers_in.accept_language = &al_hdr;
    }

    part.elts  = hdrs;
    part.nelts = injected;
    part.next  = NULL;

    r.headers_in.headers.part = part;

    sentinel_ja4h_compute(&r, out);

    /* Suppress result — we only care about crashes/OOB. */
    return 0;
}
