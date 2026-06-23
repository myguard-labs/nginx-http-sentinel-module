/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_ja4h.c — JA4H fingerprint computation from HTTP request headers.
 *
 * JA4H canonical form (per public spec):
 *   method + http_version + has_cookie(1/0) + has_referer(1/0)
 *   + header_count (2 decimal digits)
 *   + sorted header-name list (comma-separated, lowercased, excluding cookie/referer)
 *   + accept-language value (first tag only)
 *
 * We SHA-256 the canonical string and hex the first 12 bytes (24 hex chars).
 * All inputs from r->headers_in — pure HTTP, no TLS.
 * Fixed stack buffer; bail to zero hash on overflow (fail-open).
 */

#include "sentinel.h"

/* Maximum header names we sort for the fingerprint (stack-allocated). */
#define NGX_SENTINEL_JA4H_MAX_HDRS   64

/* We skip these header names from the ordered list per JA4H spec. */
static const ngx_str_t ja4h_skip_names[] = {
    ngx_string("cookie"),
    ngx_string("referer"),
    ngx_null_string
};

static ngx_inline int
ja4h_header_skip(ngx_str_t *name)
{
    const ngx_str_t *s;
    for (s = ja4h_skip_names; s->len; s++) {
        if (name->len == s->len
            && ngx_strncasecmp(name->data, s->data, s->len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int
ja4h_strcmp(const void *a, const void *b)
{
    const ngx_str_t *sa = (const ngx_str_t *) a;
    const ngx_str_t *sb = (const ngx_str_t *) b;
    size_t           min_len;
    int              rc;

    min_len = (sa->len < sb->len) ? sa->len : sb->len;
    rc = ngx_strncasecmp(sa->data, sb->data, min_len);
    if (rc != 0) {
        return rc;
    }
    return (int) sa->len - (int) sb->len;
}

void
sentinel_ja4h_compute(ngx_http_request_t *r, u_char *out)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *hdr;
    ngx_uint_t        i;
    ngx_str_t         hdr_names[NGX_SENTINEL_JA4H_MAX_HDRS];
    ngx_uint_t        nhdr;
    ngx_uint_t        has_cookie, has_referer;
    u_char            canon[NGX_SENTINEL_JA4H_CANLEN];
    u_char           *p, *end;
    u_char            digest[SHA256_DIGEST_LENGTH];
    const char       *method;
    const char       *ver;

    /*
     * On any error or overflow we write the all-zero hash (fail-open):
     * 24 hex zeros + NUL.
     */
    ngx_memset(out, '0', NGX_SENTINEL_JA4H_HEX_LEN);
    out[NGX_SENTINEL_JA4H_HEX_LEN] = '\0';

    /* --- Method (2-char abbreviation) ------------------------------------ */
    switch (r->method) {
    case NGX_HTTP_GET:     method = "ge"; break;
    case NGX_HTTP_POST:    method = "po"; break;
    case NGX_HTTP_PUT:     method = "pu"; break;
    case NGX_HTTP_DELETE:  method = "de"; break;
    case NGX_HTTP_HEAD:    method = "he"; break;
    case NGX_HTTP_OPTIONS: method = "op"; break;
    case NGX_HTTP_PATCH:   method = "pa"; break;
    default:               method = "xx"; break;
    }

    /* --- HTTP version (2-char) ----------------------------------------- */
    if (r->http_version >= NGX_HTTP_VERSION_20) {
        ver = "20";
    } else if (r->http_version >= NGX_HTTP_VERSION_11) {
        ver = "11";
    } else {
        ver = "10";
    }

    /* --- Walk headers once -------------------------------------------- */
    has_cookie  = 0;
    has_referer = 0;
    nhdr        = 0;

    part = &r->headers_in.headers.part;
    while (part) {
        hdr = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].hash == 0) {
                continue;
            }
            if (hdr[i].key.len == sizeof("Cookie") - 1
                && ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) "Cookie",
                                   sizeof("Cookie") - 1) == 0)
            {
                has_cookie = 1;
            } else if (hdr[i].key.len == sizeof("Referer") - 1
                       && ngx_strncasecmp(hdr[i].key.data,
                                          (u_char *) "Referer",
                                          sizeof("Referer") - 1) == 0)
            {
                has_referer = 1;
            }

            if (!ja4h_header_skip(&hdr[i].key)) {
                if (nhdr < NGX_SENTINEL_JA4H_MAX_HDRS) {
                    hdr_names[nhdr].data = hdr[i].key.data;
                    hdr_names[nhdr].len  = hdr[i].key.len;
                    nhdr++;
                }
            }
        }
        part = part->next;
    }

    /* Sort header names for canonical ordering. */
    if (nhdr > 1) {
        ngx_qsort(hdr_names, nhdr, sizeof(ngx_str_t), ja4h_strcmp);
    }

    /* --- Accept-Language: first tag only --------------------------------- */
    u_char  *lang_val = NULL;
    size_t   lang_len = 0;

    if (r->headers_in.accept_language != NULL) {
        u_char *av = r->headers_in.accept_language->value.data;
        size_t  al = r->headers_in.accept_language->value.len;
        /* Take up to the first ',' or ';' or whitespace. */
        size_t j = 0;
        while (j < al && av[j] != ',' && av[j] != ';' && av[j] != ' ') {
            j++;
        }
        /* Cap at 32 chars to keep the canonical string bounded. */
        lang_val = av;
        lang_len = (j > 32) ? 32 : j;
    }

    /* --- Build canonical string into fixed stack buffer ------------------ */
    p   = canon;
    end = canon + NGX_SENTINEL_JA4H_CANLEN - 1;

#define CANAPPEND_STR(s, l)                          \
    do {                                             \
        if (p + (l) >= end) { goto overflow; }      \
        ngx_memcpy(p, (s), (l));                    \
        p += (l);                                    \
    } while (0)

#define CANAPPEND_LIT(lit)  CANAPPEND_STR((lit), sizeof(lit) - 1)

    CANAPPEND_STR((u_char *) method, 2);
    CANAPPEND_LIT("|");
    CANAPPEND_STR((u_char *) ver, 2);
    CANAPPEND_LIT("|");
    *p++ = (u_char) ('0' + (has_cookie  ? 1 : 0));
    *p++ = (u_char) ('0' + (has_referer ? 1 : 0));
    CANAPPEND_LIT("|");

    /* header count (2 decimal digits, capped at 99) */
    {
        ngx_uint_t cnt = (nhdr > 99) ? 99 : nhdr;
        *p++ = (u_char) ('0' + cnt / 10);
        *p++ = (u_char) ('0' + cnt % 10);
    }
    CANAPPEND_LIT("|");

    /* sorted header names, comma-separated, lowercased */
    for (i = 0; i < nhdr; i++) {
        size_t j2;
        if (i > 0) {
            CANAPPEND_LIT(",");
        }
        if (p + hdr_names[i].len >= end) {
            goto overflow;
        }
        for (j2 = 0; j2 < hdr_names[i].len; j2++) {
            *p++ = ngx_tolower(hdr_names[i].data[j2]);
        }
    }

    CANAPPEND_LIT("|");
    if (lang_val && lang_len > 0) {
        CANAPPEND_STR(lang_val, lang_len);
    }

    *p = '\0';

#undef CANAPPEND_STR
#undef CANAPPEND_LIT

    /* --- SHA-256 and hex-encode first 12 bytes -------------------------- */
    SHA256(canon, (size_t) (p - canon), digest);

    {
        static const u_char hex[] = "0123456789abcdef";
        for (i = 0; i < NGX_SENTINEL_JA4H_BIN_LEN; i++) {
            out[i * 2]     = hex[(digest[i] >> 4) & 0xf];
            out[i * 2 + 1] = hex[digest[i] & 0xf];
        }
        out[NGX_SENTINEL_JA4H_HEX_LEN] = '\0';
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: ja4h=%s canonical=%s", out, canon);
    return;

overflow:
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "sentinel: JA4H canonical string overflow, using zero hash");
    /* out already pre-filled with zeros above */
    return;
}
