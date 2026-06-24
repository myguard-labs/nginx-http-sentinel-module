/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_pow.c — built-in proof-of-work challenge for CHALLENGE-band verdicts.
 *
 * When a request lands in the CHALLENGE band in enforce mode and PoW is enabled
 * (sentinel_pow on; sentinel_pow_secret <key>;), sentinel serves a small,
 * self-contained HTML+JS page that asks the client to find a nonce such that
 *
 *     SHA256(challenge || nonce)  has >= difficulty leading zero BITS.
 *
 * The challenge is STATELESS — no shm:
 *
 *     challenge = hex( HMAC-SHA256(secret, binary_remote_addr || time_bucket) )
 *
 * where time_bucket = ngx_time() / pow_ttl, so a challenge is valid for the
 * remainder of its bucket window. The client re-requests with the solved nonce
 * (header `X-Sentinel-Pow: <nonce>` or query `?__sentinel_pow=<nonce>`). The
 * module recomputes the same challenge, checks the difficulty, and on success
 * issues a signed cookie:
 *
 *     __sentinel_pow = <expiry_hex> "." hex( HMAC-SHA256(secret, IP || expiry) )
 *
 * Subsequent requests carrying a valid, unexpired cookie bypass the challenge.
 *
 * Security posture:
 *   - Cookie/solution HMAC compares are CONSTANT-TIME (ngx_memn2cmp).
 *   - A request with a PRESENT but INVALID cookie FAILS CLOSED (re-challenge),
 *     so a forged/garbage cookie can never bypass.
 *   - FAIL-OPEN only when the signal is disabled or no secret is configured.
 *   - No malloc in the verify path beyond a couple of small request-pool bufs;
 *     no network, no regex, no global-state mutation.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/hmac.h>

#include "sentinel.h"


#define NGX_SENTINEL_POW_COOKIE       "__sentinel_pow"
#define NGX_SENTINEL_POW_HEADER       "X-Sentinel-Pow"
#define NGX_SENTINEL_POW_ARG          "__sentinel_pow"
/* Hex-encoded HMAC-SHA256 = 64 chars. */
#define NGX_SENTINEL_POW_HEXLEN       (NGX_SENTINEL_DIGEST_LEN * 2)
/* Bound the client-supplied nonce so a hostile value can't blow the hash buf. */
#define NGX_SENTINEL_POW_NONCE_MAX    64


static void
sentinel_pow_hex(u_char *dst, const u_char *src, size_t len)
{
    static const u_char  hex[] = "0123456789abcdef";
    size_t               i;

    for (i = 0; i < len; i++) {
        dst[2 * i]     = hex[src[i] >> 4];
        dst[2 * i + 1] = hex[src[i] & 0x0f];
    }
}


/*
 * Compute the per-IP, per-bucket challenge hex string into `out` (must hold
 * NGX_SENTINEL_POW_HEXLEN bytes). Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
sentinel_pow_challenge(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf,
    u_char *out)
{
    u_char         mac[NGX_SENTINEL_DIGEST_LEN];
    u_char         msg[16 + sizeof("18446744073709551615") - 1];
    u_char        *p;
    unsigned int   maclen = 0;
    struct sockaddr_in  *sin;
    ngx_uint_t     bucket;
    size_t         iplen;
    void          *ipdat;

    /* Identity = binary_remote_addr (IPv4 4 bytes / IPv6 16 bytes). */
    switch (r->connection->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        ipdat = sin6->sin6_addr.s6_addr;
        iplen = 16;
        break;
    }
#endif
    case AF_INET:
        sin   = (struct sockaddr_in *) r->connection->sockaddr;
        ipdat = &sin->sin_addr.s_addr;
        iplen = 4;
        break;
    default:
        /* Unix socket / unknown — fall back to text addr. */
        ipdat = r->connection->addr_text.data;
        iplen = r->connection->addr_text.len;
        break;
    }

    if (iplen == 0 || iplen > 16) {
        return NGX_ERROR;
    }

    bucket = (ngx_uint_t) (ngx_time() / (lcf->pow_ttl > 0 ? lcf->pow_ttl : 1));

    p = ngx_cpymem(msg, ipdat, iplen);
    p = ngx_sprintf(p, "%ui", bucket);

    if (HMAC(EVP_sha256(), lcf->pow_secret.data, (int) lcf->pow_secret.len,
             msg, (size_t) (p - msg), mac, &maclen) == NULL
        || maclen != NGX_SENTINEL_DIGEST_LEN)
    {
        return NGX_ERROR;
    }

    sentinel_pow_hex(out, mac, NGX_SENTINEL_DIGEST_LEN);
    return NGX_OK;
}


/* Count leading zero BITS of an SHA-256 digest; return >= difficulty? */
static ngx_int_t
sentinel_pow_meets_difficulty(const u_char *digest, ngx_int_t difficulty)
{
    ngx_int_t  bits = 0;
    size_t     i;

    for (i = 0; i < NGX_SENTINEL_DIGEST_LEN; i++) {
        u_char  b = digest[i];

        if (b == 0) {
            bits += 8;
            continue;
        }
        while ((b & 0x80) == 0) {
            bits++;
            b = (u_char) (b << 1);
        }
        break;
    }

    return bits >= difficulty;
}


/*
 * Compute the signed-cookie HMAC for (IP || expiry) into `out` (hex,
 * NGX_SENTINEL_POW_HEXLEN bytes). Returns NGX_OK / NGX_ERROR.
 */
static ngx_int_t
sentinel_pow_cookie_mac(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf,
    time_t expiry, u_char *out)
{
    u_char         mac[NGX_SENTINEL_DIGEST_LEN];
    u_char         msg[16 + sizeof("-9223372036854775808") - 1];
    u_char        *p;
    unsigned int   maclen = 0;
    struct sockaddr_in  *sin;
    size_t         iplen;
    void          *ipdat;

    switch (r->connection->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        ipdat = sin6->sin6_addr.s6_addr;
        iplen = 16;
        break;
    }
#endif
    case AF_INET:
        sin   = (struct sockaddr_in *) r->connection->sockaddr;
        ipdat = &sin->sin_addr.s_addr;
        iplen = 4;
        break;
    default:
        ipdat = r->connection->addr_text.data;
        iplen = r->connection->addr_text.len;
        break;
    }

    if (iplen == 0 || iplen > 16) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(msg, ipdat, iplen);
    p = ngx_sprintf(p, "%T", expiry);

    if (HMAC(EVP_sha256(), lcf->pow_secret.data, (int) lcf->pow_secret.len,
             msg, (size_t) (p - msg), mac, &maclen) == NULL
        || maclen != NGX_SENTINEL_DIGEST_LEN)
    {
        return NGX_ERROR;
    }

    sentinel_pow_hex(out, mac, NGX_SENTINEL_DIGEST_LEN);
    return NGX_OK;
}


/*
 * Inspect the request cookie. Returns:
 *   NGX_OK     — a valid, unexpired cookie is present (bypass the challenge).
 *   NGX_DECLINED — no cookie present (proceed to solution check / challenge).
 *   NGX_ERROR  — cookie present but INVALID/expired (caller MUST fail closed).
 */
static ngx_int_t
sentinel_pow_check_cookie(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf)
{
    ngx_str_t  cookie = ngx_string(NGX_SENTINEL_POW_COOKIE);
    ngx_str_t  val;
    u_char    *dot;
    u_char     want[NGX_SENTINEL_POW_HEXLEN];
    time_t     expiry;

    if (ngx_http_parse_cookie_lines(r, r->headers_in.cookie, &cookie, &val)
        == NULL || val.len == 0)
    {
        return NGX_DECLINED;
    }

    /* Expected form: <expiry-digits>.<64 hex>. */
    if (val.len <= NGX_SENTINEL_POW_HEXLEN + 1) {
        return NGX_ERROR;
    }

    dot = ngx_strlchr(val.data, val.data + val.len, '.');
    if (dot == NULL
        || (size_t) (val.data + val.len - dot - 1) != NGX_SENTINEL_POW_HEXLEN)
    {
        return NGX_ERROR;
    }

    expiry = ngx_atotm(val.data, dot - val.data);
    if (expiry == NGX_ERROR || expiry <= ngx_time()) {
        return NGX_ERROR;
    }

    if (sentinel_pow_cookie_mac(r, lcf, expiry, want) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Constant-time compare of the supplied vs recomputed MAC. */
    if (ngx_memn2cmp(dot + 1, want, NGX_SENTINEL_POW_HEXLEN,
                     NGX_SENTINEL_POW_HEXLEN) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Extract the client-supplied nonce (header first, then query arg). */
static ngx_int_t
sentinel_pow_get_nonce(ngx_http_request_t *r, ngx_str_t *nonce)
{
    ngx_list_part_t   *part = &r->headers_in.headers.part;
    ngx_table_elt_t   *h    = part->elts;
    ngx_uint_t         i;
    static ngx_str_t   hname = ngx_string(NGX_SENTINEL_POW_HEADER);

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h    = part->elts;
            i    = 0;
        }
        if (h[i].key.len == hname.len
            && ngx_strncasecmp(h[i].key.data, hname.data, hname.len) == 0)
        {
            if (h[i].value.len > 0 && h[i].value.len <= NGX_SENTINEL_POW_NONCE_MAX) {
                *nonce = h[i].value;
                return NGX_OK;
            }
            return NGX_DECLINED;
        }
    }

    if (ngx_http_arg(r, (u_char *) NGX_SENTINEL_POW_ARG,
                     sizeof(NGX_SENTINEL_POW_ARG) - 1, nonce) == NGX_OK)
    {
        if (nonce->len > 0 && nonce->len <= NGX_SENTINEL_POW_NONCE_MAX) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/*
 * Set the signed bypass cookie on the response (expiry = now + pow_ttl).
 * Best-effort: on alloc/HMAC failure the request still passes (the work was
 * already done) — it just won't be cached.
 */
static void
sentinel_pow_set_cookie(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf)
{
    ngx_table_elt_t  *set;
    u_char            machex[NGX_SENTINEL_POW_HEXLEN];
    u_char           *p;
    time_t            expiry;
    size_t            len;

    expiry = ngx_time() + (lcf->pow_ttl > 0 ? lcf->pow_ttl : 1);

    if (sentinel_pow_cookie_mac(r, lcf, expiry, machex) != NGX_OK) {
        return;
    }

    set = ngx_list_push(&r->headers_out.headers);
    if (set == NULL) {
        return;
    }

    set->hash = 1;
    ngx_str_set(&set->key, "Set-Cookie");

    /* "__sentinel_pow=<expiry>.<64hex>; Path=/; Max-Age=<ttl>; HttpOnly" */
    len = sizeof(NGX_SENTINEL_POW_COOKIE "=") - 1
          + NGX_TIME_T_LEN + 1 + NGX_SENTINEL_POW_HEXLEN
          + sizeof("; Path=/; Max-Age=; HttpOnly") - 1 + NGX_TIME_T_LEN;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return;
    }

    set->value.data = p;
    p = ngx_cpymem(p, NGX_SENTINEL_POW_COOKIE "=",
                   sizeof(NGX_SENTINEL_POW_COOKIE "=") - 1);
    p = ngx_sprintf(p, "%T.", expiry);
    p = ngx_cpymem(p, machex, NGX_SENTINEL_POW_HEXLEN);
    p = ngx_sprintf(p, "; Path=/; Max-Age=%T; HttpOnly",
                    (time_t) (lcf->pow_ttl > 0 ? lcf->pow_ttl : 1));
    set->value.len = (size_t) (p - set->value.data);
}


/* Serve the self-contained PoW challenge page (HTTP 200). Returns NGX_DONE. */
static ngx_int_t
sentinel_pow_send_page(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf,
    u_char *challenge)
{
    static const char  tmpl_head[] =
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>Verifying your browser</title>"
        "<meta name=robots content=noindex></head>"
        "<body><h1>Checking your browser&hellip;</h1>"
        "<p>One moment — solving a small computational puzzle.</p>"
        "<noscript>JavaScript is required to continue.</noscript>"
        "<script>"
        "(function(){"
        "var c='";
    static const char  tmpl_mid1[] = "',d=";
    static const char  tmpl_mid2[] = ";"
        "async function sha(s){var b=new TextEncoder().encode(s);"
        "var h=await crypto.subtle.digest('SHA-256',b);"
        "return new Uint8Array(h);}"
        "function lz(a){var n=0;for(var i=0;i<a.length;i++){"
        "var v=a[i];if(v===0){n+=8;continue;}"
        "while((v&128)===0){n++;v=(v<<1)&255;}break;}return n;}"
        "(async function(){var n=0;"
        "for(;;){var h=await sha(c+n);if(lz(h)>=d)break;n++;}"
        "var u=new URL(location.href);"
        "u.searchParams.set('" NGX_SENTINEL_POW_ARG "',n);"
        "location.replace(u.toString());})();"
        "})();"
        "</script></body></html>";

    ngx_buf_t    *b;
    ngx_chain_t   out;
    size_t        len;
    u_char       *p;
    ngx_int_t     rc;

    len = sizeof(tmpl_head) - 1 + NGX_SENTINEL_POW_HEXLEN
          + sizeof(tmpl_mid1) - 1 + NGX_INT_T_LEN
          + sizeof(tmpl_mid2) - 1;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = b->pos;
    p = ngx_cpymem(p, tmpl_head, sizeof(tmpl_head) - 1);
    p = ngx_cpymem(p, challenge, NGX_SENTINEL_POW_HEXLEN);
    p = ngx_cpymem(p, tmpl_mid1, sizeof(tmpl_mid1) - 1);
    p = ngx_sprintf(p, "%i", lcf->pow_difficulty);
    p = ngx_cpymem(p, tmpl_mid2, sizeof(tmpl_mid2) - 1);
    b->last = p;
    b->last_buf = 1;
    b->last_in_chain = 1;

    r->headers_out.status            = NGX_HTTP_OK;
    r->headers_out.content_length_n  = (off_t) (b->last - b->pos);
    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_len  = r->headers_out.content_type.len;
    /* Never let an intermediary cache the challenge page. */
    r->headers_out.last_modified_time = -1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    out.buf  = b;
    out.next = NULL;
    rc = ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


/*
 * sentinel_pow_dispatch — entry point from the CHALLENGE verdict case.
 *
 * Returns:
 *   NGX_DECLINED — let the request proceed (PoW off / no secret / valid cookie
 *                  / valid solution just accepted).
 *   NGX_DONE     — a challenge page was served; request ownership transferred.
 *
 * Sets ctx->pow_state for the $sentinel_pow variable.
 */
ngx_int_t
sentinel_pow_dispatch(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf,
    ngx_sentinel_ctx_t *ctx)
{
    u_char     challenge[NGX_SENTINEL_POW_HEXLEN];
    ngx_str_t  nonce;
    ngx_int_t  rc;

    /* Fail-open: signal disabled or no secret configured. */
    if (!lcf->pow_enabled || lcf->pow_secret.len == 0) {
        ctx->pow_state = NGX_SENTINEL_POW_OFF;
        return NGX_DECLINED;
    }

    /* 1. Valid bypass cookie → pass. Present-but-invalid → fail CLOSED. */
    rc = sentinel_pow_check_cookie(r, lcf);
    if (rc == NGX_OK) {
        ctx->pow_state = NGX_SENTINEL_POW_VERIFIED;
        return NGX_DECLINED;
    }
    /* rc == NGX_ERROR (forged/expired cookie) falls through to re-challenge. */

    /* 2. Compute the expected challenge for this IP/bucket. */
    if (sentinel_pow_challenge(r, lcf, challenge) != NGX_OK) {
        /* Can't build a challenge → fail open rather than wedge the client. */
        ctx->pow_state = NGX_SENTINEL_POW_OFF;
        return NGX_DECLINED;
    }

    /* 3. A solution submitted? Verify SHA256(challenge||nonce) difficulty. */
    if (sentinel_pow_get_nonce(r, &nonce) == NGX_OK) {
        u_char  hbuf[NGX_SENTINEL_POW_HEXLEN + NGX_SENTINEL_POW_NONCE_MAX];
        u_char  digest[NGX_SENTINEL_DIGEST_LEN];
        u_char *p;

        p = ngx_cpymem(hbuf, challenge, NGX_SENTINEL_POW_HEXLEN);
        p = ngx_cpymem(p, nonce.data, nonce.len);
        SHA256(hbuf, (size_t) (p - hbuf), digest);

        if (sentinel_pow_meets_difficulty(digest, lcf->pow_difficulty)) {
            sentinel_pow_set_cookie(r, lcf);
            ctx->pow_state = NGX_SENTINEL_POW_VERIFIED;
            return NGX_DECLINED;
        }
        /* Bad solution → re-challenge. */
    }

    /* 4. No/invalid cookie + no/bad solution → serve the challenge page. */
    ctx->pow_state = NGX_SENTINEL_POW_CHALLENGE;
    return sentinel_pow_send_page(r, lcf, challenge);
}
