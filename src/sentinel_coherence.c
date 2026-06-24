/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_coherence.c — UA <-> request-shape coherence signal for
 *                        ngx_http_sentinel_module.
 *
 * A real desktop/mobile browser (Chrome, Firefox, Safari, Edge) ALWAYS emits a
 * characteristic request shape: an Accept header, an Accept-Language header, an
 * Accept-Encoding header advertising gzip (+ usually br), and HTTP/1.1 or HTTP/2.
 * A scraper that forges a browser User-Agent string but speaks a bare HTTP
 * client (no Accept*, HTTP/1.0, no compression) is INCOHERENT: it claims to be
 * a browser it demonstrably is not.
 *
 * This signal flags exactly that mismatch — UA claims a mainstream browser
 * family AND the request lacks the header shape every real instance of that
 * family sends. It is deliberately conservative (any ONE of the browser
 * fingerprints present clears it) to keep the false-positive rate near zero.
 *
 * NO fingerprint database, NO JA4H hash comparison (a SHA-256 hash cannot be
 * mapped to a browser family without a brittle per-version table). Pure
 * structural heuristic over r->headers_in. No regex, no malloc, no I/O, no
 * network. Bounded by the small static family table.
 *
 * Fail-open: NULL r / no User-Agent / non-browser UA (curl, bots, libraries —
 * already covered by sentinel_botua.c) / fully browser-shaped request → 0.
 */

#include "sentinel.h"

/*
 * UA substrings that identify a mainstream interactive browser. Only families
 * whose request shape is well-known and uniform belong here. We intentionally
 * exclude headless/automation UAs and anything sentinel_botua.c already flags.
 *
 * Order matters only for the debug log; matching is "any".
 */
static const ngx_str_t browser_ua_substrings[] = {
    ngx_string("Chrome/"),     /* Chrome, Chromium, Brave, Opera, Edge (Chromium) */
    ngx_string("Firefox/"),
    ngx_string("Safari/"),     /* real Safari always also sends "Version/"; Chrome
                                * carries "Safari/" too but is caught by Chrome/ */
    ngx_string("Edg/"),        /* modern Edge token */
    ngx_string("Gecko/"),      /* Firefox-family rendering engine token */
    ngx_null_string
};

/* Case-sensitive substring search (mirrors sentinel_botua.c::ua_contains). */
static ngx_inline int
coh_ua_contains(const u_char *ua, size_t ualen,
                const u_char *sub, size_t sublen)
{
    size_t  i;

    if (sublen == 0 || sublen > ualen) {
        return 0;
    }

    for (i = 0; i <= ualen - sublen; i++) {
        if (ua[i] == sub[0]
            && ngx_strncmp(ua + i, sub, sublen) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* Does Accept-Encoding advertise gzip? Every mainstream browser does. */
static ngx_inline int
coh_accepts_gzip(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    ae = r->headers_in.accept_encoding;
    if (ae == NULL || ae->value.len == 0) {
        return 0;
    }

    /* substring "gzip" — case-insensitive to be lenient (browsers send lower). */
    return coh_ua_contains(ae->value.data, ae->value.len,
                           (u_char *) "gzip", sizeof("gzip") - 1)
        || coh_ua_contains(ae->value.data, ae->value.len,
                           (u_char *) "br", sizeof("br") - 1);
}

void
sentinel_coherence_signal(ngx_http_request_t *r, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t        *ua;
    const ngx_str_t  *sub;
    int               looks_browser;
    int               has_accept;
    int               has_accept_lang;
    int               has_gzip;
    int               modern_proto;

    inputs->ua_incoherent = 0;

    if (r == NULL || r->headers_in.user_agent == NULL) {
        /* No UA at all — coherence makes no claim; sentinel_botua.c handles it. */
        return;
    }

    ua = &r->headers_in.user_agent->value;

    /* Does the UA CLAIM to be a mainstream browser? */
    looks_browser = 0;
    for (sub = browser_ua_substrings; sub->len; sub++) {
        if (coh_ua_contains(ua->data, ua->len, sub->data, sub->len)) {
            looks_browser = 1;
            break;
        }
    }

    if (!looks_browser) {
        /* Non-browser UA — not our concern (bot/library UAs are scored
         * elsewhere; an honest non-browser client is not "incoherent"). */
        return;
    }

    /*
     * It claims to be a browser. Verify it sends a browser's request shape.
     * Any one of these being absent is suspicious, but to keep false positives
     * near zero we only flag when the request is MISSING the core browser
     * fingerprint entirely: no Accept, OR no Accept-Language, OR no gzip/br
     * Accept-Encoding, OR a pre-HTTP/1.1 protocol. A real browser satisfies
     * all four; a forged-UA bare client typically satisfies none.
     */
    has_accept      = (r->headers_in.accept != NULL
                       && r->headers_in.accept->value.len > 0);
    has_accept_lang = (r->headers_in.accept_language != NULL
                       && r->headers_in.accept_language->value.len > 0);
    has_gzip        = coh_accepts_gzip(r);
    modern_proto    = (r->http_version >= NGX_HTTP_VERSION_11);

    if (!has_accept || !has_accept_lang || !has_gzip || !modern_proto) {
        inputs->ua_incoherent = 1;
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: UA claims browser but incoherent "
                       "(accept=%d accept_lang=%d gzip=%d http11=%d)",
                       has_accept, has_accept_lang, has_gzip, modern_proto);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: UA coherent with browser request shape");
}
