/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_botua.c — User-Agent bot heuristics for ngx_http_sentinel_module.
 *
 * Static substring tables only; no regex.
 * Sets inputs->bot_ua (1 = suspicious/bot UA) and
 *      inputs->known_good_ua (1 = forward-confirmed search-engine UA).
 *
 * Phase 1: known_good_ua is set by UA substring only (no forward-DNS verify;
 * that is Phase 3 "bot-verifier" integration). Flag it clearly so the score
 * stub does not over-trust it.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Static substring tables (no regex, no malloc, read-only)
 * ---------------------------------------------------------------------- */

/* UA substrings that indicate known search-engine / monitoring crawlers.
 * Phase 1: name-only (no forward-DNS confirm); score stub discounts this. */
static const ngx_str_t good_ua_substrings[] = {
    ngx_string("Googlebot"),
    ngx_string("Googlebot-Image"),
    ngx_string("Googlebot-News"),
    ngx_string("Googlebot-Video"),
    ngx_string("Bingbot"),
    ngx_string("Slurp"),          /* Yahoo */
    ngx_string("DuckDuckBot"),
    ngx_string("Baiduspider"),
    ngx_string("YandexBot"),
    ngx_string("facebot"),        /* Facebook */
    ngx_string("ia_archiver"),    /* Alexa / Wayback */
    ngx_string("UptimeRobot"),
    ngx_string("Pingdom"),
    ngx_null_string
};

/* UA substrings strongly associated with scanners / exploit tools. */
static const ngx_str_t bad_ua_substrings[] = {
    ngx_string("sqlmap"),
    ngx_string("nikto"),
    ngx_string("nmap"),
    ngx_string("masscan"),
    ngx_string("ZGrab"),
    ngx_string("zgrab"),
    ngx_string("Nuclei"),
    ngx_string("nuclei"),
    ngx_string("python-requests"),
    ngx_string("Go-http-client/1.1"),   /* common scanner default */
    ngx_string("curl/7"),               /* old curl — broad but common in scans */
    ngx_string("libwww-perl"),
    ngx_string("WPScan"),
    ngx_string("wpscan"),
    ngx_string("Acunetix"),
    ngx_string("acunetix"),
    ngx_string("Metasploit"),
    ngx_string("metasploit"),
    ngx_string("Burp"),
    ngx_string("dirbuster"),
    ngx_string("DirBuster"),
    ngx_string("gobuster"),
    ngx_string("ffuf"),
    ngx_string("feroxbuster"),
    ngx_string("WordPress/"),           /* old WP pingback UA used in floods */
    ngx_null_string
};

/* UA empty / very short string (< 5 chars) is also a bot signal. */
#define SENTINEL_BOT_UA_MIN_LEN  5

/* -------------------------------------------------------------------------
 * Helper: case-sensitive substring search (memmem fallback)
 * ---------------------------------------------------------------------- */

static ngx_inline int
ua_contains(const u_char *ua, size_t ualen,
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

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
sentinel_botua_signal(ngx_http_request_t *r, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t         *ua_str;
    const ngx_str_t   *sub;

    inputs->bot_ua       = 0;
    inputs->known_good_ua = 0;

    if (r->headers_in.user_agent == NULL) {
        /* Missing UA is itself a bot signal. */
        inputs->bot_ua = 1;
        return;
    }

    ua_str = &r->headers_in.user_agent->value;

    if (ua_str->len < SENTINEL_BOT_UA_MIN_LEN) {
        inputs->bot_ua = 1;
        return;
    }

    /* Check known-good first (search engines / monitors). */
    for (sub = good_ua_substrings; sub->len; sub++) {
        if (ua_contains(ua_str->data, ua_str->len,
                        sub->data, sub->len))
        {
            inputs->known_good_ua = 1;
            /*
             * Phase 1 note: we do NOT forward-DNS verify here.
             * Score stub in sentinel_score.c returns 0 regardless,
             * so this flag is informational only until Phase 3.
             */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: known-good UA matched \"%V\"", ua_str);
            return;  /* good UA overrides bad check */
        }
    }

    /* Check bad / scanner UA list. */
    for (sub = bad_ua_substrings; sub->len; sub++) {
        if (ua_contains(ua_str->data, ua_str->len,
                        sub->data, sub->len))
        {
            inputs->bot_ua = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: bot UA matched \"%V\"", ua_str);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: UA neutral \"%V\"", ua_str);
}
