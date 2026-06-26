/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_ja3sig.c — JA3 (TLS) fingerprint deny-list signal for
 *                     ngx_http_sentinel_module.
 *
 * JA3 is the older MD5-based TLS ClientHello fingerprint. Its primary value
 * here is the publicly-maintained abuse.ch SSLBL JA3 blacklist
 * (https://sslbl.abuse.ch/blacklist/) — a curated set of JA3 MD5 hashes of
 * known malware / botnet C2 TLS clients, distinct from the scraper/bot
 * population that JA4 catches.
 *
 * The module does NOT link openssl or parse the ClientHello: the JA3
 * fingerprint is produced by the separately-packaged
 * ngx_http_ssl_fingerprint_module. The operator maps its variable into
 * sentinel via
 *
 *     ssl_fingerprint on;
 *     sentinel_ja3 $ssl_fingerprint_ja3_hash;
 *     sentinel_ja3_deny e7d705a3286e19ea42f587b344ee6865 ... ;   # SSLBL feed
 *
 * At request time sentinel_ja3_signal() evaluates the operator-supplied
 * complex value and flags a case-insensitive match against the configured
 * deny list (matches a raw JA3 string or a JA3 MD5 hash equally — whichever
 * the operator listed and the source variable emits). Pure read — no regex,
 * no malloc in the request path, no I/O, no network. Bounded by ja3_list
 * count.
 *
 * Fail-open: NULL r / NULL lcf / no ja3_source / empty ja3_list / empty
 * value → ja3_flagged = 0.
 */

#include "sentinel.h"

void
sentinel_ja3_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t   val;
    ngx_str_t  *deny;
    ngx_uint_t  i;

    inputs->ja3_flagged = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->ja3_source == NULL || lcf->ja3_list.nelts == 0) {
        return;
    }

    if (ngx_http_complex_value(r, lcf->ja3_source, &val) != NGX_OK) {
        /* fail-open: cannot resolve the source variable */
        return;
    }

    if (val.len == 0) {
        /* ssl-fingerprint leaves the var empty for non-TLS / no ClientHello */
        return;
    }

    deny = lcf->ja3_list.elts;

    for (i = 0; i < lcf->ja3_list.nelts; i++) {
        if (deny[i].len == val.len
            && ngx_strncasecmp(deny[i].data, val.data, val.len) == 0)
        {
            inputs->ja3_flagged = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: ja3 match on denied fp \"%V\"", &val);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: ja3 \"%V\" not denied", &val);
}
