/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_ja4sig.c — JA4 (TLS) fingerprint deny-list signal for
 *                     ngx_http_sentinel_module.
 *
 * This is JA4 *TLS* — distinct from the module's own in-HTTP JA4H
 * (sentinel_ja4h.c). The module does NOT link openssl or parse the
 * ClientHello: the TLS JA4 fingerprint is produced by the separately-packaged
 * ngx_http_ssl_fingerprint_module. The operator maps its variable into
 * sentinel via
 *
 *     ssl_fingerprint on;
 *     sentinel_ja4 $ssl_fingerprint_ja4;
 *     sentinel_ja4_deny t13d1516h2_8daaf6152771_b186095e22b6 ... ;
 *
 * At request time sentinel_ja4_signal() evaluates the operator-supplied
 * complex value and flags a case-insensitive match against the configured
 * deny list (matches a raw JA4 string or a JA4 hash equally — whichever the
 * operator listed and the source variable emits). Pure read — no regex, no
 * malloc in the request path, no I/O, no network. Bounded by ja4_list count.
 *
 * Fail-open: NULL r / NULL lcf / no ja4_source / empty ja4_list / empty
 * value → ja4_flagged = 0.
 */

#include "sentinel.h"

void
sentinel_ja4_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t   val;
    ngx_str_t  *deny;
    ngx_uint_t  i;

    inputs->ja4_flagged = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->ja4_source == NULL || lcf->ja4_list.nelts == 0) {
        return;
    }

    if (ngx_http_complex_value(r, lcf->ja4_source, &val) != NGX_OK) {
        /* fail-open: cannot resolve the source variable */
        return;
    }

    if (val.len == 0) {
        /* ssl-fingerprint leaves the var empty for non-TLS / no ClientHello */
        return;
    }

    deny = lcf->ja4_list.elts;

    for (i = 0; i < lcf->ja4_list.nelts; i++) {
        if (deny[i].len == val.len
            && ngx_strncasecmp(deny[i].data, val.data, val.len) == 0)
        {
            inputs->ja4_flagged = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: ja4 match on denied fp \"%V\"", &val);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: ja4 \"%V\" not denied", &val);
}
