/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_ja4tsig.c — JA4T (TCP/transport) fingerprint deny-list signal for
 *                      ngx_http_sentinel_module.
 *
 * JA4T is a *TCP/transport* fingerprint (SYN window size, TCP-options order,
 * MSS) — a DIFFERENT layer from JA4 TLS (sentinel_ja4sig.c, ClientHello) and
 * the in-HTTP JA4H (sentinel_ja4h.c). nginx core does NOT compute JA4T. The
 * fingerprint is produced upstream — typically an edge load balancer that
 * computes JA4T and passes it down in a PROXY-protocol v2 custom TLV. nginx
 * exposes that TLV out of the box (no patch) via the generic
 * $proxy_protocol_tlv_0xNN variable. The operator maps it into sentinel via
 *
 *     listen 443 ssl proxy_protocol;
 *     sentinel_ja4t $proxy_protocol_tlv_0xe0;
 *     sentinel_ja4t_deny t13d... ... ;
 *
 * At request time sentinel_ja4t_signal() evaluates the operator-supplied
 * complex value and flags a case-insensitive match against the configured
 * deny list. Pure read — no regex, no malloc in the request path, no I/O, no
 * network, no core patch. Bounded by ja4t_list count.
 *
 * Fail-open: NULL r / NULL lcf / no ja4t_source / empty ja4t_list / empty
 * value (no PROXY protocol / no TLV) → ja4t_flagged = 0.
 */

#include "sentinel.h"

void
sentinel_ja4t_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t   val;
    ngx_str_t  *deny;
    ngx_uint_t  i;

    inputs->ja4t_flagged = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->ja4t_source == NULL || lcf->ja4t_list.nelts == 0) {
        return;
    }

    if (ngx_http_complex_value(r, lcf->ja4t_source, &val) != NGX_OK) {
        /* fail-open: cannot resolve the source variable */
        return;
    }

    if (val.len == 0) {
        /* no PROXY protocol / no TLV present → fail open */
        return;
    }

    deny = lcf->ja4t_list.elts;

    for (i = 0; i < lcf->ja4t_list.nelts; i++) {
        if (deny[i].len == val.len
            && ngx_strncasecmp(deny[i].data, val.data, val.len) == 0)
        {
            inputs->ja4t_flagged = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: ja4t match on denied fp \"%V\"", &val);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: ja4t \"%V\" not denied", &val);
}
