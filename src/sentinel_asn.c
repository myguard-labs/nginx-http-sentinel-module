/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_asn.c — datacenter/abuse-ASN detection signal for
 *                  ngx_http_sentinel_module.
 *
 * The module does NOT link libmaxminddb or own any GeoIP database. ASN lookup
 * is delegated entirely to the separately-packaged ngx_http_geoip2_module:
 * the operator maps a geoip2 ASN variable into sentinel via
 *
 *     geoip2 /usr/share/GeoIP/GeoLite2-ASN.mmdb {
 *         $geoip2_asn autonomous_system_number;
 *     }
 *     sentinel_asn $geoip2_asn;
 *     sentinel_datacenter_asn 16509 14618 15169 14061 ...;
 *
 * At request time sentinel_asn_signal() evaluates the operator-supplied
 * complex value, parses it as an unsigned ASN, and flags a match against the
 * configured list. Pure read — no regex, no malloc in the request path, no I/O,
 * no network. Bounded by asn_list count.
 *
 * Fail-open: NULL r / NULL lcf / no asn_source / empty asn_list / empty or
 * non-numeric value → datacenter_asn = 0.
 */

#include "sentinel.h"

void
sentinel_asn_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t    val;
    ngx_uint_t  *asn;
    ngx_uint_t   i;
    ngx_int_t    parsed;

    inputs->datacenter_asn = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->asn_source == NULL || lcf->asn_list.nelts == 0) {
        return;
    }

    if (ngx_http_complex_value(r, lcf->asn_source, &val) != NGX_OK) {
        /* fail-open: cannot resolve the source variable */
        return;
    }

    if (val.len == 0) {
        /* geoip2 leaves the var empty when the IP is not in the DB */
        return;
    }

    parsed = ngx_atoi(val.data, val.len);
    if (parsed == NGX_ERROR || parsed <= 0) {
        /* non-numeric or zero — not a usable ASN, fail-open */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: asn source non-numeric \"%V\"", &val);
        return;
    }

    asn = lcf->asn_list.elts;

    for (i = 0; i < lcf->asn_list.nelts; i++) {
        if (asn[i] == (ngx_uint_t) parsed) {
            inputs->datacenter_asn = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: asn match on flagged AS%ui",
                           (ngx_uint_t) parsed);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: asn AS%ui not flagged", (ngx_uint_t) parsed);
}
