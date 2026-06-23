/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_honeypot.c — decoy-URL (honeypot) detection signal for
 *                       ngx_http_sentinel_module.
 *
 * Operator configures one or more decoy path prefixes via `sentinel_honeypot`.
 * No legitimate client should ever request these paths; a match is treated as
 * a near-certain malicious probe and sets inputs->honeypot = 1.
 *
 * Pure-HTTP, no regex, no malloc in the request path, no I/O. Match is a
 * simple case-sensitive prefix comparison (URL paths are case-sensitive).
 * Bounded by the decoy_paths array count.
 *
 * Fail-open: NULL r / NULL lcf / empty decoy_paths array → honeypot = 0.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
sentinel_honeypot_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_str_t   *decoy;
    ngx_uint_t   i;

    inputs->honeypot = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->decoy_paths.nelts == 0) {
        return;
    }

    decoy = lcf->decoy_paths.elts;

    for (i = 0; i < lcf->decoy_paths.nelts; i++) {
        if (r->uri.len >= decoy[i].len
            && ngx_strncmp(r->uri.data, decoy[i].data, decoy[i].len) == 0)
        {
            inputs->honeypot = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: honeypot match on decoy \"%V\"",
                           &decoy[i]);
            return;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: honeypot no match");
}
