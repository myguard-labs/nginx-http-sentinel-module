/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_allowlist.c — static CIDR allowlist signal for
 *                        ngx_http_sentinel_module.
 *
 * Operator configures one or more trusted IP/CIDR ranges via
 * `sentinel_allowlist <ip|cidr> [ip|cidr ...]`. A request whose client address
 * falls inside any configured range sets inputs->allowlisted = 1, which the
 * scoring stage treats as a full short-circuit to score 0 — EXCEPT when a
 * CrowdSec ban is present (see sentinel_score.c: an explicit operator ban must
 * never be wiped by a network-level allowlist; same auth-bypass reasoning that
 * gates known_good_ua).
 *
 * Intended for operator-verified ranges only — e.g. published search-engine
 * CIDR blocks, internal monitoring, or office egress. Forward-confirmed reverse
 * DNS (FCrDNS) verification of self-declaring crawlers is a separate, async
 * follow-up; this signal is the pure-in-memory, request-path-safe half.
 *
 * Pure-memory match (ngx_cidr_match), no regex, no malloc in the request path,
 * no I/O, no network. Bounded by the configured CIDR array count.
 *
 * Fail-open: NULL r / NULL lcf / empty allow_cidrs / missing sockaddr →
 * allowlisted = 0.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
sentinel_allowlist_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_int_t  rc;

    inputs->allowlisted = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    if (lcf->allow_cidrs.nelts == 0) {
        return;
    }

    if (r->connection == NULL || r->connection->sockaddr == NULL) {
        return;
    }

    /* ngx_cidr_match returns NGX_OK on the first matching CIDR in the array,
     * NGX_DECLINED otherwise. Pure in-memory address compare, no I/O. */
    rc = ngx_cidr_match(r->connection->sockaddr, &lcf->allow_cidrs);
    if (rc == NGX_OK) {
        inputs->allowlisted = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: allowlist match");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: allowlist no match");
}
