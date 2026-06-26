/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_c2ip.c — C2 / malware-infrastructure IP reputation signal for
 *                   ngx_http_sentinel_module.
 *
 * The operator loads a static deny list of known-malicious IPs / CIDRs via
 *
 *     sentinel_c2ip_deny 1.2.3.4 5.6.7.0/24 2001:db8::/32 ...;
 *     include /etc/nginx/sentinel-c2ip-deny.conf;   # generated daily by
 *                                                   # tools/feodo-c2ip-fetch.sh
 *     sentinel_weight_c2ip 80;
 *
 * The feed is the abuse.ch Feodo Tracker C2 IP blocklist — IPs of confirmed
 * botnet command-and-control servers. An inbound client whose address is known
 * C2 infrastructure is high-confidence malicious, hence the default weight 80
 * (block band on first hit).
 *
 * Unlike a CrowdSec ban (dynamic, TTL'd, per-decision shm), this list is
 * fairly static and large, so it is compiled into radix trees at config time
 * (sentinel_conf_c2ip_deny) and looked up by longest prefix per request. No
 * network, no DB link, no malloc / regex in the request path — one radix
 * lookup bounded by address-bit depth.
 *
 * Fail-open: NULL r / NULL lcf / no tree / non-IP connection (unix socket) /
 * unknown address family → c2ip_flagged = 0.
 */

#include "sentinel.h"

void
sentinel_c2ip_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    uintptr_t             v6;
#endif
    uint32_t              key;
    uintptr_t             val;

    inputs->c2ip_flagged = 0;

    if (r == NULL || lcf == NULL || r->connection == NULL) {
        return;
    }

    if (r->connection->sockaddr == NULL) {
        return;
    }

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (lcf->c2ip_tree == NULL) {
            return;
        }
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        key = ntohl(sin->sin_addr.s_addr);
        val = ngx_radix32tree_find(lcf->c2ip_tree, key);
        if (val != NGX_RADIX_NO_VALUE) {
            inputs->c2ip_flagged = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: c2ip match on flagged client IP");
        }
        return;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        if (lcf->c2ip_tree6 == NULL) {
            return;
        }
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        v6 = ngx_radix128tree_find(lcf->c2ip_tree6, sin6->sin6_addr.s6_addr);
        if (v6 != NGX_RADIX_NO_VALUE) {
            inputs->c2ip_flagged = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "sentinel: c2ip match on flagged client IPv6");
        }
        return;
#endif

    default:
        /* non-IP (unix socket) — fail-open */
        return;
    }
}
