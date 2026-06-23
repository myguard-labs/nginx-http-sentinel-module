/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_velocity.c — per-identity request-rate signal for
 *                        ngx_http_sentinel_module.
 *
 * Reuses the errrate sliding-window shm ring (sentinel_shm_errrate_lookup /
 * sentinel_shm_errrate_record) with a SEPARATE velocity zone that counts ALL
 * requests (not just errors >= 400). The record call is in ngx_sentinel_log_handler
 * so every completed request increments the counter. This file handles only
 * the READ path (preaccess lookup → inputs->velocity_exceeded).
 *
 * Identity = SHA-256($addr_text) — same derivation as errrate_signal.
 * No malloc in the hot path: digest lives on the stack.
 * Fail-open everywhere (WARN + return on any error).
 */

#include "sentinel.h"

void
sentinel_velocity_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_sentinel_zone_t  *zone;
    u_char                digest[SHA256_DIGEST_LENGTH];
    ngx_str_t             key;
    time_t                now;
    ngx_uint_t            count;
    time_t                blocked_until;
    ngx_int_t             rc;

    inputs->velocity_exceeded = 0;

    if (r == NULL || lcf == NULL) {
        return;
    }

    zone = lcf->vel_zone;
    if (zone == NULL) {
        return;  /* no sentinel_velocity_zone configured — fail-open */
    }

    if (r->connection->addr_text.len == 0) {
        return;  /* no client address — fail-open */
    }

    /* Build identity: SHA-256($addr_text) — no pool allocation in hot path. */
    SHA256(r->connection->addr_text.data, r->connection->addr_text.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

    now = ngx_time();

    rc = sentinel_shm_errrate_lookup(zone, &key, now, &count, &blocked_until);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "sentinel: velocity zone \"%V\" lookup error (fail-open)",
                      &zone->name);
        return;
    }

    inputs->velocity_exceeded = (rc == NGX_BUSY) ? 1 : 0;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: velocity count=%ui exceeded=%i",
                   count, inputs->velocity_exceeded);
}
