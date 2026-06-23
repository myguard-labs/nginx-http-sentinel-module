/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_errrate.c — error-burst sliding-window counter + scanner-path
 * signal for ngx_http_sentinel_module.
 *
 * Absorbed from ngx_http_error_abuse_module (record / init_zone / rbtree_insert
 * patterns). STRIPPED: all hiredis/Redis, async, TLS, file-snapshot,
 * thread-pool. KEPT: in-process shmem sliding counter + SHA-256 identity.
 *
 * Identity = SHA-256($binary_remote_addr) — bounded, same as error-abuse SEC-3.
 *
 * NOTE: Phase 1 does NOT hook the header filter to record error responses
 * (that requires an output filter chain, deferred to Phase 1b).  The errrate
 * signal therefore reflects only previously-recorded burst state from the
 * shared zone (read-only preaccess lookup).  Recording will be wired in
 * Phase 1b when the header filter is added.
 *
 * Scanner-path prefix match (no regex):
 *   .env  .git  wp-login  wp-admin  .aws  phpinfo
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Scanner-path prefix table (plain fixed-string, no regex)
 * ---------------------------------------------------------------------- */

static const ngx_str_t scanner_prefixes[] = {
    ngx_string("/.env"),
    ngx_string("/.git"),
    ngx_string("/wp-login"),
    ngx_string("/wp-admin"),
    ngx_string("/.aws"),
    ngx_string("/phpinfo"),
    ngx_null_string
};

static ngx_flag_t
sentinel_errrate_is_scanner_path(ngx_http_request_t *r)
{
    const ngx_str_t  *pfx;
    ngx_str_t        *uri;

    uri = &r->uri;

    for (pfx = scanner_prefixes; pfx->len; pfx++) {
        if (uri->len >= pfx->len
            && ngx_strncasecmp(uri->data, pfx->data, pfx->len) == 0)
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
sentinel_errrate_signal(ngx_http_request_t *r,
    ngx_sentinel_loc_conf_t *lcf, ngx_sentinel_inputs_t *inputs)
{
    ngx_sentinel_zone_t  *zone;
    u_char                digest[SHA256_DIGEST_LENGTH];
    ngx_str_t             key;
    ngx_str_t             addr;
    time_t                now;
    ngx_uint_t            count;
    time_t                blocked_until;
    ngx_int_t             rc;

    inputs->errrate_count   = 0;
    inputs->errrate_blocked = 0;

    /* Scanner-path check is independent of the shmem zone. */
    inputs->scanner_path = sentinel_errrate_is_scanner_path(r);

    zone = lcf->zone;
    if (zone == NULL) {
        return;  /* no sentinel_zone configured — fail-open */
    }

    /* Build identity: SHA-256($binary_remote_addr). */
    addr.data = r->connection->addr_text.data;
    addr.len  = r->connection->addr_text.len;

    if (addr.len == 0) {
        return;  /* no client address — fail-open */
    }

    /*
     * digest is on the stack: no pool allocation in the hot path (DESIGN rule).
     * key.data points into the stack-allocated digest buffer.
     */
    SHA256(addr.data, addr.len, digest);
    key.data = digest;
    key.len  = NGX_SENTINEL_DIGEST_LEN;

    now = ngx_time();

    rc = sentinel_shm_errrate_lookup(zone, &key, now, &count, &blocked_until);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "sentinel: errrate zone \"%V\" lookup error (fail-open)",
                      &zone->name);
        return;
    }

    inputs->errrate_count   = count;
    inputs->errrate_blocked = (rc == NGX_BUSY) ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: errrate count=%ui blocked=%i scanner=%i",
                   inputs->errrate_count,
                   inputs->errrate_blocked,
                   inputs->scanner_path);
}
