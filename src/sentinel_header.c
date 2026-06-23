/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_header.c — request-header anomaly heuristics for
 *                     ngx_http_sentinel_module.
 *
 * Pure-HTTP, no regex, no malloc, no I/O. Sets inputs->header_anomaly (1 =
 * suspicious request headers). Each check is independent; the first match
 * short-circuits to 1. Checks (all auditable, all from r->headers_in):
 *
 *   - HTTP/1.1 request with no Host header (HTTP/1.0 may legitimately omit it).
 *   - Content-Length AND Transfer-Encoding both present (request-smuggling
 *     vector — RFC 7230 forbids the pair).
 *   - Duplicate Host header (>1 "host" key in the parsed header list).
 *   - Neither Accept nor User-Agent present (a real browser sends both; a
 *     bare scanner request often sends neither).
 *
 * Fail-open: NULL request -> header_anomaly = 0.
 */

#include "sentinel.h"

/* -------------------------------------------------------------------------
 * Helper: count header-list entries whose key equals `name` (case-insensitive).
 * Bounded by the parsed header count. Returns the match count.
 * ---------------------------------------------------------------------- */

static ngx_uint_t
header_count(ngx_http_request_t *r, const char *name, size_t namelen)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i, n;

    part = &r->headers_in.headers.part;
    h    = part->elts;
    n    = 0;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].key.len == namelen
            && ngx_strncasecmp(h[i].key.data, (u_char *) name, namelen) == 0)
        {
            n++;
        }
    }

    return n;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void
sentinel_header_signal(ngx_http_request_t *r, ngx_sentinel_inputs_t *inputs)
{
    inputs->header_anomaly = 0;

    if (r == NULL) {
        return;
    }

    /* 1. HTTP/1.1 request without Host. (HTTP/1.0 omission is allowed.) */
    if (r->http_version == NGX_HTTP_VERSION_11
        && r->headers_in.host == NULL)
    {
        inputs->header_anomaly = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: header anomaly — HTTP/1.1 without Host");
        return;
    }

    /* 2. Content-Length AND Transfer-Encoding both present (smuggling). */
    if (r->headers_in.content_length != NULL
        && r->headers_in.transfer_encoding != NULL)
    {
        inputs->header_anomaly = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: header anomaly — CL+TE both present");
        return;
    }

    /* 3. Duplicate Host header. */
    if (header_count(r, "host", sizeof("host") - 1) > 1) {
        inputs->header_anomaly = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: header anomaly — duplicate Host");
        return;
    }

    /* 4. Neither Accept nor User-Agent present. */
    if (r->headers_in.user_agent == NULL
        && header_count(r, "accept", sizeof("accept") - 1) == 0)
    {
        inputs->header_anomaly = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sentinel: header anomaly — no Accept and no User-Agent");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sentinel: headers neutral");
}
