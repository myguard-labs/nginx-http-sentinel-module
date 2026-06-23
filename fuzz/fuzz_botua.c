/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * fuzz_botua.c -- libFuzzer target for the bot-UA substring scanner.
 *
 * Fuzz surface: ua_contains() (static helper in sentinel_botua.c) via the
 * public sentinel_botua_signal() entry point with a synthetic request that
 * exposes arbitrary attacker-controlled UA bytes.
 *
 * What is fuzzed:
 *   The linear substring scan (ua_contains) over every entry in
 *   good_ua_substrings[] and bad_ua_substrings[].  The fuzzer feeds
 *   arbitrary bytes as the User-Agent value.
 *
 * Standalone compilation: stubs below provide the minimal nginx surface
 * needed so we never need ngx_config.h or ngx_http.h.
 *
 * Build: see fuzz/build.sh
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Minimal nginx type stubs.
 * ---------------------------------------------------------------------- */

typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef int            ngx_flag_t;

#define NGX_OK        0
#define NGX_ERROR    -1

#define ngx_inline inline
#define ngx_string(str)  { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string  { 0, NULL }

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* Logging: discard. */
#define ngx_log_error(level, log, err, fmt, ...)  ((void)0)
#define ngx_log_debug1(level, log, err, fmt, ...) ((void)0)
typedef void ngx_log_t;

#define ngx_strncmp(s1, s2, n)  strncmp((char *)(s1), (char *)(s2), (n))

/* -------------------------------------------------------------------------
 * Sentinel type stubs — only what sentinel_botua.c touches.
 * ---------------------------------------------------------------------- */

#define NGX_SENTINEL_CS_NONE 0

typedef struct {
    u_char      ja4h[25];
    ngx_uint_t  errrate_count;
    ngx_flag_t  errrate_blocked;
    ngx_flag_t  scanner_path;
    ngx_flag_t  bot_ua;
    ngx_flag_t  known_good_ua;
    ngx_flag_t  crowdsec_hit;
    u_char      crowdsec_action;
} ngx_sentinel_inputs_t;

/* Minimal table_elt stub for the user-agent header. */
typedef struct {
    ngx_uint_t  hash;
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_table_elt_t;

typedef struct {
    ngx_table_elt_t  *user_agent;
} ngx_http_headers_in_t;

typedef struct { void *log; } ngx_connection_t;

typedef struct {
    ngx_http_headers_in_t  headers_in;
    ngx_connection_t      *connection;
} ngx_http_request_t;

/* -------------------------------------------------------------------------
 * Include implementation directly.
 * ---------------------------------------------------------------------- */

#define SENTINEL_H
#include "../src/sentinel_botua.c"

/* -------------------------------------------------------------------------
 * libFuzzer entry point.
 * ---------------------------------------------------------------------- */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_http_request_t    r;
    ngx_connection_t      conn;
    ngx_table_elt_t       ua_hdr;
    ngx_sentinel_inputs_t inputs;

    memset(&r,      0, sizeof(r));
    memset(&conn,   0, sizeof(conn));
    memset(&ua_hdr, 0, sizeof(ua_hdr));
    memset(&inputs, 0, sizeof(inputs));

    r.connection = &conn;

    if (size == 0) {
        /* Missing UA: fuzz the NULL-UA branch. */
        r.headers_in.user_agent = NULL;
    } else {
        ua_hdr.value.data        = (u_char *) data;
        ua_hdr.value.len         = size;
        r.headers_in.user_agent  = &ua_hdr;
    }

    sentinel_botua_signal(&r, &inputs);

    /* Suppress result — we only care that no crash/OOB occurs. */
    return 0;
}
