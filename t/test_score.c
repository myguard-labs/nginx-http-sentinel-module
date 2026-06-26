/*
 * t/test_score.c — standalone unit tests for sentinel_score_compute() and
 *                  sentinel_score_to_verdict().
 *
 * Build and run (from the repo root):
 *
 *   cc -std=c99 -I src -o .build/test_score t/test_score.c && .build/test_score
 *
 * This file does NOT link against nginx or OpenSSL.  It provides its own
 * minimal stubs for the nginx types used by sentinel.h / sentinel_score.c so
 * the pure-arithmetic score functions can be compiled and tested in isolation.
 *
 * The Test::Nginx harness (t/basic.t) is HTTP-based and cannot exercise pure C
 * functions directly, hence this separate driver.  ci-build.sh calls it via the
 * "unit" step after the module build.
 *
 * Copyright (c) 2026 Eilander — MIT
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Minimal nginx-type stubs — only what sentinel_score.c uses.
 * We define all types before pulling in sentinel_score.c, and we
 * short-circuit sentinel.h's nginx includes by pre-defining its guard.
 * ---------------------------------------------------------------------- */

typedef unsigned char  u_char;
typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef int            ngx_flag_t;

/* ngx_inline: nginx uses `static ngx_inline` at call sites, so the macro
 * itself must expand to just `inline` (the outer `static` is explicit). */
#define ngx_inline  inline

/* -------------------------------------------------------------------------
 * Sentinel constants and types (self-contained copy so we don't need
 * ngx_config.h / OpenSSL).  These must match sentinel.h exactly.
 * ---------------------------------------------------------------------- */

#define NGX_SENTINEL_JA4H_HEX_LEN     24
#define NGX_SENTINEL_SCORE_MAX         100000

#define NGX_SENTINEL_DEFAULT_W_ERRRATE 1
#define NGX_SENTINEL_DEFAULT_W_BLOCKED 100
#define NGX_SENTINEL_DEFAULT_W_SCANNER 50
#define NGX_SENTINEL_DEFAULT_W_BOT     30
#define NGX_SENTINEL_DEFAULT_W_HEADER  25
#define NGX_SENTINEL_DEFAULT_W_HONEYPOT 90
#define NGX_SENTINEL_DEFAULT_W_VELOCITY 30
#define NGX_SENTINEL_DEFAULT_W_ASN     35
#define NGX_SENTINEL_DEFAULT_W_COHERENCE 40
#define NGX_SENTINEL_DEFAULT_W_JA3     80
#define NGX_SENTINEL_DEFAULT_W_JA4     50
#define NGX_SENTINEL_DEFAULT_W_JA4T    45
#define NGX_SENTINEL_DEFAULT_W_CROWDSEC 100

#define NGX_SENTINEL_CS_NONE      0
#define NGX_SENTINEL_CS_BAN       1
#define NGX_SENTINEL_CS_CAPTCHA   2
#define NGX_SENTINEL_CS_THROTTLE  3

#define NGX_SENTINEL_DEFAULT_THRESH_CH 30
#define NGX_SENTINEL_DEFAULT_THRESH_TP 60
#define NGX_SENTINEL_DEFAULT_THRESH_BK 80

typedef enum {
    NGX_SENTINEL_VERDICT_ALLOW     = 0,
    NGX_SENTINEL_VERDICT_CHALLENGE = 1,
    NGX_SENTINEL_VERDICT_TARPIT    = 2,
    NGX_SENTINEL_VERDICT_BLOCK     = 3
} ngx_sentinel_verdict_e;

typedef struct {
    u_char      ja4h[NGX_SENTINEL_JA4H_HEX_LEN + 1];
    ngx_uint_t  errrate_count;
    ngx_flag_t  errrate_blocked;
    ngx_flag_t  scanner_path;
    ngx_flag_t  bot_ua;
    ngx_flag_t  known_good_ua;
    ngx_flag_t  fcrdns_verified;
    ngx_flag_t  fcrdns_spoofed;
    ngx_flag_t  header_anomaly;
    ngx_flag_t  honeypot;
    ngx_flag_t  velocity_exceeded;
    ngx_flag_t  datacenter_asn;
    ngx_flag_t  ua_incoherent;
    ngx_flag_t  ja3_flagged;
    ngx_flag_t  ja4_flagged;
    ngx_flag_t  ja4t_flagged;
    ngx_flag_t  allowlisted;
    ngx_flag_t  crowdsec_hit;
    u_char      crowdsec_action;
} ngx_sentinel_inputs_t;

typedef struct {
    ngx_int_t  challenge;
    ngx_int_t  tarpit;
    ngx_int_t  block;
} ngx_sentinel_threshold_t;

typedef struct {
    ngx_int_t  errrate;
    ngx_int_t  blocked;
    ngx_int_t  scanner;
    ngx_int_t  bot;
    ngx_int_t  header;
    ngx_int_t  honeypot;  /* added once if honeypot        */
    ngx_int_t  velocity;
    ngx_int_t  asn;       /* added once if datacenter_asn   */
    ngx_int_t  coherence; /* added once if ua_incoherent    */
    ngx_int_t  ja3;       /* added once if ja3_flagged       */
    ngx_int_t  ja4;       /* added once if ja4_flagged       */
    ngx_int_t  ja4t;      /* added once if ja4t_flagged      */
    ngx_int_t  crowdsec;
} ngx_sentinel_weights_t;

/* Minimal loc-conf stub: only weights field is used by sentinel_score.c. */
typedef struct {
    ngx_flag_t               enabled;
    ngx_flag_t               shadow;
    ngx_flag_t               fail_open;
    void                    *zone;
    ngx_sentinel_threshold_t threshold;
    ngx_sentinel_weights_t   weights;
} ngx_sentinel_loc_conf_t;

/* -------------------------------------------------------------------------
 * Pull in the implementation directly (avoids a separate link step).
 * Pre-define SENTINEL_H so the real sentinel.h (which needs ngx_config.h
 * and OpenSSL) is skipped — our stubs above provide everything the score
 * functions actually use.
 * ---------------------------------------------------------------------- */

#define SENTINEL_H  /* skip real sentinel.h */
#include "../src/sentinel_score.c"

/* -------------------------------------------------------------------------
 * Test harness
 * ---------------------------------------------------------------------- */

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT_EQ(label, got, expected)                                        \
    do {                                                                       \
        if ((got) == (expected)) {                                             \
            printf("PASS  %s\n", (label));                                     \
            g_pass++;                                                          \
        } else {                                                               \
            printf("FAIL  %s  (got=%ld, expected=%ld)\n",                     \
                   (label), (long)(got), (long)(expected));                    \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

/* Build a default loc_conf with canonical default weights + thresholds. */
static ngx_sentinel_loc_conf_t
make_lcf(ngx_int_t w_errrate, ngx_int_t w_blocked,
         ngx_int_t w_scanner, ngx_int_t w_bot)
{
    ngx_sentinel_loc_conf_t lcf;
    memset(&lcf, 0, sizeof(lcf));
    lcf.weights.errrate  = w_errrate;
    lcf.weights.blocked  = w_blocked;
    lcf.weights.scanner  = w_scanner;
    lcf.weights.bot      = w_bot;
    lcf.weights.honeypot = 0;  /* caller sets explicitly when testing honeypot */
    lcf.weights.velocity = 0;  /* caller sets explicitly when testing velocity */
    lcf.weights.asn      = 0;  /* caller sets explicitly when testing asn */
    lcf.weights.coherence = 0; /* caller sets explicitly when testing coherence */
    lcf.weights.ja3      = 0;  /* caller sets explicitly when testing ja3 */
    lcf.weights.ja4      = 0;  /* caller sets explicitly when testing ja4 */
    lcf.weights.ja4t     = 0;  /* caller sets explicitly when testing ja4t */
    lcf.weights.crowdsec = NGX_SENTINEL_DEFAULT_W_CROWDSEC;
    lcf.threshold.challenge = NGX_SENTINEL_DEFAULT_THRESH_CH;
    lcf.threshold.tarpit    = NGX_SENTINEL_DEFAULT_THRESH_TP;
    lcf.threshold.block     = NGX_SENTINEL_DEFAULT_THRESH_BK;
    return lcf;
}

static ngx_sentinel_inputs_t
make_inputs(ngx_uint_t errrate_count, ngx_flag_t errrate_blocked,
            ngx_flag_t scanner_path, ngx_flag_t bot_ua,
            ngx_flag_t known_good_ua)
{
    ngx_sentinel_inputs_t inp;
    memset(&inp, 0, sizeof(inp));
    inp.errrate_count   = errrate_count;
    inp.errrate_blocked = errrate_blocked;
    inp.scanner_path    = scanner_path;
    inp.bot_ua          = bot_ua;
    inp.known_good_ua   = known_good_ua;
    return inp;
}

int
main(void)
{
    ngx_sentinel_inputs_t    inp;
    ngx_sentinel_loc_conf_t  lcf;
    ngx_int_t                score;

    /* ------------------------------------------------------------------
     * (a) known_good_ua short-circuits to 0 regardless of other signals.
     * ------------------------------------------------------------------ */

    lcf = make_lcf(NGX_SENTINEL_DEFAULT_W_ERRRATE,
                   NGX_SENTINEL_DEFAULT_W_BLOCKED,
                   NGX_SENTINEL_DEFAULT_W_SCANNER,
                   NGX_SENTINEL_DEFAULT_W_BOT);

    /* All signals active but known_good_ua=1 → must be 0. */
    inp = make_inputs(64, 1, 1, 1, 1);
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("known_good_ua short-circuits to 0", score, 0);

    /* known_good_ua=0, signals active → must be non-zero. */
    inp = make_inputs(1, 0, 0, 0, 0);
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("no known_good_ua, errrate=1 → non-zero", score != 0, 1);

    /* FCrDNS: a SPOOFED verdict suppresses the known_good_ua short-circuit —
     * the request scores as the bot it is. */
    inp = make_inputs(64, 1, 1, 1, 1);   /* all signals + known_good_ua */
    inp.fcrdns_spoofed = 1;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("fcrdns spoofed: known_good_ua no longer short-circuits",
              score != 0, 1);

    /* FCrDNS: a VERIFIED verdict leaves the short-circuit intact (real crawler). */
    inp = make_inputs(64, 1, 1, 1, 1);
    inp.fcrdns_verified = 1;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("fcrdns verified: known_good_ua still short-circuits", score, 0);

    /* FCrDNS: pending (both 0) keeps legacy fail-open short-circuit. */
    inp = make_inputs(64, 1, 1, 1, 1);
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("fcrdns pending: known_good_ua short-circuits (fail-open)",
              score, 0);

    /* ------------------------------------------------------------------
     * (b) Weighted sum is correct for a known input set.
     *     weights: errrate=2, blocked=10, scanner=5, bot=3
     *     inputs:  errrate_count=4, blocked=1, scanner=1, bot=1
     *     expected: 2*4 + 10 + 5 + 3 = 26
     * ------------------------------------------------------------------ */

    lcf = make_lcf(2, 10, 5, 3);
    inp = make_inputs(4, 1, 1, 1, 0);
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("weighted sum 2*4+10+5+3 = 26", score, 26);

    /* Verify each weight in isolation. */
    lcf = make_lcf(3, 0, 0, 0);
    inp = make_inputs(5, 0, 0, 0, 0);
    ASSERT_EQ("errrate only: 3*5 = 15", sentinel_score_compute(&inp, &lcf), 15);

    lcf = make_lcf(0, 7, 0, 0);
    inp = make_inputs(0, 1, 0, 0, 0);
    ASSERT_EQ("blocked only: 7", sentinel_score_compute(&inp, &lcf), 7);

    lcf = make_lcf(0, 0, 9, 0);
    inp = make_inputs(0, 0, 1, 0, 0);
    ASSERT_EQ("scanner only: 9", sentinel_score_compute(&inp, &lcf), 9);

    lcf = make_lcf(0, 0, 0, 11);
    inp = make_inputs(0, 0, 0, 1, 0);
    ASSERT_EQ("bot only: 11", sentinel_score_compute(&inp, &lcf), 11);

    /* header_anomaly only: weight 25 added once. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.header = NGX_SENTINEL_DEFAULT_W_HEADER;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.header_anomaly = 1;
    ASSERT_EQ("header only: 25", sentinel_score_compute(&inp, &lcf), 25);

    /* known_good_ua short-circuits header_anomaly to 0. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.header = NGX_SENTINEL_DEFAULT_W_HEADER;
    inp = make_inputs(0, 0, 0, 0, 1);
    inp.header_anomaly = 1;
    ASSERT_EQ("known_good_ua overrides header_anomaly",
              sentinel_score_compute(&inp, &lcf), 0);

    /* No signals → 0. */
    lcf = make_lcf(NGX_SENTINEL_DEFAULT_W_ERRRATE,
                   NGX_SENTINEL_DEFAULT_W_BLOCKED,
                   NGX_SENTINEL_DEFAULT_W_SCANNER,
                   NGX_SENTINEL_DEFAULT_W_BOT);
    inp = make_inputs(0, 0, 0, 0, 0);
    ASSERT_EQ("no signals → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (c) Clamp: score cannot exceed NGX_SENTINEL_SCORE_MAX (100000).
     * ------------------------------------------------------------------ */

    /* weight_blocked=100000, blocked=1 → exactly at cap. */
    lcf = make_lcf(0, NGX_SENTINEL_SCORE_MAX, 0, 0);
    inp = make_inputs(0, 1, 0, 0, 0);
    ASSERT_EQ("clamp: single-weight at cap", sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_SCORE_MAX);

    /* weight_blocked=100000, scanner=50 → sum would overflow; must clamp. */
    lcf = make_lcf(0, NGX_SENTINEL_SCORE_MAX, 50, 0);
    inp = make_inputs(0, 1, 1, 0, 0);
    ASSERT_EQ("clamp: sum beyond cap stays at cap",
              sentinel_score_compute(&inp, &lcf), NGX_SENTINEL_SCORE_MAX);

    /* large errrate_count * large weight → clamp. */
    lcf = make_lcf(NGX_SENTINEL_SCORE_MAX, 0, 0, 0);
    inp = make_inputs(100, 0, 0, 0, 0);
    ASSERT_EQ("clamp: huge errrate product",
              sentinel_score_compute(&inp, &lcf), NGX_SENTINEL_SCORE_MAX);

    /* ------------------------------------------------------------------
     * (d) NULL inputs / lcf → 0 (fail-open).
     * ------------------------------------------------------------------ */

    lcf = make_lcf(1, 100, 50, 30);
    ASSERT_EQ("NULL inputs → 0", sentinel_score_compute(NULL, &lcf), 0);

    inp = make_inputs(10, 1, 1, 1, 0);
    ASSERT_EQ("NULL lcf → 0", sentinel_score_compute(&inp, NULL), 0);

    ASSERT_EQ("NULL both → 0", sentinel_score_compute(NULL, NULL), 0);

    /* ------------------------------------------------------------------
     * (f) CrowdSec term: action-tiered weight, known_good short-circuit wins.
     *     Default w_crowdsec=100; thresholds ch=30 tp=60 bk=80.
     *     ban=100 (block), captcha=40 (challenge), throttle=65 (tarpit).
     * ------------------------------------------------------------------ */

    lcf = make_lcf(NGX_SENTINEL_DEFAULT_W_ERRRATE,
                   NGX_SENTINEL_DEFAULT_W_BLOCKED,
                   NGX_SENTINEL_DEFAULT_W_SCANNER,
                   NGX_SENTINEL_DEFAULT_W_BOT);

    /* crowdsec ban only -> full weight 100 (block band). */
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("crowdsec ban -> 100", score, 100);

    /* crowdsec captcha -> 100*40/100 = 40 (challenge band). */
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_CAPTCHA;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("crowdsec captcha -> 40", score, 40);
    ASSERT_EQ("captcha -> challenge band",
              sentinel_score_to_verdict(score, &lcf.threshold),
              NGX_SENTINEL_VERDICT_CHALLENGE);

    /* crowdsec throttle -> 100*65/100 = 65 (tarpit band). */
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_THROTTLE;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("crowdsec throttle -> 65", score, 65);
    ASSERT_EQ("throttle -> tarpit band",
              sentinel_score_to_verdict(score, &lcf.threshold),
              NGX_SENTINEL_VERDICT_TARPIT);

    /* ban -> block band. */
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;
    score = sentinel_score_compute(&inp, &lcf);
    ASSERT_EQ("ban -> block band",
              sentinel_score_to_verdict(score, &lcf.threshold),
              NGX_SENTINEL_VERDICT_BLOCK);

    /* crowdsec weighted with custom weight: w=200, captcha -> 80. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.crowdsec = 200;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_CAPTCHA;
    ASSERT_EQ("crowdsec captcha w=200 -> 80",
              sentinel_score_compute(&inp, &lcf), 80);

    /*
     * SECURITY: an UNVERIFIED known_good_ua (UA substring only, spoofable)
     * must NOT nullify a CrowdSec ban. The good-UA short-circuit is gated on
     * !crowdsec_hit, so with a ban present the score falls through to the
     * weighted sum and the ban weight (default 100) still applies.
     */
    lcf = make_lcf(NGX_SENTINEL_DEFAULT_W_ERRRATE,
                   NGX_SENTINEL_DEFAULT_W_BLOCKED,
                   NGX_SENTINEL_DEFAULT_W_SCANNER,
                   NGX_SENTINEL_DEFAULT_W_BOT);
    inp = make_inputs(0, 0, 0, 0, 1);   /* known_good_ua = 1 */
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;
    ASSERT_EQ("spoofed good-UA does NOT nullify crowdsec ban",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_CROWDSEC);

    /* But with NO crowdsec hit, a good-UA still short-circuits the in-module
     * heuristics to 0 (the allowlist still works for genuine crawlers). */
    inp = make_inputs(64, 1, 1, 1, 1);  /* every heuristic, good-UA, no ban */
    ASSERT_EQ("good-UA still short-circuits heuristics when no ban",
              sentinel_score_compute(&inp, &lcf), 0);

    /* crowdsec hit but weight 0 -> no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.crowdsec = 0;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;
    ASSERT_EQ("crowdsec weight 0 -> 0",
              sentinel_score_compute(&inp, &lcf), 0);

    /* crowdsec folds additively with other signals. */
    lcf = make_lcf(0, 0, 10, 0);
    lcf.weights.crowdsec = 100;
    inp = make_inputs(0, 0, 1, 0, 0);   /* scanner=1 -> +10 */
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;  /* +100 */
    ASSERT_EQ("crowdsec ban + scanner = 110",
              sentinel_score_compute(&inp, &lcf), 110);

    /* ------------------------------------------------------------------
     * (e) Verdict mapping: block > tarpit > challenge > allow at boundaries.
     *     Default thresholds: challenge=30, tarpit=60, block=80.
     * ------------------------------------------------------------------ */

    ngx_sentinel_threshold_t thr = {
        .challenge = NGX_SENTINEL_DEFAULT_THRESH_CH,
        .tarpit    = NGX_SENTINEL_DEFAULT_THRESH_TP,
        .block     = NGX_SENTINEL_DEFAULT_THRESH_BK,
    };

    ASSERT_EQ("verdict 0 → allow",
              sentinel_score_to_verdict(0, &thr),
              NGX_SENTINEL_VERDICT_ALLOW);
    ASSERT_EQ("verdict 29 → allow",
              sentinel_score_to_verdict(29, &thr),
              NGX_SENTINEL_VERDICT_ALLOW);
    ASSERT_EQ("verdict 30 → challenge",
              sentinel_score_to_verdict(30, &thr),
              NGX_SENTINEL_VERDICT_CHALLENGE);
    ASSERT_EQ("verdict 59 → challenge",
              sentinel_score_to_verdict(59, &thr),
              NGX_SENTINEL_VERDICT_CHALLENGE);
    ASSERT_EQ("verdict 60 → tarpit",
              sentinel_score_to_verdict(60, &thr),
              NGX_SENTINEL_VERDICT_TARPIT);
    ASSERT_EQ("verdict 79 → tarpit",
              sentinel_score_to_verdict(79, &thr),
              NGX_SENTINEL_VERDICT_TARPIT);
    ASSERT_EQ("verdict 80 → block",
              sentinel_score_to_verdict(80, &thr),
              NGX_SENTINEL_VERDICT_BLOCK);
    ASSERT_EQ("verdict 100000 → block",
              sentinel_score_to_verdict(NGX_SENTINEL_SCORE_MAX, &thr),
              NGX_SENTINEL_VERDICT_BLOCK);

    /* ------------------------------------------------------------------
     * (g) Honeypot weight: inputs->honeypot contributes w_honeypot once.
     * ------------------------------------------------------------------ */

    /* honeypot only: weight 90 added once. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.honeypot = NGX_SENTINEL_DEFAULT_W_HONEYPOT;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.honeypot = 1;
    ASSERT_EQ("honeypot only: 90",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_HONEYPOT);

    /* honeypot + scanner: combined contribution. */
    lcf = make_lcf(0, 0, 50, 0);
    lcf.weights.honeypot = NGX_SENTINEL_DEFAULT_W_HONEYPOT;
    inp = make_inputs(0, 0, 1, 0, 0);
    inp.honeypot = 1;
    ASSERT_EQ("honeypot + scanner: 90 + 50 = 140",
              sentinel_score_compute(&inp, &lcf), 140);

    /* honeypot=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.honeypot = NGX_SENTINEL_DEFAULT_W_HONEYPOT;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.honeypot = 0;
    ASSERT_EQ("honeypot=0 → 0",
              sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h) Velocity signal: inputs->velocity_exceeded adds w_velocity once.
     * ------------------------------------------------------------------ */

    /* velocity_exceeded=1, weight=30 → score 30. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.velocity = NGX_SENTINEL_DEFAULT_W_VELOCITY;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.velocity_exceeded = 1;
    ASSERT_EQ("velocity only: 30",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_VELOCITY);

    /* velocity + scanner combined: 30 + 50 = 80. */
    lcf = make_lcf(0, 0, 50, 0);
    lcf.weights.velocity = NGX_SENTINEL_DEFAULT_W_VELOCITY;
    inp = make_inputs(0, 0, 1, 0, 0);
    inp.velocity_exceeded = 1;
    ASSERT_EQ("velocity + scanner: 30 + 50 = 80",
              sentinel_score_compute(&inp, &lcf), 80);

    /* velocity_exceeded=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.velocity = NGX_SENTINEL_DEFAULT_W_VELOCITY;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.velocity_exceeded = 0;
    ASSERT_EQ("velocity=0 → 0",
              sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h2) ASN signal: inputs->datacenter_asn adds w_asn once.
     * ------------------------------------------------------------------ */

    /* datacenter_asn=1, weight=35 → score 35. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.asn = NGX_SENTINEL_DEFAULT_W_ASN;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.datacenter_asn = 1;
    ASSERT_EQ("asn only: 35",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_ASN);

    /* asn + bot combined: 35 + 30 = 65. */
    lcf = make_lcf(0, 0, 0, NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.asn = NGX_SENTINEL_DEFAULT_W_ASN;
    inp = make_inputs(0, 0, 0, 1, 0);
    inp.datacenter_asn = 1;
    ASSERT_EQ("asn + bot: 35 + 30 = 65", sentinel_score_compute(&inp, &lcf), 65);

    /* datacenter_asn=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.asn = NGX_SENTINEL_DEFAULT_W_ASN;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.datacenter_asn = 0;
    ASSERT_EQ("asn=0 → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h3) Coherence signal: inputs->ua_incoherent adds w_coherence once.
     * ------------------------------------------------------------------ */

    /* ua_incoherent=1, weight=40 → score 40. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.coherence = NGX_SENTINEL_DEFAULT_W_COHERENCE;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ua_incoherent = 1;
    ASSERT_EQ("coherence only: 40",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_COHERENCE);

    /* coherence + bot combined: 40 + 30 = 70. */
    lcf = make_lcf(0, 0, 0, NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.coherence = NGX_SENTINEL_DEFAULT_W_COHERENCE;
    inp = make_inputs(0, 0, 0, 1, 0);
    inp.ua_incoherent = 1;
    ASSERT_EQ("coherence + bot: 40 + 30 = 70",
              sentinel_score_compute(&inp, &lcf), 70);

    /* ua_incoherent=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.coherence = NGX_SENTINEL_DEFAULT_W_COHERENCE;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ua_incoherent = 0;
    ASSERT_EQ("coherence=0 → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h4) JA4 (TLS) signal: inputs->ja4_flagged adds w_ja4 once.
     * ------------------------------------------------------------------ */

    /* ja4_flagged=1, weight=50 → score 50. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja4 = NGX_SENTINEL_DEFAULT_W_JA4;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja4_flagged = 1;
    ASSERT_EQ("ja4 only: 50",
              sentinel_score_compute(&inp, &lcf), 50);

    /* ja4 + bot combined: 50 + 30 = 80. */
    lcf = make_lcf(0, 0, 0, NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.ja4 = NGX_SENTINEL_DEFAULT_W_JA4;
    inp = make_inputs(0, 0, 0, 1, 0);
    inp.ja4_flagged = 1;
    ASSERT_EQ("ja4 + bot: 50 + 30 = 80",
              sentinel_score_compute(&inp, &lcf), 80);

    /* ja4_flagged=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja4 = NGX_SENTINEL_DEFAULT_W_JA4;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja4_flagged = 0;
    ASSERT_EQ("ja4=0 → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h4a) JA3 (TLS) signal: inputs->ja3_flagged adds w_ja3 once.
     * ------------------------------------------------------------------ */

    /* ja3_flagged=1, weight=80 → score 80. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja3 = NGX_SENTINEL_DEFAULT_W_JA3;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja3_flagged = 1;
    ASSERT_EQ("ja3 only: 80",
              sentinel_score_compute(&inp, &lcf), 80);

    /* ja3 + bot combined: 80 + 30 = 110. */
    lcf = make_lcf(0, 0, 0, NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.ja3 = NGX_SENTINEL_DEFAULT_W_JA3;
    inp = make_inputs(0, 0, 0, 1, 0);
    inp.ja3_flagged = 1;
    ASSERT_EQ("ja3 + bot: 80 + 30 = 110",
              sentinel_score_compute(&inp, &lcf), 110);

    /* ja3_flagged=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja3 = NGX_SENTINEL_DEFAULT_W_JA3;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja3_flagged = 0;
    ASSERT_EQ("ja3=0 → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (h4b) JA4T (TCP) signal: inputs->ja4t_flagged adds w_ja4t once.
     * ------------------------------------------------------------------ */

    /* ja4t_flagged=1, weight=45 → score 45. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja4t = NGX_SENTINEL_DEFAULT_W_JA4T;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja4t_flagged = 1;
    ASSERT_EQ("ja4t only: 45",
              sentinel_score_compute(&inp, &lcf), 45);

    /* ja4t + bot combined: 45 + 30 = 75. */
    lcf = make_lcf(0, 0, 0, NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.ja4t = NGX_SENTINEL_DEFAULT_W_JA4T;
    inp = make_inputs(0, 0, 0, 1, 0);
    inp.ja4t_flagged = 1;
    ASSERT_EQ("ja4t + bot: 45 + 30 = 75",
              sentinel_score_compute(&inp, &lcf), 75);

    /* ja4t_flagged=0 → no contribution. */
    lcf = make_lcf(0, 0, 0, 0);
    lcf.weights.ja4t = NGX_SENTINEL_DEFAULT_W_JA4T;
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.ja4t_flagged = 0;
    ASSERT_EQ("ja4t=0 → 0", sentinel_score_compute(&inp, &lcf), 0);

    /* ------------------------------------------------------------------
     * (i) Allowlist short-circuit: allowlisted forces 0, but a CrowdSec ban
     *     overrides it (same auth-bypass guard as known_good_ua).
     * ------------------------------------------------------------------ */

    /* allowlisted=1, every heuristic active, no ban → short-circuit to 0. */
    lcf = make_lcf(NGX_SENTINEL_DEFAULT_W_ERRRATE,
                   NGX_SENTINEL_DEFAULT_W_BLOCKED,
                   NGX_SENTINEL_DEFAULT_W_SCANNER,
                   NGX_SENTINEL_DEFAULT_W_BOT);
    lcf.weights.honeypot = NGX_SENTINEL_DEFAULT_W_HONEYPOT;
    inp = make_inputs(64, 1, 1, 1, 0);   /* all heuristics, NO good-UA */
    inp.honeypot = 1;
    inp.allowlisted = 1;
    ASSERT_EQ("allowlisted short-circuits heuristics to 0",
              sentinel_score_compute(&inp, &lcf), 0);

    /* allowlisted=1 but CrowdSec ban present → score falls through, ban applies. */
    inp = make_inputs(0, 0, 0, 0, 0);
    inp.allowlisted = 1;
    inp.crowdsec_hit = 1;
    inp.crowdsec_action = NGX_SENTINEL_CS_BAN;
    ASSERT_EQ("allowlist does NOT nullify crowdsec ban",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_CROWDSEC);

    /* allowlisted=0 → no effect, heuristics score normally. */
    lcf = make_lcf(0, 0, NGX_SENTINEL_DEFAULT_W_SCANNER, 0);
    inp = make_inputs(0, 0, 1, 0, 0);
    inp.allowlisted = 0;
    ASSERT_EQ("allowlisted=0 → scanner scores normally",
              sentinel_score_compute(&inp, &lcf),
              NGX_SENTINEL_DEFAULT_W_SCANNER);

    /* ------------------------------------------------------------------
     * Summary
     * ------------------------------------------------------------------ */

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
