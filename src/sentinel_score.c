/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_score.c — score computation for ngx_http_sentinel_module.
 *
 * Plain weighted sum over the in-module signals (auditable, no ML, no regex,
 * no allocation, no I/O):
 *
 *   score = w_errrate * errrate_count
 *         + w_blocked * errrate_blocked
 *         + w_scanner * scanner_path
 *         + w_bot     * bot_ua
 *
 * known_good_ua (forward-confirmed search engine) short-circuits to 0 and
 * overrides every other signal. The result is clamped to
 * [0, NGX_SENTINEL_SCORE_MAX] so a misconfigured weight or a large burst
 * count can never overflow ngx_int_t. Fail-open: any inconsistent input
 * (NULL pointers) yields score 0.
 *
 * Phase 2: w_ja4 * ja4_blocklist_hit. Phase 3: w_crowdsec * crowdsec_hit.
 */

#include "sentinel.h"

/* Saturating add into *acc, capped at NGX_SENTINEL_SCORE_MAX. Inputs are all
 * non-negative here, so we only guard the upper bound. */
static ngx_inline void
sentinel_score_add(ngx_int_t *acc, ngx_int_t term)
{
    if (term <= 0) {
        return;
    }
    if (term > NGX_SENTINEL_SCORE_MAX - *acc) {
        *acc = NGX_SENTINEL_SCORE_MAX;
        return;
    }
    *acc += term;
}

ngx_int_t
sentinel_score_compute(const ngx_sentinel_inputs_t *inputs,
    const ngx_sentinel_loc_conf_t *lcf)
{
    const ngx_sentinel_weights_t  *w;
    ngx_int_t                       score;

    /* Fail-open on any inconsistent state. */
    if (inputs == NULL || lcf == NULL) {
        return 0;
    }

    /* Forward-confirmed search engine: allow, override everything. */
    if (inputs->known_good_ua) {
        return 0;
    }

    w = &lcf->weights;
    score = 0;

    /* errrate_count is bounded by NGX_SENTINEL_MAX_WINDOW_EVENTS; clamp the
     * product defensively so a huge weight cannot overflow. */
    if (w->errrate > 0 && inputs->errrate_count > 0) {
        ngx_int_t  cnt = (ngx_int_t) inputs->errrate_count;

        if (cnt > NGX_SENTINEL_SCORE_MAX / w->errrate) {
            sentinel_score_add(&score, NGX_SENTINEL_SCORE_MAX);
        } else {
            sentinel_score_add(&score, w->errrate * cnt);
        }
    }

    if (inputs->errrate_blocked) {
        sentinel_score_add(&score, w->blocked);
    }

    if (inputs->scanner_path) {
        sentinel_score_add(&score, w->scanner);
    }

    if (inputs->bot_ua) {
        sentinel_score_add(&score, w->bot);
    }

    if (score < 0) {
        score = 0;
    }
    if (score > NGX_SENTINEL_SCORE_MAX) {
        score = NGX_SENTINEL_SCORE_MAX;
    }

    return score;
}

ngx_sentinel_verdict_e
sentinel_score_to_verdict(ngx_int_t score,
    const ngx_sentinel_threshold_t *thr)
{
    if (score >= thr->block) {
        return NGX_SENTINEL_VERDICT_BLOCK;
    }
    if (score >= thr->tarpit) {
        return NGX_SENTINEL_VERDICT_TARPIT;
    }
    if (score >= thr->challenge) {
        return NGX_SENTINEL_VERDICT_CHALLENGE;
    }
    return NGX_SENTINEL_VERDICT_ALLOW;
}
