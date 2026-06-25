/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * sentinel_score.c — score computation for ngx_http_sentinel_module.
 *
 * Plain weighted sum over the in-module signals (auditable, no ML, no regex,
 * no allocation, no I/O):
 *
 *   score = w_errrate  * errrate_count
 *         + w_blocked  * errrate_blocked
 *         + w_scanner  * scanner_path
 *         + w_bot      * bot_ua
 *         + w_header   * header_anomaly
 *         + w_honeypot * honeypot
 *         + w_velocity * velocity_exceeded
 *         + w_asn      * datacenter_asn
 *         + w_ja4      * ja4_flagged
 *         + w_ja4t     * ja4t_flagged
 *         + w_coherence * ua_incoherent
 *         + w_crowdsec * crowdsec_hit (action-tiered: see below)
 *
 * CrowdSec action tiering (keeps weaker actions out of the block band):
 *   ban      => full w_crowdsec        (block band at default weight 100)
 *   captcha  => w_crowdsec * 40 / 100  (challenge band: >=30 <60 default)
 *   throttle => w_crowdsec * 65 / 100  (tarpit band:    >=60 <80 default)
 * Plain integer arithmetic, a single switch — no table lookup in the hot path.
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

    /*
     * Search-engine allowlist short-circuit.
     *
     * SECURITY: known_good_ua is set by User-Agent SUBSTRING only (see
     * sentinel_botua.c) — it is NOT forward/reverse-DNS confirmed yet (the
     * Phase 3 "bot-verifier" is still pending). A `User-Agent: Googlebot`
     * header is therefore trivially spoofable. We allow it to override the
     * in-module heuristic signals (errrate/scanner/bot/header), but it MUST
     * NOT nullify a CrowdSec ban: a deployed CrowdSec feed is the operator
     * explicitly asserting "this IP is malicious regardless of headers."
     * Letting a spoofed UA wipe that is an auth-bypass. So: only short-circuit
     * when there is no CrowdSec hit.
     *
     * FCrDNS tightening: when the forward-confirmed reverse-DNS check has
     * positively DISPROVED the crawler claim (fcrdns_spoofed), the known_good_ua
     * short-circuit is suppressed entirely — the request is scored as the bot it
     * is. A VERIFIED verdict (or FCrDNS disabled / still pending) leaves the
     * legacy behavior intact (fail-open: a pending verdict does not punish).
     */
    if (inputs->known_good_ua && !inputs->crowdsec_hit
        && !inputs->fcrdns_spoofed)
    {
        return 0;
    }

    /*
     * Operator CIDR allowlist short-circuit.
     *
     * Unlike known_good_ua (a spoofable UA substring), allow_cidrs is a network-
     * level assertion the operator made about source addresses — much stronger.
     * It still must NOT nullify a CrowdSec ban, by the same reasoning: a deployed
     * feed is the operator explicitly marking the IP malicious. If a trusted
     * range is later found compromised, the ban wins. So short-circuit only when
     * there is no CrowdSec hit.
     */
    if (inputs->allowlisted && !inputs->crowdsec_hit) {
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

    if (inputs->header_anomaly) {
        sentinel_score_add(&score, w->header);
    }

    if (inputs->honeypot) {
        sentinel_score_add(&score, w->honeypot);
    }

    /* velocity_exceeded — rate limit exceeded */
    if (inputs->velocity_exceeded) {
        sentinel_score_add(&score, w->velocity);
    }

    /* datacenter_asn — request originates from a flagged datacenter/abuse ASN */
    if (inputs->datacenter_asn) {
        sentinel_score_add(&score, w->asn);
    }

    /* ja4_flagged — client JA4 (TLS) fingerprint on the operator deny list */
    if (inputs->ja4_flagged) {
        sentinel_score_add(&score, w->ja4);
    }

    /* ja4t_flagged — client JA4T (TCP) fingerprint on the operator deny list */
    if (inputs->ja4t_flagged) {
        sentinel_score_add(&score, w->ja4t);
    }

    /* ua_incoherent — UA claims a browser the request shape contradicts */
    if (inputs->ua_incoherent) {
        sentinel_score_add(&score, w->coherence);
    }

    /* CrowdSec hit — action-tiered fraction of w_crowdsec (no block escalation
     * for captcha/throttle). known_good_ua above already short-circuited. */
    if (inputs->crowdsec_hit && w->crowdsec > 0) {
        ngx_int_t  term;

        switch (inputs->crowdsec_action) {
        case NGX_SENTINEL_CS_CAPTCHA:
            term = w->crowdsec * 40 / 100;
            break;
        case NGX_SENTINEL_CS_THROTTLE:
            term = w->crowdsec * 65 / 100;
            break;
        case NGX_SENTINEL_CS_BAN:
        default:
            term = w->crowdsec;
            break;
        }
        sentinel_score_add(&score, term);
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
