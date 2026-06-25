/*
 * sentinel_metrics.c — Prometheus metrics for ngx_http_sentinel_module.
 *
 * Aggregate counters live in the same dedicated shm segment as the tarpit
 * per-worker sub-counters (allocated at sentinel_zone init; see
 * ngx_sentinel_tarpit_shm_init). They are a flat ngx_atomic_t[] indexed by
 * ngx_sentinel_metric_e and bumped lock-free with ngx_atomic_fetch_add from the
 * preaccess handler — observability is best-effort and NEVER blocks, allocates,
 * or fails a request. The `sentinel_status;` content handler scrapes them with
 * plain (lock-free) reads and emits text/plain exposition; pull-model, the
 * operator protects the location with allow/deny.
 *
 * tarpit_active is NOT a counter — it is summed live from the per-worker
 * tarpit_conns array on scrape (a gauge), matching the existing accounting.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "sentinel.h"


/* Bump one counter; safe no-op when the metrics array is absent. */
static ngx_inline void
sentinel_metric_inc(ngx_sentinel_main_conf_t *mcf, ngx_sentinel_metric_e idx)
{
    if (mcf == NULL || mcf->metrics == NULL) {
        return;
    }
    (void) ngx_atomic_fetch_add(&mcf->metrics[idx], 1);
}


void
sentinel_metrics_record(ngx_sentinel_main_conf_t *mcf,
    const ngx_sentinel_ctx_t *ctx, ngx_uint_t shadow)
{
    const ngx_sentinel_inputs_t  *in;

    if (mcf == NULL || mcf->metrics == NULL || ctx == NULL) {
        return;
    }

    sentinel_metric_inc(mcf, NGX_SENTINEL_M_REQUESTS);

    /* verdict_total — enum order matches the M_VERDICT_* block. */
    sentinel_metric_inc(mcf,
        (ngx_sentinel_metric_e) (NGX_SENTINEL_M_VERDICT_ALLOW + ctx->verdict));

    /* signal_total — one bump per input that fired. */
    in = &ctx->inputs;
    if (in->errrate_count > 0) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_ERRRATE);
    }
    if (in->errrate_blocked) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_BLOCKED);
    }
    if (in->scanner_path) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_SCANNER);
    }
    if (in->bot_ua) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_BOT);
    }
    if (in->header_anomaly) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_HEADER);
    }
    if (in->honeypot) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_HONEYPOT);
    }
    if (in->velocity_exceeded) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_VELOCITY);
    }
    if (in->datacenter_asn) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_ASN);
    }
    if (in->ja4_flagged) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_JA4);
    }
    if (in->ja4t_flagged) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_JA4T);
    }
    if (in->ua_incoherent) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_COHERENCE);
    }
    if (in->crowdsec_hit) {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SIG_CROWDSEC);
    }

    /* shadow_total: would-block decision suppressed by shadow mode. */
    if (shadow
        && (ctx->verdict == NGX_SENTINEL_VERDICT_TARPIT
            || ctx->verdict == NGX_SENTINEL_VERDICT_BLOCK))
    {
        sentinel_metric_inc(mcf, NGX_SENTINEL_M_SHADOW);
    }
}


/* Static label tables — names are compile-time constants (no escaping needed:
 * no '"', '\\', or '\n' in any of them). */

static const char *const  sentinel_verdict_labels[] = {
    "allow", "challenge", "tarpit", "block"
};

static const struct {
    ngx_sentinel_metric_e  idx;
    const char            *label;
} sentinel_signal_labels[] = {
    { NGX_SENTINEL_M_SIG_ERRRATE,   "errrate"   },
    { NGX_SENTINEL_M_SIG_BLOCKED,   "blocked"   },
    { NGX_SENTINEL_M_SIG_SCANNER,   "scanner"   },
    { NGX_SENTINEL_M_SIG_BOT,       "bot"       },
    { NGX_SENTINEL_M_SIG_HEADER,    "header"    },
    { NGX_SENTINEL_M_SIG_HONEYPOT,  "honeypot"  },
    { NGX_SENTINEL_M_SIG_VELOCITY,  "velocity"  },
    { NGX_SENTINEL_M_SIG_ASN,       "asn"       },
    { NGX_SENTINEL_M_SIG_COHERENCE, "coherence" },
    { NGX_SENTINEL_M_SIG_CROWDSEC,  "crowdsec"  },
    { NGX_SENTINEL_M_SIG_JA4,       "ja4"       },
    { NGX_SENTINEL_M_SIG_JA4T,      "ja4t"      }
};

#define SENTINEL_SIGNAL_LABELS                                                \
    (sizeof(sentinel_signal_labels) / sizeof(sentinel_signal_labels[0]))


static ngx_inline ngx_atomic_uint_t
sentinel_metric_get(ngx_sentinel_main_conf_t *mcf, ngx_sentinel_metric_e idx)
{
    if (mcf == NULL || mcf->metrics == NULL) {
        return 0;
    }
    return (ngx_atomic_uint_t) mcf->metrics[idx];
}


/* tarpit_active: live sum of the per-worker tarpit_conns sub-counters (gauge). */
static ngx_atomic_uint_t
sentinel_tarpit_active(ngx_sentinel_main_conf_t *mcf)
{
    ngx_atomic_uint_t  sum = 0;
    ngx_uint_t         i;

    if (mcf == NULL || mcf->tarpit_conns == NULL) {
        return 0;
    }

    for (i = 0; i < NGX_MAX_PROCESSES; i++) {
        sum += (ngx_atomic_uint_t) mcf->tarpit_conns[i];
    }

    return sum;
}


/*
 * Upper bound for the exposition body:
 *  - fixed HELP/TYPE/sample text for the scalar metrics, and
 *  - the verdict/signal families: per line ~ a long label + a 20-digit value.
 * 4 KB comfortably covers the fully-populated output (currently ~1.5 KB);
 * computed generously so a future counter addition stays within budget.
 */
#define SENTINEL_STATUS_BUFSZ  4096


ngx_int_t
sentinel_metrics_status_handler(ngx_http_request_t *r)
{
    ngx_sentinel_main_conf_t  *mcf;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    u_char                    *buf, *p, *last;
    ngx_uint_t                 i;
    ngx_int_t                  rc;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_sentinel_module);

    buf = ngx_pnalloc(r->pool, SENTINEL_STATUS_BUFSZ);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p    = buf;
    last = buf + SENTINEL_STATUS_BUFSZ;

    /* requests_total */
    p = ngx_slprintf(p, last,
        "# HELP sentinel_requests_total Requests evaluated by sentinel.\n"
        "# TYPE sentinel_requests_total counter\n"
        "sentinel_requests_total %uA\n",
        sentinel_metric_get(mcf, NGX_SENTINEL_M_REQUESTS));

    /* verdict_total{v=...} */
    p = ngx_slprintf(p, last,
        "# HELP sentinel_verdict_total Verdicts by band.\n"
        "# TYPE sentinel_verdict_total counter\n");
    for (i = 0; i < 4; i++) {
        p = ngx_slprintf(p, last,
            "sentinel_verdict_total{v=\"%s\"} %uA\n",
            sentinel_verdict_labels[i],
            sentinel_metric_get(mcf,
                (ngx_sentinel_metric_e) (NGX_SENTINEL_M_VERDICT_ALLOW + i)));
    }

    /* signal_total{s=...} */
    p = ngx_slprintf(p, last,
        "# HELP sentinel_signal_total Signal hits by source.\n"
        "# TYPE sentinel_signal_total counter\n");
    for (i = 0; i < SENTINEL_SIGNAL_LABELS; i++) {
        p = ngx_slprintf(p, last,
            "sentinel_signal_total{s=\"%s\"} %uA\n",
            sentinel_signal_labels[i].label,
            sentinel_metric_get(mcf, sentinel_signal_labels[i].idx));
    }

    /* shadow_total */
    p = ngx_slprintf(p, last,
        "# HELP sentinel_shadow_total Would-block decisions suppressed by "
        "shadow mode.\n"
        "# TYPE sentinel_shadow_total counter\n"
        "sentinel_shadow_total %uA\n",
        sentinel_metric_get(mcf, NGX_SENTINEL_M_SHADOW));

    /* tarpit_active — gauge (live connection count) */
    p = ngx_slprintf(p, last,
        "# HELP sentinel_tarpit_active Connections currently held in a "
        "tarpit.\n"
        "# TYPE sentinel_tarpit_active gauge\n"
        "sentinel_tarpit_active %uA\n",
        sentinel_tarpit_active(mcf));

    /* p never reaches `last` for the current metric set; ngx_slprintf would
     * truncate (not overflow) if a future addition exceeded the buffer. */

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = p - buf;

    ngx_str_set(&r->headers_out.content_type, "text/plain; version=0.0.4");
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos      = buf;
    b->last     = p;
    b->memory   = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
