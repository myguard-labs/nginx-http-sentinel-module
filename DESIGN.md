# Design — ngx_http_sentinel_module

Locked decisions + non-negotiable safety rules. Read before coding any phase.

## Locked decisions

1. **No network I/O in the request path.** Per-request work = a pure
   shared-memory lookup against a ban/score table. Reputation data
   (CrowdSec, ja4 blocklist) is loaded **out of band** (feed file / `keyval`
   zone, refreshed by a sidecar — Phase 3). Rationale: zero added latency, no
   head-of-line, no blocking worker, no self-inflicted slowloris.
2. **Self-contained — absorb, don't depend (decided 2026-06-23).** Sentinel
   computes/owns **every** signal in-module. No runtime dependency on any sibling
   module. The capabilities sentinel needs are *ported into* it (one module,
   zero external coupling), not read off sibling runtime variables.
   - JA4 (TLS ClientHello): **DEFERRED to Phase 4** (recon 2026-06-23). NOT
     patch-free: `ssl-fingerprint` registers `SSL_CTX_set_client_hello_cb` and
     extends `ngx_ssl_connection_s` via a **core nginx patch**
     (`ssl-fingerprint/patches/nginx-1.29.3+.patch`). A pure HTTP module cannot
     hook the ClientHello. Phase 1–3 ship self-contained with **zero core patch**;
     JA4H already catches most TLS-randomized bots. JA4 lands in Phase 4 via that
     core patch + an in-module port of the JA4 byte-parse, only when traffic
     shows JA4H/H2 evasion. Until then sentinel does NOT read `$ssl_ja4`.
   - JA4H (HTTP header order + method/version/cookie/referer/Accept-Lang):
     computed in-module at the HTTP phase from request headers. Pure-HTTP.
   - Error-rate / scanner-path (404 bursts, `.env`/`.git`/`wp-login`): the
     `nginx-error-abuse-module` logic is **absorbed** into sentinel as a native
     score signal (shared-mem sliding counter). Standalone error-abuse module is
     **deprecated later** once sentinel covers it.
   - UA parse + bot heuristics (`user-agent`, `bot-verifier`): ported in-module
     as score inputs / allowlist (forward-confirmed search-engine verify).
   - JA4T (TCP SYN options): **deferred** (Phase 4, needs proxy_protocol v2
     TLV). Only if real traffic shows JA4/JA4H evasion.
3. **Phase hook = `NGX_HTTP_PREACCESS_PHASE`.** Runs before access/auth, after
   headers are parsed (so JA4H + all header signals are available).
4. **Fail-open default.** Zone-full, lock contention fallback, malformed feed,
   or missing fingerprint → log + allow. `sentinel_fail closed;` is opt-in for
   high-security vhosts.
5. **Absorb, don't reinvent — but stay single-module.** Score logic is *ported
   from* shipped modules (`ssl-fingerprint` JA4 parse, `bot-verifier`/`user-agent`
   heuristics, `error-abuse` error-rate counter) into sentinel's own source. No
   runtime sibling dep. `keyval`-style feed loading is done by sentinel's own
   out-of-band loader (no `keyval` module dep). Mid-score challenge: built-in
   proof-of-work / redirect, or optional handoff to `js-challenge`/`captcha` if
   present (soft, not required).
6. **CrowdSec via stream/out-of-band, not live query.** Phase 3 feeds decisions
   from the existing lua bouncer (stream mode) → `keyval`/file → sentinel
   shared-mem. A native async LAPI client is explicitly deferred (complexity).
7. **Shadow mode is first-class.** `sentinel_mode shadow` computes + logs the
   score/verdict but enforces nothing. Ships in Phase 1 — thresholds must be
   tunable against real traffic before any client is affected. `enforce` opt-in.

## Safety rules (every phase, enforced in CI)

- No `malloc` in the hot path — request pool + fixed stack buffers only.
- Every shared-memory access under its zone lock; entries bounded + expiring
  (LRU / TTL) so the zone can never grow unbounded.
- No blocking I/O in the request path. Network only in out-of-band loaders.
- Tarpit globally connection-capped (shared counter); minimal fixed write
  buffer; hard max lifetime then close; decrement on every exit path
  (success / abort / timeout / worker exit).
- No regex in the hot path.
- Every function + feature gets a CI test in the same commit (build-test +
  valgrind + asan + security-scanners; fuzz where input is attacker-controlled).

## Directive set (target)

```
sentinel               on | off;                    # default off
sentinel_zone          name:size;                   # shared-mem ban/score table
sentinel_fail          open | closed;               # default open
sentinel_ja4_blocklist file;                         # static ja4 blocklist (Phase 1)
sentinel_threshold     challenge=N tarpit=M block=K; # score cut points
sentinel_action_challenge  <uri|named-location>;     # hand off to js-challenge/captcha
sentinel_tarpit_max_conns  N;                        # global cap (Phase 2)
sentinel_tarpit_delay  ms;                            # drip interval
sentinel_tarpit_bytes  N;                             # bytes per drip / total cap
sentinel_crowdsec_zone name;                          # decisions feed (Phase 3)
```

## Exported variables

- `$sentinel_score`   — computed integer score
- `$sentinel_verdict` — allow | challenge | tarpit | block
- `$sentinel_ja4h`    — computed JA4H hash

## Scoring model (Phase 1, tunable)

`score = w_crowdsec·hit + w_ja4·blocklist_hit + w_bot·bot_signal +
w_errrate·error_burst`. All signals computed in-module. Weights are
directives with safe defaults. Verdict = first threshold crossed
(block > tarpit > challenge > allow). Keep it a plain weighted sum — no ML, no
regex, auditable.

## Roadmap — signal & action catalog

Core (Phases 1–3) ships JA4/JA4H, crowdsec + static ja4 blocklist, the score,
shadow mode, and allow/challenge/tarpit/block. Everything below layers on the
same score-then-act pipeline once core proves out. Full prose + config examples:
the internal pitch page (deb.myguard.nl, noindex).

**Signals (score inputs, all O(1) / no request-path network):**
- JA4 (TLS, reused) · JA4H (HTTP header order, in-module) · JA4T (TCP, Phase 4)
- HTTP/2 frame-order fingerprint (Akamai-style) — survives TLS randomization
- UA ↔ fingerprint coherence — UA says Chrome, JA4H/H2 says curl ⇒ strong bot tell
- datacenter/ASN reputation (reuse `geoip2`) · geo weighting
- velocity (shared-mem sliding counter) · scanner-path behaviour (404 bursts, `.env`/`.git`/`wp-login`)
- honeypot/canary hit ⇒ instant max score · header anomalies (missing Accept-Language, dup headers)

**Actions (verdict dispatch, escalating):**
- allow · observe(shadow) · challenge (js-challenge / captcha / built-in proof-of-work)
- throttle (bandwidth-cap, don't drop) · cache-only (origin shield) · tarpit (drip / maze)
- block (403/444) · feedback (push verdict back to CrowdSec — closes loop)

**Ops/safety:** per-route policy · allowlist (forward-confirmed search engines via
`bot-verifier`, monitoring IPs) · metrics → VTS/statsd/OTel · structured decision
log · TTL soft-bans · `sentinel off` kill-switch.

## Module source layout (Phase 1+)

`config` (nginx addon) + `src/ngx_http_sentinel_module.c` (core: conf, phase
handler, vars) splitting out as it grows: `sentinel_score.c`,
`sentinel_ja4.c` (TLS ClientHello parse, ported from ssl-fingerprint),
`sentinel_ja4h.c` (HTTP header order), `sentinel_shm.c`, `sentinel_tarpit.c`,
`sentinel_errrate.c` (error-burst counter, absorbed from error-abuse),
`sentinel_botua.c` (UA/bot heuristics + search-engine verify),
`sentinel_feed.c` (out-of-band loader) — mirrors the sibling `nla_*.c` /
`ngx_autocert_*.c` split style.
