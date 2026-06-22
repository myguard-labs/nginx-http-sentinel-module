# Design — ngx_http_sentinel_module

Locked decisions + non-negotiable safety rules. Read before coding any phase.

## Locked decisions

1. **No network I/O in the request path.** Per-request work = a pure
   shared-memory lookup against a ban/score table. Reputation data
   (CrowdSec, ja4 blocklist) is loaded **out of band** (feed file / `keyval`
   zone, refreshed by a sidecar — Phase 3). Rationale: zero added latency, no
   head-of-line, no blocking worker, no self-inflicted slowloris.
2. **Fingerprint sourcing — zero new SSL patch.**
   - JA4 (TLS ClientHello): **reuse** the `ssl-fingerprint` module's existing
     variable. Sentinel only reads it.
   - JA4H (HTTP header order + method/version/cookie/referer/Accept-Lang):
     computed **inside sentinel** at the HTTP phase from request headers.
     Pure-HTTP → no core/SSL patch.
   - JA4T (TCP SYN options): **deferred** (Phase 4, needs proxy_protocol v2
     TLV). Only if real traffic shows JA4/JA4H evasion.
3. **Phase hook = `NGX_HTTP_PREACCESS_PHASE`.** Runs before access/auth, after
   headers are parsed (so JA4H + all header signals are available).
4. **Fail-open default.** Zone-full, lock contention fallback, malformed feed,
   or missing fingerprint → log + allow. `sentinel_fail closed;` is opt-in for
   high-security vhosts.
5. **Reuse, don't reinvent.** Score inputs come from modules already shipped:
   `ssl-fingerprint` (ja4), `keyval` (data feed), `bot-verifier` + `user-agent`
   (bot/UA signal). Mid-score challenge hands off to `js-challenge` / `captcha`.
6. **CrowdSec via stream/out-of-band, not live query.** Phase 3 feeds decisions
   from the existing lua bouncer (stream mode) → `keyval`/file → sentinel
   shared-mem. A native async LAPI client is explicitly deferred (complexity).

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
  valgrind + asan + codeql; fuzz where input is attacker-controlled).

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

`score = w_crowdsec·hit + w_ja4·blocklist_hit + w_bot·bot_signal`. Weights are
directives with safe defaults. Verdict = first threshold crossed
(block > tarpit > challenge > allow). Keep it a plain weighted sum — no ML, no
regex, auditable.

## Module source layout (Phase 1+)

`config` (nginx addon) + `src/ngx_http_sentinel_module.c` (core: conf, phase
handler, vars) splitting out as it grows: `sentinel_score.c`,
`sentinel_ja4h.c`, `sentinel_shm.c`, `sentinel_tarpit.c`, `sentinel_feed.c`
(mirrors the sibling `nla_*.c` / `ngx_autocert_*.c` split style).
