# TODO — ngx_http_sentinel_module

Phased build plan. Each phase = own feat branch off `dev` → PR to **`dev`** →
**local CI green** → merge. NO remote CI on dev. master PRs only on user word
(unsquashed + remote CI). Tier tag `[haiku|sonnet|opus-low|opus|codex]` = cheapest
model that does the step. Design + safety: [DESIGN.md](DESIGN.md). Loop/CI/cron
rules: `memory/eilandert/nginx-http-sentinel-module/workflow.md`.

## Phase 0 — Recon `[sonnet, investigator]`
Self-contained module → recon maps code to **PORT**, not vars to read.
Compressed file:line map, no fixes. One agent.
- [ ] ssl-fingerprint: HOW it registers the ClientHello SSL callback (confirm
      patch-free) + the JA4 byte-parse fn to port — file:line + fn names
- [ ] error-abuse: error-rate/scanner-path counter logic + shmem counter shape
      to absorb; tarpit/drip prior-art; CI harness files to copy
- [ ] bot-verifier + user-agent: UA-parse + forward-confirmed-DNS verify fns to port
- [ ] js-challenge: OPTIONAL soft handoff mechanism (redirect/named loc) — sentinel
      has built-in PoW, this is just the optional bridge
- [ ] shmem prior-art: rbtree+slab+TTL pattern from a sibling (error-abuse / dynamic-limit-req)
- [ ] output = port map (what fn from where → which sentinel_*.c) → Phase 1 spec

## Phase 1 — Skeleton + score + decide `PR #1`
Static data only (ja4 blocklist file + in-module feed). Verdict = allow / 403 / challenge. No tarpit, no live CrowdSec. **All signals in-module.**
- [x] `[sonnet]` `config` addon + `src/ngx_http_sentinel_module.c` skeleton
- [x] `[sonnet]` PREACCESS handler, conf create/merge, var registration
- [x] `[sonnet]` directives: `sentinel`, `sentinel_zone`, `sentinel_ja4_blocklist`, `sentinel_fail`, `sentinel_mode shadow|enforce`, `sentinel_threshold`
- [x] `[sonnet]` JA4H compute from headers → `$sentinel_ja4h` (fixed buffers, no malloc) — pure-HTTP, no patch
- [x] `[sonnet]` error-rate signal absorbed from error-abuse: port `ngx_http_error_abuse_record` sliding-window circular buffer + status-bitfield match → score input. Add scanner-path static match (.env/.git/wp-login, no regex)
- [x] `[sonnet]` UA/bot heuristics: port `ngx_http_user_agent_variable` trie+version-range → score input. (forward-DNS verify deferred to Phase 3 allowlist)
- [x] `[sonnet]` shmem ban/score table: rbtree+slab, TTL/LRU bound, locked — copy error-abuse `ngx_http_error_abuse_init_zone` + `rbtree_insert` pattern
- [x] `[opus-low]` score combine + action dispatch + fail-open path + shadow mode (score+log, no enforce) (security core)
- [x] `[sonnet]` vars `$sentinel_score $sentinel_verdict`
- [x] `[sonnet]` CI harness (copy error-abuse): ci-build + test_runtime + valgrind/asan/codeql; test every fn
- [x] `[codex]` audit Phase 1
- [x] `[opus-low]` fix findings → PR #1 → CI green → merge

## Phase 1b — wire errrate recording (carryover from Phase 1)
- [x] `[sonnet]` `sentinel_shm_errrate_record` exists + tested but NOT called: add
      response-status output hook (header/log-phase) to feed the sliding counter,
      so error-rate signal is live (Phase 1 only reads, never records yet)

## Phase 2 — Tarpit action `PR #2`
Highest self-DoS risk → opus owns resource model.
- [x] `[opus]` design tarpit resource model (conn cap, timers, fixed buf, max lifetime) — spec first
- [x] `[sonnet]` implement drip to spec: content handler, ngx_add_timer, small writes, decrement on every exit
- [x] `[sonnet]` directives `sentinel_tarpit_max_conns/delay/bytes`; wire verdict=tarpit
- [x] `[sonnet]` CI: conn-cap enforced, no FD/mem leak under flood, abort/timeout paths (valgrind+asan)
- [x] `[codex]` audit leak/DoS surface
- [x] `[opus]` review concurrency → PR #2 → CI green → merge

## Phase 3 — CrowdSec live feed `PR #3`
Out-of-band sync; request path untouched.
- [x] `[opus-low]` confirm feed path: lua bouncer stream → keyval → module (recommended) vs native client (defer)
- [x] `[sonnet]` consume decisions from keyval/file into ban table; honor feed TTL
- [x] `[sonnet]` key by ip + ja4; decision delete = entry removal
- [x] `[sonnet]` CI: feed-update reflected, expiry honored, malformed feed → fail-open + log
- [x] `[codex]` audit
- [x] `[opus-low]` fixes → PR #3 → CI green → merge

## Phase 4 — JA4 (TLS) + JA4T (patch-bearing, defer) `PR #4`
Only if traffic shows JA4H/H2 evasion. Both need core surface beyond pure HTTP.
- [ ] `[opus-low]` JA4 (TLS ClientHello): apply `ssl-fingerprint/patches/nginx-1.29.3+.patch` to build (SSL_CTX_set_client_hello_cb + ngx_ssl_connection_s fields); port JA4 byte-parse (`ngx_ssl_fingerprint_ja3`/ja4 fns) into `sentinel_ja4.c` → `$sentinel_ja4` → score. Patch must rebase per nginx release.
- [ ] `[opus-low]` JA4T: proxy_protocol v2 TLV → JA4T var → score.

## Roadmap (post-core, incremental — layered on the score-then-act pipeline)
Each = own small PR. Full catalog + config examples: the pitch page (DESIGN.md links it).
- [x] signal: header-anomaly (no-Host/CL+TE/dup-Host/no-Accept+UA) — PR #1, merged to dev 2026-06-23
- [x] signal: honeypot (operator decoy-path prefix match → w_honeypot 90) — PR #3, merged to dev 2026-06-23
- [x] signal: velocity (request-rate per identity, reuses errrate shm ring; sentinel_velocity_zone name:size rate=/window=/block=; w_velocity 30) — PR #4, merged to dev 2026-06-23
- [x] velocity: per-LOCATION vel_zone binding — `sentinel_velocity <zone>;` opt-in dir, auto-bind removed, inherits to nested loc — PR #5, dev 2026-06-23
- [x] velocity: edge — child-loc bad zone name silently inherited parent binding. Fixed: clear vel_zone before name resolution → unknown name now rejected. Runtime T8b covers it — PR #6, dev 2026-06-23
- [ ] test harness: t/basic.t (Test::Nginx) is non-functional — all tests die with "sentinel directive is not allowed here" (module never load_module'd by harness). Either wire %%TEST_NGINX_LOAD_MODULES%% / main_config load, or drop t/*.t and rely on tools/test_runtime.py (current authority). Coverage currently lives in test_runtime.py + t/test_score.c unit
- [ ] signals: HTTP/2 frame-order fingerprint (needs core surface, traffic-gated)
- [x] signals: datacenter/ASN (geoip2) — `sentinel_asn $geoip2_asn;` + `sentinel_datacenter_asn N...;`; reads complex value, no libmaxminddb link, w_asn 35, $sentinel_asn var. Runtime TEST 15. PR #20, master 2026-06-24
- [x] signals: UA↔request-shape coherence — UA claims a mainstream browser but the request lacks a real browser's header shape (no Accept/Accept-Language/gzip Accept-Encoding, or pre-HTTP/1.1) → w_coherence 40; structural heuristic, NO JA4H hash DB; new sentinel_coherence.c + $sentinel_coherence var. Runtime TEST 16. PR #21, master 2026-06-24
- [x] actions: throttle (bandwidth-cap) — `sentinel_throttle_rate size;` forks the TARPIT verdict (enforce) to cap egress via native r->limit_rate instead of dripping; $sentinel_throttled var. Runtime TEST 12. PR #16, master 2026-06-24
- [x] actions: cache-only origin-shield — `sentinel_shield on;` forks the TARPIT verdict (enforce) to raise $sentinel_shield=1 + NGX_DECLINED (request served, operator wires proxy_cache_use_stale/proxy_no_cache to serve cache-only); module only raises the signal (no upstream obj at preaccess). Throttle wins precedence. Runtime TEST 19. PR #24, master 2026-06-24
- [ ] actions: CrowdSec verdict feedback (PoW DONE #23; maze DONE #19; throttle DONE #16; shield DONE #24)
- [x] ops: TTL soft-bans — `sentinel_block_ttl S;` persists a self-ban (now+ttl) in the errrate zone on BLOCK/enforce; reuses errrate blocked_until → w_blocked re-block, no re-eval; fail-open if no zone; shadow never persists. Runtime TEST 11. PR #15, master 2026-06-24
- [x] ops: per-route policy — all policy directives merge per-location via stock nginx inheritance (delivered by http/server/loc context widening); README section + runtime TEST 13 (same bot UA → strict=403, lax=200) lock the contract — PR, 2026-06-24
- [x] ops: structured decision log — 14 NOCACHEABLE vars + JSON log_format example (PR #12/#13); throttled-field finish (example + t/basic.t TEST 10 cover $sentinel_throttled) — PR, 2026-06-24
- [x] ops: FCrDNS verify (verified search engines) — `sentinel_fcrdns <zone>;` async PTR+forward-confirm of self-declared crawlers (known_good_ua only); verdict cached in shm w/ TTL; spoofed verdict suppresses the known_good_ua score short-circuit; fail-open while pending / no resolver. New sentinel_fcrdns.c + $sentinel_fcrdns var + sentinel_fcrdns_zone/_ttl/_verify_suffix. Runtime TEST 17. PR #22, master 2026-06-24
- [ ] `[opus]` **ops: metrics → Prometheus `/sentinel-status`** — DESIGN LOCKED w/ user 2026-06-25, ready to build (backend = Prometheus pull, chosen over VTS/statsd/OTel: zero dep, self-contained, idiomatic):
      - **Aggregate counters in a dedicated shm zone** (mirror the `tarpit_conns` per-worker atomic pattern in sentinel.h:384 — allocate at zone init, per-worker sub-counters summed on read to avoid cross-worker contention; OR one `ngx_atomic_t` block w/ atomic incr — pick per-worker to match precedent). Counters: `requests_total`, `verdict_total{allow,challenge,tarpit,block}` (4), per-signal `signal_total{errrate,blocked,scanner,bot,header,honeypot,velocity,asn,coherence,crowdsec}` (mirror ngx_sentinel_weights_t fields, +1 when that input fired), `tarpit_active` (sum the existing tarpit_conns array — already live), `shadow_total` (would-block in shadow mode). Bump them in the preaccess handler right after verdict computed (one branch, no request-path net/alloc).
      - **Export = new content-phase handler** on an operator-placed `location = /sentinel-status { sentinel_status; }`. Emits `text/plain; version=0.0.4` Prometheus exposition: `# HELP`/`# TYPE` + one line per counter, labels for verdict/signal. Pull-model — operator scrapes; protect the location with `allow`/`deny` (document it). No new dep, no timer.
      - **New dir `sentinel_status;`** (LOC only, sets the content handler). New `src/sentinel_metrics.c` (counter struct + shm alloc + incr helpers + the status handler) + config + build-test strict list. Counters shm auto-allocated when ANY sentinel zone exists (or its own tiny `sentinel_status_zone`? — prefer piggyback on existing zone-init shm, like tarpit_conns, no new zone directive).
      - **Fail-open/safe:** counters are best-effort observability — never block a request; status handler reads shm under no lock (atomics) and is harmless if counters absent (emit zeros).
      - Tests: unit (counter incr + exposition format round-trip / label escaping). Runtime TEST 21: drive a few allow + a block + a bot-hit through real locations, GET /sentinel-status, assert `requests_total`>0, `verdict_total{v="block"}`>=1, `signal_total{s="bot"}`>=1. README "Prometheus metrics" section (location recipe + allow/deny + the metric list). CARE: label string-escaping (verdict/signal names are static so low risk), and tarpit_active must SUM the per-worker array not read [0].
- [x] `[opus]` **ops: Redis multi-box shared ban state** — DONE PR #25, master f1dd301 2026-06-25 (async hiredis, pull+push, mirror-crowdsec-node, event-loop adapter; libhiredis via ${shlibs:Depends}). Original locked spec:
      - **Pull + push both** + **hiredis async** (`-lhiredis`, add debian/control Depends) + **mirror CrowdSec node** (pulled ban → cs shm shape → existing w_crowdsec tier; no new weight/zone).
      - **Hard rule: NO sync net in request path.** All Redis I/O on a WORKER timer (not master) + async hiredis attached to nginx's event loop.
      - **PULL:** worker timer every N sec → scan shared ban keys (`SCAN`/`SMEMBERS`) → upsert into the crowdsec shm zone (reuse `sentinel_shm_softban_set`-style writer w/ cs_action+blocked_until+TTL). Request path reads shm only — unchanged/fast.
      - **PUSH:** when THIS box decides a BLOCK (errrate/local), queue the IP in a small shm ring; timer flushes via async `SET sentinel:ban:<ip> <action> EX <ttl>` (fire-and-forget). **Ban-loop guard:** tag pushed bans so a PULLED ban is NOT re-pushed (e.g. only push locally-originated decisions; skip keys already in shm-from-pull).
      - **hiredis↔nginx event adapter** is the hard part (non-trivial): write `redisAsyncContext` callbacks bound to `ngx_connection`/`ngx_event` (addRead/addWrite/cleanup), reconnect-on-drop w/ backoff, fail-OPEN if Redis unreachable (local decisions still work). One worker owns the connection (or per-worker — decide at build; per-worker simpler, N conns).
      - Dirs: `sentinel_redis <host:port>;` (enable+bind) `sentinel_redis_interval S;` `sentinel_redis_ttl S;` `sentinel_redis_prefix <s>;` (optional auth `sentinel_redis_password`). New `src/sentinel_redis.c` + config + build-test strict list + `-lhiredis` in config.
      - Tests: unit (RESP encode/parse round-trip if hand-rolled bits; ban-loop guard logic). Runtime TEST 20: stand up a local redis (or a mock RESP server), push a ban from box A's path, assert it lands in shm on the next pull tick → blocks. CARE: security-core + net + event-loop → Codex/Opus audit mandatory before merge.
      - **Size: multi-hour, multi-file. Start in a FRESH chat w/ full budget — do NOT begin near a grind soft-stop.**

## Deprecation — standalone error-abuse
- [ ] after sentinel error-rate signal proven in prod: announce deprecation,
      migrate configs, drop `libnginx-mod-error-abuse` from build. Track in
      error-abuse repo issues + sentinel HANDOFF.

## CI / valgrind / fuzz (Phase 1 sets up; all phases extend)
- [ ] `[sonnet]` `.github/workflows`: build-test, codeql, security-scanners (copy autocert/error-abuse)
- [ ] `[sonnet]` valgrind + fuzz workflows = `workflow_dispatch` (manual) + `schedule` **monthly** (remote)
- [ ] `[sonnet]` local CI script (`tools/ci-build.sh` + `test_runtime.py` + asan) — run before EVERY dev commit
- [ ] `[sonnet]` host cron: local valgrind **weekly** + longer soak session; mirror builder02 fuzz/valgrind/soak pattern → mail failures. Add to `host-config/crontabs/`.
- [ ] test every fn + every bug we hit = a t/ test in same commit

## Packaging / cross-cutting
- [ ] `[sonnet]` add `.github/workflows` — see CI section above
- [ ] `[sonnet]` add to `/opt/packages/modules/nginx/` + enable via `/nginx-modules-enable` → `libnginx-mod-sentinel`
- [ ] `[sonnet]` `/nginx-modules-synopsis` after merge — public page
- [ ] README cross-links to siblings + stack pages

## Token economy
- Recon = 1 compressed investigator
- ~70% of code (boilerplate, JA4H, keyval glue, packaging, CI) = sonnet
- opus only: score core, tarpit resource model, shmem concurrency, crowdsec design (~4 touches)
- audits = Codex (read-heavy, off main context)
- one isolated PR per phase = small diffs, cheap reviews
