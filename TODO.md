# TODO — ngx_http_sentinel_module

Phased build plan. Each phase = own PR + CI-green + merge before next. Tier tag
`[haiku|sonnet|opus-low|opus|codex]` = cheapest model that does the step. Design
+ safety rules: [DESIGN.md](DESIGN.md).

## Phase 0 — Recon `[haiku/sonnet, investigator]`
Compressed file:line map, no fixes. One agent.
- [ ] ssl-fingerprint: exact JA4 var name(s) + export mechanism
- [ ] keyval: lookup C API + zone declaration shape
- [ ] bot-verifier + user-agent: vars/flags to read for score
- [ ] js-challenge: how to hand a request off (redirect / named loc / var)
- [ ] error-abuse: tarpit/drip prior-art + CI harness files to copy
- [ ] output = integration map → Phase 1 spec

## Phase 1 — Skeleton + score + decide `PR #1`
Static data only (ja4 blocklist file + keyval zone). Verdict = allow / 403 / challenge. No tarpit, no live CrowdSec.
- [ ] `[sonnet]` `config` addon + `src/ngx_http_sentinel_module.c` skeleton
- [ ] `[sonnet]` PREACCESS handler, conf create/merge, var registration
- [ ] `[sonnet]` directives: `sentinel`, `sentinel_zone`, `sentinel_ja4_blocklist`, `sentinel_fail`, `sentinel_threshold`
- [ ] `[sonnet]` JA4H compute from headers → `$sentinel_ja4h` (fixed buffers, no malloc)
- [ ] `[sonnet]` shmem ban/score table: rbtree+slab, TTL/LRU bound, locked
- [ ] `[opus-low]` score combine + action dispatch + fail-open path (security core)
- [ ] `[sonnet]` vars `$sentinel_score $sentinel_verdict`
- [ ] `[sonnet]` CI harness (copy error-abuse): ci-build + test_runtime + valgrind/asan/codeql; test every fn
- [ ] `[codex]` audit Phase 1
- [ ] `[opus-low]` fix findings → PR #1 → CI green → merge

## Phase 2 — Tarpit action `PR #2`
Highest self-DoS risk → opus owns resource model.
- [ ] `[opus]` design tarpit resource model (conn cap, timers, fixed buf, max lifetime) — spec first
- [ ] `[sonnet]` implement drip to spec: content handler, ngx_add_timer, small writes, decrement on every exit
- [ ] `[sonnet]` directives `sentinel_tarpit_max_conns/delay/bytes`; wire verdict=tarpit
- [ ] `[sonnet]` CI: conn-cap enforced, no FD/mem leak under flood, abort/timeout paths (valgrind+asan)
- [ ] `[codex]` audit leak/DoS surface
- [ ] `[opus]` review concurrency → PR #2 → CI green → merge

## Phase 3 — CrowdSec live feed `PR #3`
Out-of-band sync; request path untouched.
- [ ] `[opus-low]` confirm feed path: lua bouncer stream → keyval → module (recommended) vs native client (defer)
- [ ] `[sonnet]` consume decisions from keyval/file into ban table; honor feed TTL
- [ ] `[sonnet]` key by ip + ja4; decision delete = entry removal
- [ ] `[sonnet]` CI: feed-update reflected, expiry honored, malformed feed → fail-open + log
- [ ] `[codex]` audit
- [ ] `[opus-low]` fixes → PR #3 → CI green → merge

## Phase 4 — JA4T (optional, defer) `PR #4`
- [ ] `[opus-low]` proxy_protocol v2 TLV → JA4T var → score. Only if traffic shows JA4/JA4H evasion.

## Packaging / cross-cutting
- [ ] `[sonnet]` add `.github/workflows` (copy autocert: build-test, codeql, fuzzing, security-scanners, valgrind)
- [ ] `[sonnet]` add to `/opt/packages/modules/nginx/` + enable via `/nginx-modules-enable` → `libnginx-mod-sentinel`
- [ ] `[sonnet]` `/nginx-modules-synopsis` after merge — public page
- [ ] README cross-links to siblings + stack pages

## Token economy
- Recon = 1 compressed investigator
- ~70% of code (boilerplate, JA4H, keyval glue, packaging, CI) = sonnet
- opus only: score core, tarpit resource model, shmem concurrency, crowdsec design (~4 touches)
- audits = Codex (read-heavy, off main context)
- one isolated PR per phase = small diffs, cheap reviews
