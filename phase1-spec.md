# Phase 1 spec — ngx_http_sentinel_module skeleton

Build spec for the Phase 1 skeleton. Self-contained, ZERO core nginx patch.
Read DESIGN.md (locked decisions + safety rules) first — this spec is the
buildable subset. JA4 (TLS) is OUT (Phase 4). JA4H (HTTP header order) is IN.

## Goal of Phase 1

A compilable, loadable dynamic HTTP module that:
- Registers at `NGX_HTTP_PREACCESS_PHASE`.
- Computes a JA4H hash + an error-rate signal + a bot-UA signal in-module.
- Combines them into `$sentinel_score` via a weighted sum (score core is a
  STUB returning 0 in this commit — opus-low fills it next commit).
- Exports `$sentinel_score`, `$sentinel_verdict`, `$sentinel_ja4h`.
- Runs in **shadow mode** by default (compute + log, enforce nothing).
- Fail-open everywhere.
- Builds clean + passes a local CI harness copied from nginx-error-abuse-module.

## Files to create (mirror error-abuse / autocert split style)

```
config                       # nginx addon; HTTP module (NOT filter); NO hiredis libs
src/ngx_http_sentinel_module.c   # core: main/srv/loc conf, PREACCESS handler, vars, directives
src/sentinel.h                   # shared structs, signal-fn prototypes, score-input struct
src/sentinel_ja4h.c              # JA4H from request headers (header order + method/ver/cookie/referer/accept-lang)
src/sentinel_errrate.c           # error-burst sliding counter (absorbed from error-abuse, hiredis STRIPPED)
src/sentinel_botua.c             # UA bot heuristics (static substring table, no regex)
src/sentinel_shm.c               # rbtree + slab + LRU + TTL shmem zone (prior-art: error-abuse init_zone/rbtree_insert)
src/sentinel_score.c             # STUB: ngx_int_t sentinel_score_compute(...) returns 0 + TODO marker
tools/ci-build.sh                # copy+adapt from error-abuse
tools/test_runtime.py            # copy+adapt
tools/valgrind.supp              # copy
.github/workflows/build-test.yml # copy+adapt (module name)
.github/workflows/codeql.yml     # copy+adapt
.github/workflows/valgrind.yml   # copy+adapt: workflow_dispatch + monthly schedule ONLY
.github/workflows/fuzzing.yml    # copy+adapt: workflow_dispatch + monthly schedule ONLY
.github/workflows/security-scanners.yml
t/basic.t                        # load module, shadow-mode request, assert vars set, assert allow
```

## config

```
ngx_addon_name=ngx_http_sentinel_module
ngx_module_type=HTTP
ngx_module_name=ngx_http_sentinel_module
ngx_module_srcs="$ngx_addon_dir/src/ngx_http_sentinel_module.c \
                 $ngx_addon_dir/src/sentinel_ja4h.c \
                 $ngx_addon_dir/src/sentinel_errrate.c \
                 $ngx_addon_dir/src/sentinel_botua.c \
                 $ngx_addon_dir/src/sentinel_shm.c \
                 $ngx_addon_dir/src/sentinel_score.c"
ngx_module_libs="-lcrypto"
. auto/module
```
NO hiredis. NO ssl async. `-lcrypto` only (SHA-256 for JA4H + identity digest).

## Directives (Phase 1 subset of DESIGN target)

- `sentinel on|off;` (loc, default off)
- `sentinel_mode shadow|enforce;` (loc, default shadow)
- `sentinel_zone name:size;` (main — shared-mem score/ban table)
- `sentinel_fail open|closed;` (loc, default open)
- `sentinel_threshold challenge=N tarpit=M block=K;` (loc — parsed + stored; verdict mapping wired, enforcement deferred)

Tarpit/crowdsec/ja4_blocklist directives = Phase 2/3/4 — do NOT add yet.

## Exported variables

- `$sentinel_score` — int, from score core (0 in stub)
- `$sentinel_verdict` — allow|challenge|tarpit|block (always "allow" while score=0)
- `$sentinel_ja4h` — computed JA4H hash hex string

## Handler flow (PREACCESS)

1. If `sentinel off` → `NGX_DECLINED`.
2. Gather signal inputs into a `sentinel_inputs_t` (pool-allocated):
   - JA4H hash (sentinel_ja4h.c)
   - error-rate burst count for identity (sentinel_errrate.c, shmem lookup)
   - bot-UA signal (sentinel_botua.c)
3. `score = sentinel_score_compute(inputs, weights)` — STUB returns 0.
4. Map score → verdict via thresholds.
5. Set the 3 variables (lazy via get_handler is fine, but cache the computed
   values on the request ctx so each is computed once).
6. **Shadow mode**: log `score/verdict/ja4h` at `info`, return `NGX_DECLINED`
   (allow). **Enforce mode**: Phase 1 still returns `NGX_DECLINED` for every
   verdict EXCEPT a future block — leave a clearly-marked TODO where enforce
   dispatch will go. Do NOT implement tarpit/challenge/block bodies yet.

## Safety (CI-enforced — from DESIGN)

- No `malloc` in hot path — request pool + fixed stack buffers only.
- Every shmem access under zone lock; entries TTL/LRU-bounded.
- No network I/O in request path (none in Phase 1 at all).
- No regex anywhere.
- Fail-open: any error (zone full, lock issue, malformed) → log + `NGX_DECLINED`.

## sentinel_errrate.c — absorption notes

Port the sliding-window circular-buffer counter from
`nginx-error-abuse-module/ngx_http_error_abuse_module.c`
(`ngx_http_error_abuse_record` ~:636, status-bitfield ~:998,
`init_zone` ~:1186, `rbtree_insert` ~:1111). STRIP: all hiredis/Redis,
async, TLS, file-snapshot, thread-pool code. KEEP: the in-process shmem
sliding counter + status-bitfield match. Identity = SHA-256 digest of
`$binary_remote_addr` (bounded, like error-abuse SEC-3). This is a SCORE
INPUT (returns a burst count / boolean), not an enforcing filter.

NEW code (not in error-abuse): static scanner-path prefix match —
`.env`, `.git`, `wp-login`, `wp-admin`, `.aws`, `phpinfo` — plain prefix /
fixed-string compare, NO regex. Returns a boolean signal.

## sentinel_ja4h.c notes

Compute JA4H per the public JA4H spec from the parsed request:
method + HTTP version + presence of cookie + presence of referer + count of
headers + sorted header-name list + accept-language. SHA-256 the canonical
string, hex the first 12 bytes (match JA4H truncation convention). All inputs
from `r->headers_in` — pure HTTP, no TLS. Fixed stack buffer for the canonical
string; bail to a zero/empty hash on overflow (fail-open).

## CI harness

Copy error-abuse `tools/` + `.github/workflows/`, adapt module name + paths.
build-test/codeql/security-scanners run on push/PR. valgrind + fuzzing =
`workflow_dispatch` + monthly `schedule` ONLY (per workflow.md — never on every
dev PR). `t/basic.t` must load the .so, issue a request with `sentinel on;
sentinel_mode shadow;`, and assert the 3 variables are populated + response is
the normal upstream/200 (shadow enforces nothing).

## Out of scope (later phases — do NOT build)

JA4 TLS parse + core patch (Phase 4) · tarpit bodies (Phase 2) · crowdsec feed
loader (Phase 3) · bot-verifier forward-confirm (Phase 3) · js-challenge bridge
(Phase 2) · real score weights (next commit, opus-low).
