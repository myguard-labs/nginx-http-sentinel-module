# Phase 2 — Tarpit Action Spec (ngx_http_sentinel_module)

Spec only, no code. Implements `NGX_SENTINEL_VERDICT_TARPIT` enforcement.
This is the highest self-DoS-risk feature; every rule below is a hard
invariant. Target file: `src/sentinel_tarpit.c` (+ `sentinel.h` additions).

Prior art read: `nginx-error-abuse-module` (STAB-1 duration cap, `ngx_add_timer`
patterns), `http-js-challenge` (synthetic-body hold). Tarpit differs: it *drips*
a body over time instead of sending one shot.

## 0. Core invariant

A tarpitted connection holds a worker connection + an FD for its lifetime. The
ONLY thing that bounds self-resource-use is the global connection cap. Therefore:

> Increment the global counter at tarpit entry, register the decrement in a
> pool/connection cleanup at the *same instant*, and never decrement anywhere
> else. The counter's correctness depends on exactly one increment paired with
> exactly one cleanup-driven decrement per tarpitted connection.

---

## 1. Connection accounting

### Where the counter lives
A dedicated `ngx_atomic_t` (NOT inside the rbtree zone — the score/ban zone is
LRU-evicted and per-identity; the tarpit counter is a single process-wide
scalar and must never be evicted or slab-freed). Placement:

- Allocate one `ngx_atomic_t tarpit_conns` in a tiny dedicated shared-memory
  segment owned by the module (its own `ngx_shared_memory_add` of a fixed small
  size, init sets `*tarpit_conns = 0`). Shared so the cap is **global across all
  worker processes**, not per-worker.
- Store the pointer on `ngx_sentinel_main_conf_t` (e.g. `ngx_atomic_t
  *tarpit_conns`) so handlers reach it without a zone lookup.
- Use atomic ops (`ngx_atomic_fetch_add`, `ngx_atomic_cmp_set`) — NOT the slab
  mutex. The counter is a lock-free hot value; never take a zone lock for it.

### Entry (increment) — reserve-then-commit
At tarpit dispatch, atomically claim a slot with a CAS loop that also enforces
the cap (single op, no TOCTOU):

```
loop:
  cur = *tarpit_conns
  if (cur >= max_conns)  -> AT CAP: do not increment, fall back (see below)
  if (ngx_atomic_cmp_set(tarpit_conns, cur, cur+1)) -> reserved, proceed
  else goto loop   (another worker raced; retry)
```

The CAS guarantees increment and cap-check are one decision — no separate
"check then add" window where two workers both pass the check.

### Cleanup (decrement) — the ONLY decrement site
Immediately after a successful reserve, register an `ngx_pool_cleanup_t` on
**`r->pool`** (request pool; freed when the request finalizes for any reason)
whose handler does `ngx_atomic_fetch_add(tarpit_conns, -1)` exactly once.

- Guard with a flag in the tarpit context (`unsigned counted:1`) so the cleanup
  is idempotent: decrement only if `counted`, then clear `counted`. Belt-and-
  suspenders against a double-fire.
- The cleanup is registered *before* arming the first timer, so even if timer
  setup fails the slot is still released.
- Request-pool cleanup fires on **every** request teardown path nginx has,
  which is what makes the decrement unskippable.

### Every exit path (all funnel through the one cleanup)
| Exit path | Mechanism that triggers the decrement |
|-----------|----------------------------------------|
| Drip complete (full `tarpit_bytes` sent, then `ngx_http_finalize_request`) | finalize frees `r->pool` → cleanup fires |
| Client abort / RST (`c->error`, `c->write->error`, eof) | drip write/timer detects, calls finalize → pool cleanup |
| Write error (`ngx_http_output_filter` returns NGX_ERROR) | finalize(NGX_ERROR) → pool cleanup |
| Timer / max-lifetime expiry | lifetime timer fires → finalize → pool cleanup |
| Keepalive/normal connection close before finalize | request pool still owned by request → cleanup fires at request teardown |
| Worker process exit / crash / reload | OS reclaims the worker's connections + the worker's shared counter contribution must be reconciled (see Worker-exit reconciliation) |

### Worker-exit reconciliation (the one path a pool cleanup can't cover)
If a worker is `SIGKILL`ed mid-tarpit, its `r->pool` cleanups never run, so its
in-flight increments leak into the *shared* counter and would permanently shrink
capacity. Mitigation (pick: **per-worker sub-counter, summed**):

- Keep the global cap check against a **sum of per-worker atomic sub-counters**
  laid out in the shared segment, indexed by `ngx_worker` (`ngx_atomic_t
  tarpit_conns[NGX_MAX_PROCESSES]` or sized to `worker_processes`).
- Entry increments `slot[ngx_worker]`; cleanup decrements `slot[ngx_worker]`.
  Cap check sums all slots (cheap: bounded small N, read-only).
- On worker init (`init_process`), the (re)started worker **zeroes its own
  slot** — reclaiming any stranded count from a previous incarnation that died
  hard. This makes a killed worker's leak self-healing on respawn instead of
  permanent.

### At cap → fall back to immediate block (444), do NOT queue
When the reserve loop sees `cur >= max_conns`:
- Verdict downgrades to an **immediate close: HTTP 444** (`return
  NGX_HTTP_CLOSE` / `ngx_http_finalize_request(r, NGX_HTTP_CLOSE)`).
- Justification: the tarpit exists to consume the *attacker's* resources at
  near-zero cost to us. Once we're at the self-imposed cap, holding one more
  slow connection costs *us* an FD with zero marginal benefit. Queuing (timer to
  retry the slot) is strictly worse — it holds the connection AND a timer while
  contributing nothing, and a flood would just fill the queue: a second
  unbounded resource. 444 (raw close, no response bytes) is the cheapest
  possible disposal and denies the attacker even an error page. Log at INFO:
  `tarpit at cap (N/N) -> 444`.

---

## 2. Drip mechanics

### Handler placement
Dispatch from the PREACCESS handler: on `verdict==TARPIT` in enforce mode, set
up the tarpit and return `NGX_DONE` (we take ownership of the connection;
nginx will not run later phases). The drip itself runs as a **content-less,
timer-driven writer**, not a content handler — we never produce a real response,
we emit a synthetic trickle then close.

Sequence at dispatch:
1. Reserve slot (§1). At cap → 444, done.
2. Allocate tarpit ctx from `r->pool` (one `ngx_pcalloc`, config-time-bounded,
   **not** per-tick — see no-malloc rule). Stash byte budget, deadline, flags.
3. Register pool cleanup (decrement).
4. Send response headers once: status `200`, `Content-Type: text/plain`,
   **no `Content-Length`** (chunked / unbounded so the client keeps waiting),
   `Connection: close`. `r->keepalive = 0`.
5. Compute `deadline = ngx_current_msec + max_lifetime_ms`.
6. Set `r->write_event_handler` to the drip handler and arm the first
   `ngx_add_timer(c->write, delay_ms)`. Also arm a separate **lifetime guard
   timer** OR check the deadline at the top of every tick (latter is simpler,
   one timer — preferred).
7. `r->main->count++` to hold the request alive across timer ticks.

### Per tick (the drip handler)
- **Deadline check first:** if `ngx_current_msec >= deadline` OR total bytes
  sent `>= tarpit_bytes` (total cap) → finalize (NGX_DONE/NGX_HTTP_CLOSE) →
  pool cleanup decrements. Done.
- **Connection-dead check:** if `c->error || c->write->error || c->close` →
  finalize. (Client abort lands here.)
- Build an `ngx_buf_t` pointing at a **fixed, preallocated static byte buffer**
  (module-global `static u_char drip_buf[NGX_SENTINEL_TARPIT_TICK_MAX]`, filled
  once at module load with innocuous filler, e.g. spaces/newlines). Each tick
  emits `min(tarpit_tick_bytes, remaining_budget)` bytes from it. **No malloc,
  no per-tick allocation** — the buf struct is a single field reused in the ctx,
  repointed each tick.
- `rc = ngx_http_output_filter(r, &out_chain)`:
  - `NGX_OK` → bytes accounted; `ngx_add_timer(c->write, delay_ms)`; return.
  - `NGX_AGAIN` → socket buffer full (good — attacker is slow). Do **not**
    busy-loop: leave the write event registered, let nginx re-invoke the write
    handler on writability, and (re)arm the deadline. Account only bytes the
    filter actually consumed. Non-blocking only; never block the worker.
  - `NGX_ERROR` → finalize(NGX_ERROR) → cleanup.
- Update `bytes_sent`. Never grow any buffer.

### No-malloc / fixed-buffer guarantees
- One ctx alloc at entry; zero allocs per tick.
- One process-global static drip buffer shared read-only by all tarpit
  connections (it's filler — no per-connection content).
- Output chain `ngx_buf_t` + `ngx_chain_t` live in the ctx, reused each tick.

---

## 3. Directives (defaults + bounds)

All in `NGX_HTTP_LOC_CONF`, merged like existing sentinel directives
(`NGX_CONF_UNSET` → merge default).

| Directive | Type | Default | Lower bound | Upper bound (overflow guard) | Notes |
|-----------|------|---------|-------------|------------------------------|-------|
| `sentinel_tarpit_max_conns N` | num | `256` | `0` (0 = tarpit disabled, downgrade all TARPIT to 444) | `65536` | Global across workers. Conservative: 256 slow FDs is negligible vs a sized worker_connections. |
| `sentinel_tarpit_delay ms` | msec | `5000` (5s) | `100` (reject sub-100ms — avoids busy ticking that costs *us* CPU) | `60000` (60s) | Interval between ticks. |
| `sentinel_tarpit_bytes N` | size | `1024` | `1` | `65536` (and `<= NGX_SENTINEL_TARPIT_TICK_MAX` static buf, also 65536) | TOTAL bytes dripped over the connection's life (cumulative cap), not per tick. Per-tick send = `min(tick_bytes_const, remaining)`; a small per-tick const (e.g. 16–64 B) keeps each write tiny. |
| `sentinel_tarpit_max_lifetime ms` | msec | `30000` (30s) | `1000` | `600000` (10 min) | Hard ceiling; force-close after. Add this directive — DESIGN names "hard max lifetime" but no directive existed. |

Bounds rationale (mirrors error-abuse STAB-1): cap every duration so
`now + lifetime`, `delay * 1000`, and the byte budget cannot overflow
`ngx_msec_t` / `time_t` / size arithmetic on 32-bit. Reject out-of-range values
at config parse with `NGX_CONF_ERROR` (don't silently clamp config — clamp only
runtime-derived values). Define a single `#define
NGX_SENTINEL_TARPIT_MAX_MSEC 600000` and `NGX_SENTINEL_TARPIT_TICK_MAX 65536`
in `sentinel.h`.

---

## 4. Wiring

In `ngx_sentinel_preaccess_handler`, replace the `case
NGX_SENTINEL_VERDICT_TARPIT` TODO:

```
case NGX_SENTINEL_VERDICT_TARPIT:
    if (lcf->shadow)            -> log "would tarpit", return NGX_DECLINED;
    if (tarpit disabled / max_conns==0) -> log, fall back to block path;
    rc = sentinel_tarpit_start(r, lcf);
    if (rc == NGX_DONE)         -> return NGX_DONE;   // owns the connection
    if (rc == NGX_HTTP_CLOSE)   -> return NGX_HTTP_CLOSE; // at cap -> 444
    // any setup error:
    fail-open: log WARN, return NGX_DECLINED;   // allow, never 500 the client
```

- **Shadow mode:** compute + log `verdict=tarpit (would tarpit)` and
  `NGX_DECLINED`. Never reserve a slot, never arm a timer.
- **Enforce mode:** call `sentinel_tarpit_start()`.
- **Fail-open on setup error:** any failure *constructing* the tarpit (ctx
  alloc fail, header send fail, timer add fail) → release the reserved slot
  (the pool cleanup already handles it) → log → `NGX_DECLINED` (allow). A
  broken tarpit must never become a 500 storm or a hung request. (If
  `sentinel_fail closed` is set, a setup error may instead 444 — honor the
  existing fail_open flag; default open.)
- `sentinel_tarpit_start` returns: `NGX_DONE` (running), `NGX_HTTP_CLOSE` (at
  cap → caller 444s), `NGX_DECLINED`/`NGX_ERROR` (fail-open allow).

`sentinel.h` additions: `ngx_atomic_t *tarpit_conns` (+ size const) on main
conf; tarpit fields on loc conf (`tarpit_max_conns`, `tarpit_delay`,
`tarpit_bytes`, `tarpit_max_lifetime`); `ngx_sentinel_tarpit_ctx_t` (bytes_sent,
deadline, buf/chain, `counted:1`); prototype `ngx_int_t
sentinel_tarpit_start(ngx_http_request_t *r, ngx_sentinel_loc_conf_t *lcf)`.

---

## 5. CI tests (Phase 2 must add — same commit as the code)

Follow the workspace harness (ci-build.sh + test_runtime.py +
build-test/valgrind/codeql/asan), copying the error-abuse error/abuse harness
shape.

1. **conn-cap enforced under flood** (`test_runtime.py`)
   - Config `sentinel_tarpit_max_conns 4`, generous lifetime.
   - Open ~50 concurrent slow clients to a tarpit location (force verdict via a
     test stub that returns TARPIT, or a low threshold + bot UA).
   - Assert: at most 4 connections receive the dripping 200 (held open); the
     rest get an immediate connection close / 444 with zero body bytes. Count
     held vs closed.

2. **counter returns to zero — every exit path** (3 sub-cases)
   - Expose the counter via a debug/status location or a log line at each
     decrement (`tarpit_conns now=K`).
   - **(a) normal drip complete:** one client, small `tarpit_bytes`, let it
     finish → assert counter back to 0.
   - **(b) client abort:** open tarpit, hard-close the socket mid-drip → assert
     decrement fires, counter back to 0.
   - **(c) lifetime timeout:** `max_lifetime 1000ms`, client that never reads →
     assert force-close at ~1s and counter back to 0.
   - After all three sequentially: assert counter == 0 and a fresh tarpit can
     still get a slot (proves no leak shrank capacity).

3. **no FD / mem leak — valgrind + asan**
   - Run cases (a)/(b)/(c) under valgrind (`--leak-check=full
     --errors-for-leak-kinds=definite`) and an ASan build.
   - Assert: 0 definite leaks, 0 ASan reports. Watch the per-tick path
     specifically (no growth across N ticks → confirms fixed-buffer, no
     per-tick malloc). Optionally assert worker FD count returns to baseline
     after all clients close (`ls /proc/<pid>/fd | wc -l`).

4. **no malloc in hot path (static assert / review-gate)**
   - A grep/codeql check that the drip tick function contains no `ngx_palloc`/
     `ngx_pnalloc`/`malloc`/`ngx_create_temp_buf`. (Cheap structural guard.)

5. **shadow mode never tarpits**
   - `sentinel_mode shadow`, force TARPIT verdict → assert response is normal/
     fast, log shows "would tarpit", counter stays 0.

6. **fail-open on setup error** (fault-injection build flag)
   - Force ctx-alloc or header-send to fail → assert request is allowed
     (served normally), counter stays 0, no 500.

7. **bounds parsing** (config-load test)
   - `sentinel_tarpit_delay 50`, `..._max_lifetime 999999999`, etc. → assert
     nginx fails to start with a clear error (out-of-range rejected at parse).

---

## 6. Concurrency hazards & how the design defuses them

| Hazard | How it could happen | Defense |
|--------|---------------------|---------|
| **Counter race / cap overshoot** | Two workers both read `cur=255`, both add → 257 over a cap of 256 | Reserve via `ngx_atomic_cmp_set` CAS loop: check-and-increment is one atomic op; loser retries against the new value. Never "read, check, then add" as separate steps. |
| **Double-decrement** | Cleanup fires, then some other exit path also decrements → counter underflows below 0, fabricates free slots | Decrement lives in **exactly one place** (the pool cleanup) and is guarded by `counted:1` (decrement only if set, then clear). No drip/abort/error path touches the counter directly. |
| **Decrement without increment** | Cleanup registered before the reserve succeeded, or registered on a path that never reserved | Reserve **first**, register cleanup **second**, set `counted=1` only after a successful CAS. At-cap path returns before registering any cleanup. Cleanup no-ops when `counted==0`. |
| **Leak on hard worker kill** | `SIGKILL` skips pool cleanups → shared count permanently inflated | Per-worker sub-counters; respawned worker zeroes its own slot at `init_process` (§1 reconciliation). Self-healing, never permanent. |
| **Busy-tick CPU self-DoS** | Sub-100ms delay or NGX_AGAIN tight loop burns our CPU | `delay` lower-bounded at 100ms at parse; NGX_AGAIN waits on the write event (no re-arm/spin), never busy-loops. |
| **Unbounded body / buffer growth** | Per-tick allocation or growing buffer | Single fixed process-global static drip buffer + total `tarpit_bytes` cap + hard `max_lifetime`. Three independent ceilings (bytes, time, conns). |

The pool-cleanup-as-sole-decrement design is the linchpin: nginx guarantees
`r->pool` cleanups run on *every* request teardown it controls, so pairing the
increment with a cleanup registration makes the decrement structurally
unskippable — the only gap (SIGKILL) is closed by the per-worker
zero-on-respawn rule.
