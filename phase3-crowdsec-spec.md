# Phase 3 Spec — CrowdSec decision-feed consumption

`ngx_http_sentinel_module`. **Spec only — no code.** Implements DESIGN
decisions #1 (no network I/O in request path) and #6 (CrowdSec via
stream/out-of-band, not live LAPI). A sonnet should be able to build from this.

## 0. Scope & non-goals

- IN: out-of-band loader that reads a flat decision feed into a new
  shared-memory ban table, a request-path O(1) lookup that feeds a
  `crowdsec_hit` score input, directives, fail-open handling, CI tests.
- OUT (deferred, do NOT build): native async LAPI client, live HTTP query,
  CIDR/range matching beyond exact IP (Phase 3 keys exact `$binary_remote_addr`
  IPs only — see §1.4), ja4 keys (Phase 4), feedback push back to CrowdSec.

## 1. Feed file format

### 1.1 Decision: flat line-oriented text, NOT JSON in-module

CrowdSec LAPI / the lua bouncer emit JSON. **The module never parses JSON.**
DESIGN bans regex and heavy deps in any path and wants parse-cheap input. So:

- **A tiny external sidecar converts** the bouncer's JSON stream/poll output to
  the flat format below and writes it atomically (see §1.3). The sidecar is the
  existing CrowdSec lua bouncer in *stream mode* (already deployed) plus a ~30-
  line shell/lua/python emitter, OR a small standalone poller. The sidecar is
  out of scope for this module's source but its contract is fixed here.
- The module's loader does a **hand-rolled byte scan** of the flat file: split
  on `\n`, split each line on single spaces, `ngx_inet_addr` / `ngx_inet6_addr`
  for the IP, `ngx_atoi` for the epoch. No regex, no JSON, no allocator in the
  scan beyond the slab inserts.

Rationale: keeps the only attacker-influenceable-but-trusted input trivial to
parse; isolates JSON brittleness in a restartable userspace process; the feed
file is operator-controlled (root-written), not attacker-controlled.

### 1.2 Line grammar

```
# sentinel-crowdsec-feed v1               <- header line 1 (version sentinel)
# generated <iso8601> count=<N>           <- header line 2 (informational)
<ip> <action> <expiry-epoch>              <- one decision per line
...
%%EOF <N> <crc32hex>                       <- trailer (record count + checksum)
```

- `<ip>`     dotted IPv4 or canonical IPv6 text (exact host; see §1.4).
- `<action>` one token from the fixed set: `ban`, `captcha`, `throttle`.
  Unknown action ⇒ line skipped + logged (treated as malformed, §5).
- `<expiry-epoch>` absolute unix seconds when the decision expires. `0` ⇒ no
  expiry given; loader assigns `now + sentinel_crowdsec_default_ttl`.
- Blank lines and `#` lines ignored.

### 1.3 Truncation / partial-write detection

Two independent guards, BOTH required to accept a feed:

1. **Atomic rename by the writer.** Sidecar writes `feed.tmp` then
   `rename(2)` over `feed`. The loader therefore never sees a half-written
   file *in the common case*. (Contract on the sidecar, restated in directive
   docs.)
2. **Self-describing trailer** `%%EOF <N> <crc32hex>`. The loader counts the
   decision lines it parsed and CRC32s the decision-line bytes (the region
   between the header and the trailer). If line count != `<N>` or
   crc mismatch ⇒ **reject the whole file, keep the previous table, log**
   (fail-open, §5). This catches a truncated/torn read even if rename was not
   used, and catches sidecar bugs.

Mirrors the error-abuse snapshot self-check pattern (record-count + checksum
trailer). CRC32 via nginx's `ngx_crc32_*` — no new dep.

### 1.4 Key normalization

Phase 3 ban table is keyed identically to the errrate table: the key bytes are
`SHA-256(text-form-of-IP-as-the-request-sees-it)` so request path and loader
agree byte-for-byte. **Critical:** the loader must derive the same text the
request path uses (`r->connection->addr_text`). Loader parses the feed IP with
`ngx_inet_addr`/`ngx_inet6_addr` only to *validate* it, then re-renders it to
canonical text with `ngx_sock_ntop` and hashes that text, guaranteeing the two
sides produce the identical digest. CIDR/range decisions in the feed are
**skipped + logged** in Phase 3 (no range match in O(1) rbtree); the sidecar
SHOULD expand or drop ranges. Document this limitation.

## 2. Out-of-band loader

New file `src/sentinel_feed.c` (already named in DESIGN layout).

### 2.1 Separate shm zone & node type

The crowdsec ban table is a **separate** shm zone from `sentinel_zone`
(errrate). Reusing `ngx_sentinel_node_t` is fine — it already has
`blocked_until`, `last_seen`, rbtree+queue, key bytes. The crowdsec node uses
`blocked_until = expiry-epoch` and ignores the event ring (allocate with
`threshold = 0` event slots, i.e. node size = `sizeof + key_len`). Add a
`u_char action` byte to the node OR (preferred, avoids struct churn) store the
action in the existing struct by adding one field:

```
/* add to ngx_sentinel_node_t */
u_char  cs_action;   /* 0=none,1=ban,2=captcha,3=throttle (crowdsec table only) */
```

A new zone descriptor reuses `ngx_sentinel_zone_t` (its `block`/`interval`
fields are unused here; `threshold` set to 0 so node alloc adds no event ring).

### 2.2 Trigger: per-worker `ngx_event` timer

- Loader runs on an `ngx_event_t` timer added in `init_process` (one per
  worker), re-armed at the tail of each run with
  `ngx_add_timer(ev, refresh_interval_ms)`. NOT a request-path action, NOT a
  separate thread. Default interval 10s (§3).
- **mtime gate:** each tick `stat(2)`s the feed. If `st_mtime` unchanged since
  the last successful load ⇒ skip (no parse, no lock churn). Cheap idle path.
- Only the worker holding... — every worker loads independently into the shared
  zone; that is idempotent because the swap (§2.4) is a full replace under lock.
  To avoid N workers parsing the same file simultaneously, use a generation
  counter in shm: a worker that sees `sh->cs_generation` already advanced past
  the feed's mtime-derived stamp skips the parse. (Simple form acceptable for
  v1: let each worker load; document the redundancy as a known cost, capped by
  the mtime gate so it only happens once per feed change per worker.)

### 2.3 Reading without blocking the event loop

- **Size cap:** `sentinel_crowdsec_max_bytes` (default 16 MiB, hard ceiling
  64 MiB). If the file exceeds the cap ⇒ reject + log (fail-open). Prevents an
  oversized feed from stalling the worker.
- Read the whole file with a single `ngx_read_file` into a **temporary buffer
  from a transient pool** (NOT the request pool, NOT shm — a
  `ngx_create_pool` owned by the loader, destroyed at end of tick). This is
  out-of-band, so a transient malloc-backed pool is allowed (DESIGN bans malloc
  only in the *request* path).
- **Chunked parse with a yield budget:** parse in a loop; after every
  `NGX_SENTINEL_FEED_PARSE_BATCH` (e.g. 4096) lines, if elapsed wall time on
  this tick exceeds a soft budget (e.g. 20ms), **re-arm the timer for 0ms and
  resume** — carry parse offset + a half-built staging table in the loader
  ctx. Keeps a 16 MiB feed from monopolizing the loop. (If implementer prefers
  simplicity for v1: a single-pass parse is acceptable provided the size cap is
  enforced and the cap is documented as the latency bound; the chunked resume is
  the preferred form and the spec-of-record.)

### 2.4 Full reload, swap, deletions

- Parse builds into a **staging structure first** (validate trailer/crc BEFORE
  touching shm — never mutate the live table from an unverified file).
- On a verified feed: take the zone lock and **full-replace**:
  - Mark+sweep is the swap strategy. Bump `sh->cs_generation`. Stamp every
    inserted/updated node with the new generation. After insert pass, walk the
    LRU queue and **delete any node whose generation != current** — these are
    keys absent from the new feed ⇒ removed upstream ⇒ shm entry removed
    (satisfies the "deletion removes the entry" requirement).
  - For each feed line: lookup; if present, update `blocked_until`=expiry,
    `cs_action`, stamp generation, touch LRU; if absent, create node. Skip
    lines whose expiry <= now (already expired ⇒ effectively a deletion).
- **TTL sweep is the backstop:** the request-path lookup (and the loader)
  treats `blocked_until <= now` as not-banned and the existing
  `sentinel_shm_expire` LRU/TTL eviction removes stale nodes even if a feed
  never arrives again. The crowdsec table's `interval` for LRU age-out =
  `sentinel_crowdsec_stale_after` so abandoned entries don't pin memory.
- **Bounded memory:** same slab zone + LRU/TTL as errrate. On `slab` full
  during insert ⇒ stop inserting, keep what fit, log "crowdsec zone full,
  partial load" (fail-open: a partial ban table still bans some, blocks none
  wrongly). Sizing guidance in directive docs (≈ feed entries × node size).

### 2.5 Generation counter location

Add `ngx_uint_t cs_generation;` to `ngx_sentinel_shctx_t` (shared, bumped under
lock). Add the `cs_generation` field per node (reuse the struct; non-crowdsec
zones leave it 0).

## 3. Directives

All in `ngx_http_sentinel_module.c` conf parsing. Defaults safe, bounds
enforced at parse time (reject config out of range — config-time error is fine,
it is not the request path).

```
sentinel_crowdsec_zone        name;        # http{} — declares the crowdsec shm
                                           # zone; ties a sentinel{} block to it.
                                           # Reuses sentinel_zone size syntax:
                                           #   sentinel_crowdsec_zone cs:8m;
sentinel_crowdsec_feed        path;        # location/server — feed file path.
                                           # default: none (feature off if unset)
sentinel_crowdsec_interval    time;        # refresh tick. default 10s,
                                           # min 1s, max 3600s.
sentinel_crowdsec_default_ttl time;        # TTL for expiry==0 lines.
                                           # default 3600s, min 60s, max 86400s.
sentinel_crowdsec_stale_after time;        # feed-age threshold => stale (§5)
                                           # AND LRU age-out. default 600s,
                                           # min 30s, max 86400s.
sentinel_crowdsec_max_bytes   size;        # feed size cap. default 16m,
                                           # max 64m.
sentinel_weight_crowdsec      number;      # score weight for a crowdsec hit.
                                           # default: see §4. min 0,
                                           # max NGX_SENTINEL_SCORE_MAX.
```

Add corresponding `#define NGX_SENTINEL_CROWDSEC_DEFAULT_*` to `sentinel.h`
alongside the existing default block. `sentinel_crowdsec_zone` is declared like
`sentinel_zone` (creates the shm zone via `ngx_shared_memory_add` with
`sentinel_shm_init_zone`); the loc-conf gets a `ngx_sentinel_zone_t *cs_zone;`
pointer mirroring `zone`.

## 4. Request-path read & scoring

### 4.1 Lookup

In the PREACCESS handler / `sentinel_*_signal` collection, add
`sentinel_crowdsec_signal(r, lcf, inputs)` in a new path inside
`sentinel_feed.c` (read side) or `sentinel_crowdsec.c`. It:

1. Builds the identity digest exactly as `sentinel_errrate_signal` does
   (`SHA-256(addr_text)`), reusing the same helper (factor it out if needed).
2. New shm read fn `sentinel_shm_crowdsec_lookup(cs_zone, key, now,
   &action)` — O(1) rbtree lookup under `cs_zone->shpool->mutex`. Returns
   `NGX_BUSY` + `action` if a node exists with `blocked_until > now`;
   `NGX_OK` (no hit) otherwise; `NGX_ERROR` on zone error. Mirrors
   `sentinel_shm_errrate_lookup`'s lock discipline; **read-only** (it may touch
   LRU + run `sentinel_shm_expire` like errrate does, all under the same lock).

### 4.2 New input field + weight

Add to `ngx_sentinel_inputs_t`:
```
ngx_flag_t  crowdsec_hit;     /* IP present + unexpired in crowdsec table */
u_char      crowdsec_action;  /* 0/ban/captcha/throttle, for verdict mapping */
```
Add to `ngx_sentinel_weights_t`:
```
ngx_int_t  crowdsec;   /* added once if crowdsec_hit (sentinel_weight_crowdsec) */
```
`sentinel_score_compute` adds `+= weights.crowdsec` when `inputs->crowdsec_hit`.
Matches the existing weighted-sum pattern (DESIGN `w_crowdsec·hit`).

### 4.3 Ban vs score — decision: HIGH weight, action-tiered, NOT a hard block

A crowdsec decision routes through the **same score→verdict pipeline**, not a
bypass. Justification: keeps shadow mode honest (crowdsec hits are logged, not
enforced, until thresholds are tuned), keeps the allowlist short-circuit
authoritative, and keeps one auditable verdict path.

- **Default `sentinel_weight_crowdsec` = 100** (== `NGX_SENTINEL_DEFAULT_W_BLOCKED`):
  high enough that a `ban` action alone clears the default block threshold (80),
  so a crowdsec `ban` ⇒ `block` verdict in practice — but it is still a score,
  still subject to shadow mode and the allowlist.
- **Action tiering:** map `crowdsec_action` so weaker actions cost less:
  `ban` ⇒ full `weight_crowdsec`; `captcha` ⇒ enough to reach the *challenge*
  band but not block (e.g. weight scaled to challenge threshold); `throttle` ⇒
  challenge/tarpit band. Implementation: store action, and in
  `sentinel_score_compute` add `weight_crowdsec` for `ban`, a reduced fraction
  for `captcha`/`throttle` (document the exact fractions; keep arithmetic, no
  table lookups in hot path beyond a switch).

### 4.4 Allowlist interaction

`inputs->known_good_ua` (forward-confirmed search engine) **still
short-circuits to score 0** in `sentinel_score_compute` — unchanged. Rationale:
a misattributed crowdsec ban on a Googlebot IP must not deindex the site;
forward-confirmed verification is stronger evidence than a community blocklist.
Document this explicitly; it is intentional and safe (a verified Googlebot is
not the threat crowdsec guards against). The `crowdsec_hit` is still logged in
shadow/decision log even when short-circuited, so operators can see the
conflict.

## 5. Failure modes — all fail-open

Every one logs (rate-limited where it can spam) and continues serving. The
request path NEVER blocks/crashes on feed problems; worst case the crowdsec
signal contributes 0.

| Condition | Detection | Behavior |
|---|---|---|
| Feed file missing / unreadable | `stat`/`open` fails in loader | keep previous table; log WARN once per transition; request path keeps using last-good table (or empty if never loaded) |
| Malformed line (bad IP/action/epoch/field count) | per-line parse fail | skip that line, count it; if malformed-fraction < threshold accept rest, else reject whole file (treat as torn); log count |
| Trailer/CRC mismatch or count mismatch | §1.3 check | reject whole file, keep previous table, log WARN |
| Partial write | rename contract + trailer | as above (trailer catch) |
| Oversized feed (> max_bytes) | size check before read | reject, log WARN |
| Stale feed (sidecar dead) | feed `st_mtime` older than `now - sentinel_crowdsec_stale_after` | log WARN once per transition; **keep serving with existing entries but begin TTL/LRU age-out** so entries expire naturally; do NOT wipe (a dead sidecar must not instantly unban everyone, nor must it freeze bans forever — natural per-entry expiry handles both). Optionally expose staleness in decision log. |
| Zone full on load | slab alloc fail | partial load, log WARN |
| Request-path zone error | lookup returns NGX_ERROR | `crowdsec_hit=0`, log WARN (fail-open), score unaffected |

Stale detection is **mtime-age**, evaluated in the loader tick and on demand.
DESIGN rule #4 (`sentinel_fail closed;`) still applies globally: in closed mode
a *zone error* may escalate per existing policy, but a missing/stale **feed**
remains fail-open by design (an absent community blocklist is not grounds to
block legitimate traffic) — state this explicitly.

## 6. CI tests (Phase 3 must add, same commit as code)

Per DESIGN safety rule + repo policy (every feature gets a CI test:
build-test + valgrind + asan + codeql; fuzz the parser since the feed is
semi-trusted input). Add to the existing `test_runtime.py` / `ci-build.sh`
harness.

1. **feed-update-reflected:** write a feed with IP X `ban` future-expiry,
   trigger a load (touch mtime + wait > interval, or test hook), send a request
   from X ⇒ assert `$sentinel_score` includes the crowdsec weight and (enforce
   mode) verdict == block. Then rewrite feed WITHOUT X, reload, request from X
   ⇒ assert score back to baseline (entry deleted — verifies §2.4 mark/sweep).
2. **expiry honored:** feed with IP X `ban` expiry = now+2s; request now ⇒ hit;
   wait > 2s; request ⇒ no hit (verifies `blocked_until <= now` path and TTL).
3. **deletion honored:** covered by test 1's second half; add an explicit case:
   two IPs in feed, drop one, reload, assert the dropped one's node is gone
   (e.g. via a debug/status endpoint or by observing no score contribution).
4. **malformed feed → fail-open + log:** feed with garbage lines + bad CRC ⇒
   assert previous table preserved (a previously-banned IP still hits) and a
   WARN logged; a feed with a few malformed lines under threshold ⇒ valid lines
   still loaded.
5. **stale feed handling:** load a valid feed, then artificially age its mtime
   (`utime`) beyond `stale_after`; assert WARN logged, existing entries still
   present but aging out per TTL; assert no crash and request path serves.
6. **truncation/partial write:** feed truncated mid-decision-block (count/CRC
   mismatch) ⇒ rejected, previous table kept.
7. **oversized feed:** feed > max_bytes ⇒ rejected + WARN, no OOM, no stall.
8. **action tiering:** `captcha`/`throttle` actions ⇒ challenge/tarpit band, not
   block, at default weights.
9. **allowlist precedence:** forward-confirmed good UA from a banned IP ⇒ score
   0 / allow, crowdsec hit still logged.
10. **fuzz:** AFL/libFuzzer harness over the flat-feed parser
    (`sentinel_feed_parse`) — must never crash/OOM/UB on arbitrary bytes
    (no JSON parser ⇒ small attack surface; still fuzz it).
11. **valgrind/asan:** loader run under a churning feed (load → reload →
    delete) shows no leaks (transient pool destroyed each tick) and no
    use-after-free on the swap.

## 7. Concurrency & swap correctness

- **One lock per zone.** The crowdsec zone has its own `shpool->mutex`. Loader
  writes (insert/update/mark-sweep-delete) hold the lock; request-path lookup
  reads under the same lock. No torn reads: a reader either sees the node before
  the loader's update or after — never mid-update — because every field mutation
  on a node happens inside the lock, and node *deletion* (rbtree_delete +
  slab_free) also happens inside the lock, so a reader can never hold a pointer
  to a freed node across the lock boundary (it copies out `action` +
  `blocked_until` while locked, then unlocks).
- **Swap strategy = in-place mark-and-sweep under the lock**, NOT pointer-swap
  of two whole tables. Rationale: a full second copy doubles shm; mark/sweep
  keeps one table, bounded memory, and is atomic w.r.t. readers because the
  whole apply phase is one locked critical section per... — **but** a 16 MiB
  feed's full apply under one lock would stall readers. Therefore:
  - Validate (trailer/CRC) the staging buffer with NO lock held.
  - Apply in **lock-batched chunks**: take lock, apply up to
    `NGX_SENTINEL_FEED_APPLY_BATCH` nodes, bump per-node generation, unlock,
    repeat; do the mark-sweep delete pass in the same batched, locked manner.
    During the brief windows between batches a reader sees a *consistent but
    partially-updated* table (some new bans already live, some deletions not yet
    applied) — acceptable: every individual node is always self-consistent, and
    eventual consistency within one refresh interval is fine for a reputation
    feed. Document this.
  - The generation counter (`sh->cs_generation`) makes the sweep idempotent and
    crash-safe: a worker that dies mid-apply leaves nodes at mixed generations;
    the next successful full load re-stamps and sweeps them correctly.
- Request path takes the lock for the duration of a single O(1) lookup only
  (same cost profile as errrate today) — negligible contention.

## 8. File / symbol additions summary (for the implementer)

- `src/sentinel_feed.c` — loader (timer, stat-gate, read, parse, validate,
  batched apply, mark-sweep) + `sentinel_crowdsec_signal` read side (or split
  read into `sentinel_crowdsec.c`).
- `sentinel.h`: `cs_action` + `cs_generation` fields on node; `cs_generation`
  on shctx; `cs_zone` on loc-conf; crowdsec defaults `#define`s;
  `crowdsec_hit`/`crowdsec_action` on inputs; `crowdsec` on weights; prototypes
  `sentinel_shm_crowdsec_lookup`, `sentinel_feed_load`, `sentinel_feed_parse`,
  `sentinel_crowdsec_signal`, `sentinel_crowdsec_init_process`.
- `sentinel_shm.c`: `sentinel_shm_crowdsec_lookup` + a crowdsec insert/update
  helper + the batched mark-sweep apply (reuse existing rbtree/slab/expire
  helpers; crowdsec nodes allocate with no event ring, `threshold=0`).
- `ngx_http_sentinel_module.c`: directive parsing/validation, zone declaration,
  `init_process` timer arm, wiring `sentinel_crowdsec_signal` into PREACCESS
  signal collection and `weight_crowdsec` into score.
- `config`: add `sentinel_feed.c` (and `sentinel_crowdsec.c` if split) to
  `NGX_ADDON_SRCS`.
```
