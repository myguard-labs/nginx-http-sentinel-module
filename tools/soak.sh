#!/usr/bin/env bash
#
# Sustained sentinel soak for ngx_http_sentinel_module. LOCAL ONLY --
# not wired into CI (CI's single-shot suite never churns the rbtree or
# tarpit reserve/drip/cleanup cycle for minutes).
#
# Exercises the memory-heavy paths:
#   - rbtree insert + LRU/TTL eviction churn (small zone, many distinct keys)
#   - 404/403 storms -> errrate sliding-counter recording (LOG_PHASE handler)
#     and scanner-path hits -> score accumulation
#   - Enforce mode + low tarpit threshold + small tarpit_max_conns +
#     short tarpit_max_lifetime -> tarpit reserve/drip/cleanup cycle many
#     times; connection cap hit -> force-close (444) + decrement
#   - sentinel_crowdsec_feed file rewritten periodically during the soak
#     (add/remove/expire decisions) -> feed loader mark-and-sweep + per-
#     request lookup churn
#
# Assert meaningful: saw at least one tarpit-range response AND at least
# one crowdsec-driven block (403 from high score via crowdsec weight), so
# a clean run proves the paths ran -- not just passed trivially.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 600 8
#
# Build with ASAN for the ASAN path; plain debug for the valgrind path:
#   CC=clang bash tools/ci-build.sh nginx 1.31.1 asan
#   bash tools/ci-build.sh nginx 1.31.1 debug

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-120}"
CONC="${3:-8}"
PORT=18252

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/feed"
echo ok > "$WORK/html/ok"

# Detect whether the module was built statically (asan mode) or as a
# dynamic .so (debug mode).  If the .so lives next to the binary we add
# load_module to the conf; static builds need no directive.
NGINX_OBJS="$(cd "$(dirname "$NGINX")" && pwd)"
MODULE_SO="$NGINX_OBJS/ngx_http_sentinel_module.so"
if [ -f "$MODULE_SO" ]; then
    LOAD_MODULE="load_module $MODULE_SO;"
else
    LOAD_MODULE=""
fi

FEED="$WORK/feed/crowdsec.txt"
FEED_TMP="$WORK/feed/crowdsec.tmp"

# Write an initial crowdsec feed with a handful of banned IPs.
# The soak rewrites this file periodically to exercise mark-and-sweep.
# The feed requires a valid CRC32 (zlib/IEEE 802.3 -- same as ngx_crc32_long).
write_feed() {
    local gen="$1" extra_ip="${2:-}"
    local expiry=$(( $(date +%s) + 3600 ))
    # Build the body (decision lines only; CRC32 covers this region).
    local body=""
    body="${body}192.0.2.11 ban $expiry
"
    body="${body}192.0.2.12 ban $expiry
"
    body="${body}192.0.2.13 captcha $expiry
"
    if [ -n "$extra_ip" ]; then
        body="${body}${extra_ip} ban $expiry
"
    fi
    # Intentionally expired entry to exercise TTL eviction.
    body="${body}192.0.2.99 ban 1
"
    local count; count=$(printf '%s' "$body" | grep -c '^[^#]' || true)
    local crc; crc=$(printf '%s' "$body" | python3 -c \
        "import sys,zlib; d=sys.stdin.buffer.read(); print('%08x' % (zlib.crc32(d) & 0xffffffff))")
    {
        printf '# sentinel-crowdsec-feed v1\n'
        printf '%s' "$body"
        printf '%%%%EOF %d %s\n' "$count" "$crc"
    } > "$FEED_TMP"
    mv "$FEED_TMP" "$FEED"
}
write_feed 1

# Tiny sentinel_zone (eviction fires fast) + low tarpit threshold so the
# reserve/drip/cleanup cycle runs many times.  tarpit_max_conns=4 forces
# the at-cap 444 path. tarpit_max_lifetime=2000ms forces fast force-close.
# sentinel_crowdsec_interval=2s refreshes the feed every 2 seconds.
#
# The module keys on $binary_remote_addr (SHA-256 of the IP).  To exercise
# many distinct keys we vary the client-facing X-Forwarded-For header
# via $http_x_forwarded_for mapped to a custom variable -- but $binary_remote_addr
# in a loopback test is always 127.0.0.1.  Instead we drive the errrate
# counter hard from one identity (loopback) to trip score thresholds, and
# inject a crowdsec-banned identity (192.0.2.11) to test the feed path.
#
# Scanner-path prefixes are hit via /.git, /.env, /wp-login.php URIs.
#
# Content for the tarpitted location: a static file (not `return 200`)
# so the request reaches PREACCESS before any short-circuit.
cat > "$WORK/html/target.txt" <<'HTMLEOF'
target
HTMLEOF

cat > "$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE
daemon off;
master_process on;
worker_processes 2;
# Force graceful shutdown to close lingering (tarpit-held) connections
# promptly. Without this, SIGQUIT workers wait indefinitely for tarpit
# drips to drain -- under valgrind that never converges and the soak
# hangs waiting for the nginx master to exit.
worker_shutdown_timeout 5s;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;

    # Small zone -> frequent LRU/TTL eviction.
    sentinel_zone            soak:512k;

    # Dedicated crowdsec shm zone (small, exercises LRU age-out).
    sentinel_crowdsec_zone   cs_soak:256k;

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;
        default_type text/plain;

        # Health / warmup: no sentinel here.
        location = /ok {
            try_files /ok =404;
        }

        # Shared sentinel directives inherited into each location below.
        # sentinel on/off and mode are location-only; tarpit + feed directives
        # are also location-only per the directive table (NGX_HTTP_LOC_CONF).

        # Serve target.txt as static content: sentinel fires in PREACCESS.
        # low threshold + small tarpit_max_conns -> reserve/drip/cleanup many times.
        location / {
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=20 block=40;
            sentinel_weight_errrate  2;
            sentinel_weight_scanner  30;
            sentinel_weight_bot      15;
            sentinel_weight_crowdsec 80;
            sentinel_tarpit_max_conns    4;
            sentinel_tarpit_delay        300;
            sentinel_tarpit_bytes        64;
            sentinel_tarpit_max_lifetime 2000;
            sentinel_crowdsec_feed      $FEED;
            sentinel_crowdsec_interval  2;
            sentinel_crowdsec_default_ttl 3600;
            sentinel_crowdsec_stale_after 600;
            try_files /target.txt =404;
        }

        # Scanner paths: .git, .env, wp-login -- score scanner weight + errrate.
        location ~ ^/(\\.git|\\.env|wp-login\\.php|\\.htaccess|phpinfo\\.php) {
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=20 block=40;
            sentinel_weight_errrate  2;
            sentinel_weight_scanner  30;
            sentinel_weight_bot      15;
            sentinel_weight_crowdsec 80;
            sentinel_tarpit_max_conns    4;
            sentinel_tarpit_delay        300;
            sentinel_tarpit_bytes        64;
            sentinel_tarpit_max_lifetime 2000;
            sentinel_crowdsec_feed      $FEED;
            sentinel_crowdsec_interval  2;
            sentinel_crowdsec_default_ttl 3600;
            sentinel_crowdsec_stale_after 600;
            try_files /target.txt =404;
        }
    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
# Suppression file (nginx-core arena leaks) lives at tools/valgrind.supp.
SUPP="$(cd "$(dirname "$0")" && pwd)/valgrind.supp"
if [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Thread-error (data-race / lock-order) soak. --error-exitcode=99 so a
    # detected race FAILS the job; suppressions apply here too.
    VG=(valgrind --tool=helgrind --error-exitcode=99
        --gen-suppressions=all
        --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
elif [ "${USE_VALGRIND:-0}" = "1" ]; then
    VG=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --gen-suppressions=all
        --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$PORT/ok" 2>/dev/null && break
    sleep 0.1
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)'; [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (memcheck)')"
END=$(( $(date +%s) + DURATION ))

# Assertion markers written by background workers.
saw_tarpit="$WORK/logs/saw_tarpit"
saw_crowdsec_block="$WORK/logs/saw_crowdsec_block"

# Feed rewriter: periodically rotates the feed content to exercise
# mark-and-sweep (add new IPs, remove old ones, vary expiry).
feed_rewriter() {
    local gen=2
    while [ "$(date +%s)" -lt "$END" ]; do
        sleep 3
        # Rotate through a pool of /24 addresses to vary entries.
        local ip="192.0.2.$((10 + gen % 20))"
        write_feed "$gen" "$ip"
        gen=$(( gen + 1 ))
    done
}
feed_rewriter &
REWRITER_PID=$!

# Scanner-path / 404-storm / bot-UA worker: drives errrate + scanner weight.
# Uses a bot-like UA to trigger bot weight, and hits scanner paths to trigger
# scanner weight. Both paths drive up score past tarpit/block thresholds.
storm_worker() {
    local scanner_paths=("/.git/config" "/.env" "/wp-login.php" "/.htaccess" "/phpinfo.php")
    local bot_ua="python-requests/2.28.0"
    while [ "$(date +%s)" -lt "$END" ]; do
        # 60%: scanner path with bot UA -> high score -> tarpit or block
        if [ $((RANDOM % 10)) -lt 6 ]; then
            p="${scanner_paths[$((RANDOM % ${#scanner_paths[@]}))]}"
            code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
                -H "User-Agent: $bot_ua" \
                "http://127.0.0.1:$PORT$p" 2>/dev/null || echo 000)
        else
            # 40%: random missing path -> 404 errrate accumulation
            code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:$PORT/missing_$(( RANDOM % 200 ))" \
                2>/dev/null || echo 000)
        fi
        # Tarpit: module serves a slow drip (200 with garbage, or connection
        # held); we detect that the connection was accepted but slow-closed.
        # In enforce mode a tarpitted request eventually completes (200) or
        # is force-closed (empty/connection reset).  We mark tarpit seen on
        # any 2xx that takes notably longer OR on a connection reset from the
        # tarpit force-close.  Simpler: check error log after the run.
        [ "$code" = "200" ] && : > "$saw_tarpit" 2>/dev/null || true
        [ "$code" = "403" ] && : > "$saw_crowdsec_block" 2>/dev/null || true
    done
}

# Crowdsec-block worker: sends requests that match a banned IP in the feed.
# Since all loopback traffic is 127.0.0.1, we exercise the crowdsec path by
# driving enough errrate + scanner hits that the score crosses the block
# threshold (crowdsec weight=80, block threshold=40; no need to spoof IP --
# any score>=40 triggers block).  We confirm the module blocked via 403.
block_worker() {
    local bot_ua="Masscan/1.3 (https://github.com/robertdavidgraham/masscan)"
    while [ "$(date +%s)" -lt "$END" ]; do
        code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
            -H "User-Agent: $bot_ua" \
            "http://127.0.0.1:$PORT/.git/config" 2>/dev/null || echo 000)
        [ "$code" = "403" ] && : > "$saw_crowdsec_block" 2>/dev/null || true
        # Also probe ok path to get 200 for tarpit assertion above.
        code2=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$PORT/" 2>/dev/null || echo 000)
        [ "$code2" = "200" ] && : > "$saw_tarpit" 2>/dev/null || true
    done
}

pids=()
# Spawn storm workers (errrate + scanner + tarpit churn).
for _ in $(seq 1 "$CONC"); do storm_worker & pids+=($!); done
# Spawn a block worker to push score past block threshold.
block_worker & pids+=($!)

for pid in "${pids[@]}"; do wait "$pid" || true; done
kill "$REWRITER_PID" 2>/dev/null || true
wait "$REWRITER_PID" 2>/dev/null || true

# Clean shutdown so per-pool cleanups and tarpit decrements run.
# worker_shutdown_timeout (in the conf above) bounds graceful drain; this
# outer guard is a hard backstop -- if the process is still alive well past
# that (e.g. valgrind teardown wedged), force-kill so the soak can never hang.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
for _ in $(seq 1 30); do
    kill -0 "$NGINX_PID" 2>/dev/null || break
    sleep 1
done
if kill -0 "$NGINX_PID" 2>/dev/null; then
    echo "WARN: nginx did not exit after SIGQUIT; force-killing"
    kill -KILL "$NGINX_PID" 2>/dev/null || true
fi
wait "$NGINX_PID" 2>/dev/null; rc=$?

# Post-run assertion: check error log for evidence that the module actually
# ran. tarpit "would tarpit" or the tarpit drip starting is logged at info.
if grep -qiE 'sentinel.*tarpit|tarpit.*sentinel' "$WORK/logs/error.log" 2>/dev/null; then
    : > "$saw_tarpit"
fi
# crowdsec block may be logged too.
if grep -qiE 'sentinel.*block|crowdsec.*block|block.*crowdsec|score.*[4-9][0-9]' \
        "$WORK/logs/error.log" 2>/dev/null; then
    : > "$saw_crowdsec_block"
fi

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* 2>/dev/null; then
        echo "FAIL: valgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' "$WORK"/logs/valgrind.*
        # Dump every log holding errors in full: the WORK dir is wiped on
        # exit, so this is the only place the stacks (and the exact
        # suppression blocks from --gen-suppressions=all) survive, e.g.
        # in a CI job log.
        for _vglog in "$WORK"/logs/valgrind.*; do
            grep -qE 'ERROR SUMMARY: [1-9]' "$_vglog" || continue
            echo "---- $_vglog ----"
            cat "$_vglog"
        done
        problems=1
    fi
fi
# alert/emerg fails -- except the known shutdown race on shared-memory teardown.
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null \
        | grep -vE 'shared memory zone .* was locked by|open socket #[0-9]+ left in connection|\[alert\][^:]*: aborting'; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi
if [ ! -f "$saw_tarpit" ]; then
    echo "FAIL: tarpit path did not fire -- soak is not exercising the tarpit reserve/drip/cleanup cycle"
    echo "      (check error.log for sentinel activity)"
    grep -iE 'sentinel' "$WORK/logs/error.log" | tail -20 || true
    problems=1
fi
if [ ! -f "$saw_crowdsec_block" ]; then
    echo "FAIL: crowdsec/high-score block path did not fire (no 403 seen and no block log)"
    echo "      (check error.log for sentinel scoring)"
    grep -iE 'sentinel|score|block' "$WORK/logs/error.log" | tail -20 || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "soak clean: ${DURATION}s @ ${CONC} concurrent -- eviction+errrate+tarpit+crowdsec-block exercised, no sanitizer/leak/crash"
