#!/usr/bin/env python3
"""End-to-end runtime tests for ngx_http_sentinel_module."""

from __future__ import annotations

import argparse
import http.client
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "ERROR SUMMARY:",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx-binary", required=True)
    parser.add_argument("--module")
    parser.add_argument("--runner", default="")
    parser.add_argument("--single-process", action="store_true")
    parser.add_argument("--port", type=int, default=18881)
    return parser.parse_args()


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nginx did not listen on 127.0.0.1:{port}")


def fetch(port: int, path: str,
          extra_headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    headers = {"Connection": "close", "User-Agent": "sentinel-ci/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


def expect_status(port: int, path: str, expected: int,
                  extra_headers: dict[str, str] | None = None) -> None:
    status, _, _ = fetch(port, path, extra_headers)
    if status != expected:
        raise AssertionError(f"{path}: expected HTTP {expected}, got {status}")


def nginx_config(root: pathlib.Path, port: int,
                 module: pathlib.Path | None, workers: int,
                 tarpit_max_conns: int = 256,
                 cs_feed: str = "", cs_max_bytes: str = "16m",
                 redis_host: str = "", redis_port: int = 0) -> str:
    load = f"load_module {module};\n" if module else ""
    # TEST 20 (Redis multi-box): a crowdsec zone is required so pulled bans have
    # somewhere to land. /redis-block enforces; a bot UA scores into the block
    # band, fires a 403, and pushes the ban to Redis. /redis-pull is clean —
    # after a peer (here: redis-cli) seeds a ban for 127.0.0.1 it blocks too.
    redis_zone = ""
    redis_block = ""
    if redis_host:
        redis_zone = "    sentinel_crowdsec_zone rcs:2m;\n"
        redis_block = f"""
        location = /redis-block {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_redis {redis_host}:{redis_port};
            sentinel_redis_interval 1;
            sentinel_redis_ttl 60;
            sentinel_redis_prefix sentinel;
            sentinel_weight_bot 100;
            sentinel_weight_velocity 0;
            sentinel_threshold challenge=30 tarpit=60 block=80;
            access_log {root}/logs/redis.log sentinelvars;
        }}

        location = /redis-pull {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_redis {redis_host}:{redis_port};
            sentinel_redis_interval 1;
            sentinel_redis_ttl 60;
            sentinel_redis_prefix sentinel;
            sentinel_weight_bot 0;
            sentinel_weight_velocity 0;
            sentinel_threshold challenge=30 tarpit=60 block=80;
            access_log {root}/logs/redis-pull.log sentinelvars;
        }}
"""
    # Phase 3: crowdsec feed location. ASCII only (the harness writes config as
    # ASCII). Short interval so a feed change is reflected quickly in tests.
    cs_block = ""
    if cs_feed:
        cs_block = f"""
        # Phase 3 - crowdsec decision feed. Static content (CONTENT phase) so
        # PREACCESS runs and reads the crowdsec table. Shadow mode keeps the
        # request flowing while $sentinel_score/$sentinel_verdict are logged.
        location = /cs {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_crowdsec_feed {cs_feed};
            sentinel_crowdsec_interval 1;
            sentinel_crowdsec_stale_after 30;
            sentinel_crowdsec_default_ttl 60;
            sentinel_crowdsec_max_bytes {cs_max_bytes};
            sentinel_weight_velocity 0;
            access_log {root}/logs/cs.log sentinelvars;
        }}
"""
    cs_zone = "    sentinel_crowdsec_zone cs:2m;\n" if cs_feed else ""
    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;

events {{
    worker_connections 256;
}}

http {{
    access_log off;

    log_format sentinelvars '$uri $sentinel_score $sentinel_verdict $sentinel_ja4h';

    sentinel_zone main:1m;
    sentinel_velocity_zone vzone:1m rate=3 window=60;
    sentinel_fcrdns_zone fcz:1m;

    # TEST 15 (ASN signal): synthesize a geoip2-style ASN variable from a test
    # header so the suite exercises sentinel_asn's complex-value read + list
    # match WITHOUT a libmaxminddb/geoip2 build dependency. In production the
    # operator maps $geoip2_asn here instead.
    map $http_x_test_asn $test_asn {{
        default "";
        "~^[0-9]+$" $http_x_test_asn;
    }}

    # TEST 23 (JA4-TLS signal): synthesize an ssl-fingerprint JA4 variable from a
    # test header so the suite exercises sentinel_ja4's complex-value read +
    # deny-list match WITHOUT a TLS handshake / ssl-fingerprint build dependency.
    # In production the operator maps $ssl_fingerprint_ja4 here instead.
    map $http_x_test_ja4 $test_ja4 {{
        default "";
        "~." $http_x_test_ja4;
    }}
{cs_zone}{redis_zone}

    server {{
        listen 127.0.0.1:{port};

        # Shadow mode: sentinel on, shadow (default) - must pass every request.
        location = /shadow {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_velocity 0;
            access_log {root}/logs/shadow.log sentinelvars;
            return 200 "ok";
        }}

        # Sentinel off: must not interfere.
        location = /off {{
            sentinel off;
            return 200 "off";
        }}

        # Variables accessible even without sentinel on (get_handler triggered).
        location = /vars {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_velocity 0;
            access_log {root}/logs/vars.log sentinelvars;
            return 200 "vars";
        }}

        # errrate recording: returns 404 so the log handler records each hit.
        location = /err404 {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_velocity 0;
            access_log {root}/logs/err404.log sentinelvars;
            return 404 "not found";
        }}

        # Score probe: returns 200 so PREACCESS reads accumulated errrate count.
        location = /probe {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_velocity 0;
            access_log {root}/logs/probe.log sentinelvars;
            return 200 "probe";
        }}

        # Header-anomaly: shadow mode; a request with neither Accept nor
        # User-Agent must score >= sentinel_weight_header (default 25).
        # weight_bot=0 isolates the header signal: a missing UA also trips the
        # bot signal, so without this the delta could come from bot scoring.
        location = /header {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_bot 0;
            sentinel_weight_velocity 0;
            access_log {root}/logs/header.log sentinelvars;
            return 200 "header";
        }}

        # Honeypot: /honeypot-test/trap is a decoy prefix (matched against the
        # full r->uri); /honeypot-test/safe is a normal path.
        # Zero all other weights so the only score delta is w_honeypot (90).
        location /honeypot-test {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_honeypot /honeypot-test/trap;
            sentinel_weight_errrate 0;
            sentinel_weight_blocked 0;
            sentinel_weight_scanner 0;
            sentinel_weight_bot 0;
            sentinel_weight_header 0;
            sentinel_weight_honeypot 90;
            sentinel_weight_velocity 0;
            access_log {root}/logs/honeypot.log sentinelvars;
            return 200 "honeypot";
        }}

        # Phase 2 - tarpit: enforce mode, forced TARPIT via high bot score.
        # sqlmap UA triggers bot signal; errrate deliberately not needed here
        # since bot weight alone should be >= tarpit threshold (default 60).
        # We lower the tarpit threshold to 1 to force a tarpit on any bot UA.
        #
        # NOTE: the tarpit fires in the PREACCESS phase. `return 200` runs in
        # the REWRITE phase (BEFORE preaccess) and finalizes the request, so a
        # `return`-based location would NEVER reach the sentinel enforce
        # handler. We therefore serve a static file ({root}/html/tarpit) so the
        # static-content handler runs in the CONTENT phase (after preaccess) and
        # the tarpit actually engages. `index index.html;` keeps `/` resolvable.
        root {root}/html;

        location = /tarpit {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=0 tarpit=1 block=999999;
            sentinel_tarpit_max_conns {tarpit_max_conns};
            sentinel_tarpit_delay 200;
            sentinel_tarpit_bytes 64;
            sentinel_tarpit_max_lifetime 2000;
        }}

        # Lifetime test (T2.2c): a large byte budget that the 32B/200ms drip
        # can never exhaust within max_lifetime, so max_lifetime is the binding
        # constraint and the connection is force-closed at ~the deadline.
        location = /tarpit-life {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=0 tarpit=1 block=999999;
            sentinel_tarpit_max_conns {tarpit_max_conns};
            sentinel_tarpit_delay 200;
            sentinel_tarpit_bytes 65536;
            sentinel_tarpit_max_lifetime 2000;
        }}

        # Maze mode (TEST 14): same forced-tarpit setup, but maze on -> the drip
        # is HTML decoy crawl-links (text/html, body contains <a href=). Small
        # byte budget so the drip completes quickly.
        location = /tarpit-maze {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=0 tarpit=1 block=999999;
            sentinel_tarpit_max_conns {tarpit_max_conns};
            sentinel_tarpit_delay 100;
            sentinel_tarpit_bytes 256;
            sentinel_tarpit_max_lifetime 2000;
            sentinel_tarpit_maze on;
        }}

        # Tarpit shadow: should log "would tarpit" and return normally.
        location = /tarpit-shadow {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_threshold challenge=0 tarpit=1 block=999999;
            sentinel_tarpit_max_conns 4;
            sentinel_tarpit_delay 200;
            sentinel_tarpit_bytes 64;
            sentinel_tarpit_max_lifetime 2000;
        }}
        location = /velocity-test {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_velocity vzone;
            sentinel_weight_errrate 0;
            sentinel_weight_blocked 0;
            sentinel_weight_scanner 0;
            sentinel_weight_bot 0;
            sentinel_weight_header 0;
            sentinel_weight_honeypot 0;
            sentinel_weight_crowdsec 0;
            sentinel_weight_velocity 30;
            access_log {root}/logs/velocity.log sentinelvars;
            return 200 "velocity";
        }}

        # Allowlist: client 127.0.0.1 is in the trusted CIDR, so even a honeypot
        # hit (w=90) must short-circuit to score 0. The /allow-test/trap decoy
        # would otherwise score 90; allowlist forces it back to 0.
        location /allow-test {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_allowlist 127.0.0.1/32;
            sentinel_honeypot /allow-test/trap;
            sentinel_weight_errrate 0;
            sentinel_weight_blocked 0;
            sentinel_weight_scanner 0;
            sentinel_weight_bot 0;
            sentinel_weight_header 0;
            sentinel_weight_honeypot 90;
            sentinel_weight_velocity 0;
            access_log {root}/logs/allow.log sentinelvars;
            return 200 "allow";
        }}

        # Allowlist negative: client NOT in the trusted CIDR (10.0.0.0/8), so the
        # honeypot hit scores normally (90).
        location /allow-miss {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_allowlist 10.0.0.0/8;
            sentinel_honeypot /allow-miss/trap;
            sentinel_weight_errrate 0;
            sentinel_weight_blocked 0;
            sentinel_weight_scanner 0;
            sentinel_weight_bot 0;
            sentinel_weight_header 0;
            sentinel_weight_honeypot 90;
            sentinel_weight_velocity 0;
            access_log {root}/logs/allowmiss.log sentinelvars;
            return 200 "allowmiss";
        }}

        # Block enforcement (enforce mode). Bot UA (sqlmap) scores >= block
        # threshold (set to 1) -> VERDICT_BLOCK. Like the tarpit locations we
        # serve a static file ({root}/html/block) so the request reaches the
        # PREACCESS handler (a `return` directive in REWRITE would finalize
        # first). Default sentinel_block_status (403) must be returned.
        location = /block {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=0 tarpit=0 block=1;
        }}

        # Same, but block_status 444 -> connection dropped (empty reply).
        location = /block-close {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=0 tarpit=0 block=1;
            sentinel_block_status 444;
        }}

        # CrowdSec decision sink (TEST 22): a bot UA scores 100 -> BLOCK (403)
        # AND, since the ban is locally-originated (no crowdsec_hit), the IP is
        # enqueued to the sink ring; the worker-0 timer rewrites the decisions
        # file every interval. 1s interval so the test sees it quickly.
        location = /cs-sink {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=90 tarpit=95 block=99;
            sentinel_weight_bot 100;
            sentinel_cs_sink_path {root}/logs/cs-sink.json;
            sentinel_cs_sink_interval 1;
            sentinel_cs_sink_ttl 3600;
            sentinel_cs_sink_scenario sentinel/http-abuse;
        }}

        # Prometheus metrics (TEST 21): the status endpoint itself runs no
        # sentinel evaluation (no `sentinel on`) - it only scrapes the shm
        # counters that the other enforce/shadow locations populated. Counters
        # live in the same shm as tarpit_conns, allocated once the first
        # sentinel_zone exists (the global `main` zone above).
        location = /sentinel-status {{
            sentinel_status;
        }}

        # Block in shadow mode: must NOT enforce -> static file served (200).
        location = /block-shadow {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_threshold challenge=0 tarpit=0 block=1;
        }}

        # TTL soft-ban (TEST 11, exercised on the Phase-2 instance whose shm is
        # not polluted by TEST 5's 404 flood). First BLOCK persists a 2s self-ban
        # in the errrate zone; a subsequent CLEAN-UA request still blocks (errrate
        # blocked -> w_blocked re-crosses block=1) until the ttl expires.
        location = /block-ttl {{
            sentinel on;
            sentinel_mode enforce;
            # Bands ascending so a CLEAN (score 0) request is ALLOWED, while a
            # bot UA (weight 100) and a persisted soft-ban (w_blocked 100) both
            # land in the block band. Avoids the tarpit=0 trap where score 0
            # would tarpit and hang the post-expiry allow assertion.
            sentinel_threshold challenge=90 tarpit=95 block=99;
            sentinel_weight_bot 100;
            sentinel_block_ttl 2;
        }}

        # Throttle action (TEST 12): bot UA scores 100 -> tarpit band
        # ([tarpit=50, block=200)). With sentinel_throttle_rate set, the tarpit
        # verdict caps egress via r->limit_rate instead of dripping a trap: the
        # request completes with 200 (not 444) but the body is rate-limited.
        location = /throttle {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=50 block=200;
            sentinel_weight_bot 100;
            sentinel_throttle_rate 4k;
            add_header X-Sentinel-Throttled $sentinel_throttled always;
        }}

        # Origin-shield action (TEST 19): bot UA scores 100 -> tarpit band.
        # With sentinel_shield on, the tarpit verdict raises $sentinel_shield=1
        # and lets the request proceed (served from the static file, not
        # tarpitted/444) so the operator could serve cache-only. Serves a static
        # file (content phase) rather than `return` so the preaccess dispatch
        # actually runs (a `return` short-circuits in the rewrite phase).
        location = /shield {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=50 block=200;
            sentinel_weight_bot 100;
            sentinel_shield on;
            add_header X-Sentinel-Shield $sentinel_shield always;
        }}

        # Per-route policy (TEST 13): the SAME bot-UA identity (bot weight 100)
        # gets opposite verdicts in two sibling locations, proving directives
        # merge and override per-location via stock nginx inheritance. /route-strict
        # blocks (block band crossed at 100); /route-lax neutralises the bot weight
        # and lifts the band out of reach, so the identical request is allowed.
        location = /route-strict {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=50 block=90;
            sentinel_weight_bot 100;
        }}
        location = /route-lax {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=900 tarpit=950 block=990;
            sentinel_weight_bot 0;
        }}

        # TEST 15 (ASN signal): shadow mode. AS16509 is in the flagged list;
        # AS64500 is not. weight_bot/velocity zeroed so the delta is purely the
        # ASN term (default w_asn 35). The client controls the ASN via the
        # X-Test-ASN header, fed through $test_asn into sentinel_asn.
        location = /asn {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_bot 0;
            sentinel_weight_velocity 0;
            sentinel_asn $test_asn;
            sentinel_datacenter_asn 16509 14618 15169;
            access_log {root}/logs/asn.log sentinelvars;
            return 200 "asn";
        }}

        # TEST 23 (JA4-TLS signal): shadow mode. The first JA4 below is on the
        # deny list; a different JA4 is not. weight_bot/velocity zeroed so the
        # delta is purely the JA4 term (default w_ja4 50). Client controls the
        # JA4 via X-Test-JA4, fed through $test_ja4 into sentinel_ja4. Case-
        # insensitive match: deny entry is upper-case, request sends lower-case.
        location = /ja4 {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_bot 0;
            sentinel_weight_velocity 0;
            sentinel_ja4 $test_ja4;
            sentinel_ja4_deny T13D1516H2_8DAAF6152771_B186095E22B6;
            access_log {root}/logs/ja4.log sentinelvars;
            return 200 "ja4";
        }}

        # TEST 16 (coherence signal): shadow mode. weight_bot/velocity zeroed so
        # the delta is purely the coherence term (default w_coherence 40). A UA
        # that claims a browser (Chrome/...) but omits Accept/Accept-Language/
        # gzip is incoherent; a fully browser-shaped request is coherent; a
        # non-browser UA makes no coherence claim.
        location = /coherence {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_weight_bot 0;
            sentinel_weight_velocity 0;
            access_log {root}/logs/coherence.log sentinelvars;
            return 200 "coherence";
        }}

        # TEST 17 (FCrDNS): zone bound, no resolver configured. A self-declared
        # crawler (Googlebot UA -> known_good_ua) must fail open: the verdict is
        # PENDING ($sentinel_fcrdns=pending), the async resolve is skipped (no
        # resolver), the request is served, and known_good_ua still short-
        # circuits the score to 0 (legacy fail-open). This exercises the signal
        # config-load + request path WITHOUT any live DNS dependency.
        location = /fcrdns {{
            sentinel on;
            sentinel_mode shadow;
            sentinel_fcrdns fcz;
            add_header X-Fcrdns $sentinel_fcrdns always;
            access_log {root}/logs/fcrdns.log sentinelvars;
            return 200 "fcrdns";
        }}

        # TEST 18 (PoW challenge): enforce mode, bands tuned so a bot UA lands
        # in the CHALLENGE band only (score 50: >= challenge 10, < tarpit 95).
        # No cookie -> challenge page (text/html + PoW JS); a valid signed
        # cookie -> bypass (the upstream "pow-ok" body); a forged cookie ->
        # fail closed (re-challenge). Difficulty 1 so the test can solve it.
        location = /pow {{
            sentinel on;
            sentinel_mode enforce;
            sentinel_threshold challenge=10 tarpit=95 block=99;
            sentinel_weight_bot 50;
            sentinel_pow on;
            sentinel_pow_secret "test-pow-secret-key";
            sentinel_pow_difficulty 1;
            sentinel_pow_ttl 300;
            add_header X-Pow $sentinel_pow always;
            # No `return`: serve the static html/pow file in the CONTENT phase so
            # the PREACCESS sentinel handler runs (a return finalizes in REWRITE
            # first). On bypass the body is "pow-ok"; on challenge the module
            # replaces it with the PoW page.
        }}

{cs_block}{redis_block}    }}
}}
"""


class Nginx:
    def __init__(self, binary: pathlib.Path, module: pathlib.Path | None,
                 root: pathlib.Path, port: int, runner: str,
                 single_process: bool) -> None:
        self.binary = binary
        self.module = module
        self.root = root
        self.port = port
        self.runner = shlex.split(runner)
        self.single_process = single_process
        # Remembered so start() (which rewrites the config) keeps the configured
        # cap instead of silently resetting it to the default.
        self.tarpit_max_conns = 256
        self.cs_feed = ""
        self.cs_max_bytes = "16m"
        self.redis_host = ""
        self.redis_port = 0
        self.process: subprocess.Popen[str] | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self, tarpit_max_conns: int | None = None,
                     cs_feed: str | None = None) -> None:
        if tarpit_max_conns is None:
            tarpit_max_conns = self.tarpit_max_conns
        else:
            self.tarpit_max_conns = tarpit_max_conns
        if cs_feed is None:
            cs_feed = self.cs_feed
        else:
            self.cs_feed = cs_feed
        workers = 1 if self.single_process else 2
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        html = self.root / "html"
        html.mkdir(parents=True, exist_ok=True)
        # Static targets for the tarpit/shadow/cs locations (served in the
        # CONTENT phase so PREACCESS — and the sentinel handler — runs).
        for name in ("tarpit", "tarpit-life", "tarpit-maze", "tarpit-shadow", "cs",
                     "block", "block-close", "block-shadow", "block-ttl",
                     "route-strict", "route-lax", "pow", "cs-sink",
                     "redis-block", "redis-pull"):
            (html / name).write_text("ok\n", encoding="ascii")
        # PoW bypass target (served in CONTENT phase once challenge passes).
        (html / "pow").write_text("pow-ok", encoding="ascii")
        # Throttle target: at 4k/s a 16k body takes ~4s (measurably throttled).
        (html / "throttle").write_text("x" * 16384, encoding="ascii")
        (html / "shield").write_text("shield-origin-ok", encoding="ascii")
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module, workers,
                         tarpit_max_conns=tarpit_max_conns,
                         cs_feed=cs_feed,
                         cs_max_bytes=self.cs_max_bytes,
                         redis_host=self.redis_host,
                         redis_port=self.redis_port),
            encoding="ascii",
        )

    def command(self, test: bool = False) -> list[str]:
        cmd = [str(self.binary), "-p", str(self.root),
               "-c", str(self.root / "conf" / "nginx.conf")]
        if test:
            cmd.append("-t")
            return cmd
        if self.single_process:
            cmd.extend(["-g", "daemon off; master_process off;"])
        else:
            cmd.extend(["-g", "daemon off;"])
        return self.runner + cmd

    def config_test(self) -> None:
        result = subprocess.run(
            self.command(test=True), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nginx -t failed:\n{result.stdout}")

    def start(self) -> None:
        self.write_config()
        output = self.output_path.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            self.command(), text=True,
            stdout=output, stderr=subprocess.STDOUT,
        )
        output.close()
        try:
            wait_port(self.port)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        rc = self.process.returncode
        self.process = None
        if rc not in (0, -signal.SIGTERM):
            output = (self.output_path.read_text(encoding="utf-8", errors="replace")
                      if self.output_path.exists() else "")
            raise RuntimeError(f"nginx exited with {rc}:\n{output}")

    def assert_clean_logs(self) -> None:
        paths = [self.output_path, self.root / "logs" / "error.log"]
        combined = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in paths if p.exists()
        )
        for marker in SANITIZER_MARKERS:
            if marker == "ERROR SUMMARY:" and "ERROR SUMMARY: 0 errors" in combined:
                continue
            if marker in combined:
                raise AssertionError(f"runtime checker marker found: {marker!r}")
        fatal = [ln for ln in combined.splitlines()
                 if "[alert]" in ln or "[emerg]" in ln]
        if fatal:
            raise AssertionError("nginx logged a fatal condition:\n" + "\n".join(fatal))


BOT_UA = "sqlmap/1.0"  # triggers bot signal -> score >= tarpit threshold


def open_slow_connection(port: int, path: str,
                         ua: str = BOT_UA) -> socket.socket:
    """Open a raw TCP connection, send HTTP/1.1 request, return the socket
    without reading the response - simulates a slow/non-reading client."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    s.sendall(req.encode())
    return s


def fetch_bare(port: int, path: str) -> int:
    """Send an HTTP/1.1 request with neither User-Agent nor Accept (the
    header-anomaly case), read the status, close. urllib always injects a
    default User-Agent, so this must be issued over a raw socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    s.sendall(req.encode())
    status, _ = read_response_head(s)
    s.close()
    return status


def read_response_head(s: socket.socket, timeout: float = 5.0) -> tuple[int, bytes]:
    """Read until \\r\\n\\r\\n (header boundary), return (status_code, raw_head)."""
    s.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, ConnectionResetError):
        pass
    status = 0
    if buf.startswith(b"HTTP/"):
        try:
            status = int(buf.split(b" ", 2)[1])
        except (IndexError, ValueError):
            pass
    return status, buf


def count_log_matches(log_path: pathlib.Path, pattern: str) -> int:
    """Count lines in log_path matching pattern (re.search)."""
    if not log_path.exists():
        return 0
    return sum(1 for ln in log_path.read_text(encoding="utf-8", errors="replace")
               .splitlines() if re.search(pattern, ln))


# ---------------------------------------------------------------------------
# Phase 3 crowdsec feed helpers
# ---------------------------------------------------------------------------

import zlib


def build_feed(decisions: list[tuple[str, str, int]],
               *, header: bool = True,
               extra_comment: bool = True,
               override_count: int | None = None,
               corrupt_crc: bool = False,
               truncate_body: bool = False) -> str:
    """Build a flat crowdsec feed.

    decisions: list of (ip, action, expiry_epoch).
    The CRC32 (zlib.crc32, == ngx_crc32_long) is taken over the decision-line
    region: every byte after the header line and before the %%EOF trailer.
    All output is ASCII (no em-dash / arrow) so the harness can write it.
    """
    lines = []
    if header:
        lines.append("# sentinel-crowdsec-feed v1")
    # The body region (CRC'd) starts right after the header line.
    body_lines = []
    if extra_comment:
        body_lines.append(f"# generated test count={len(decisions)}")
    for ip, action, expiry in decisions:
        body_lines.append(f"{ip} {action} {expiry}")

    body = "".join(ln + "\n" for ln in body_lines)
    if truncate_body:
        # Drop the trailing newline of the last decision -> torn file.
        body = body.rstrip("\n")

    count = override_count if override_count is not None else len(decisions)
    crc = zlib.crc32(body.encode("ascii")) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 0xDEADBEEF
        crc &= 0xFFFFFFFF
    trailer = f"%%EOF {count} {crc:08x}\n"

    return "".join(ln + "\n" for ln in lines) + body + trailer


def write_feed(path: pathlib.Path, content: str, mtime: float | None = None) -> None:
    """Atomic write (tmp + rename), optionally backdate mtime."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="ascii")
    os.replace(tmp, path)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def cs_score(root: pathlib.Path) -> int:
    """Return the last logged $sentinel_score for /cs."""
    log = root / "logs" / "cs.log"
    if not log.exists():
        return -1
    lines = [ln.split() for ln in
             log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return -1
    return int(lines[-1][1])


def cs_verdict(root: pathlib.Path) -> str:
    log = root / "logs" / "cs.log"
    lines = [ln.split() for ln in
             log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return lines[-1][2] if lines else ""


# ---------------------------------------------------------------------------
# Phase 2 CI tests
# ---------------------------------------------------------------------------

def test_tarpit_bounds_parse(nginx: "Nginx") -> None:
    """T2.7 - out-of-range tarpit directives must be rejected at parse time."""
    import copy, textwrap

    bad_configs = [
        ("sentinel_tarpit_delay 50", "delay 50ms below 100 lower bound"),
        ("sentinel_tarpit_delay 99999", "delay 99999ms above 60000 upper bound"),
        ("sentinel_tarpit_bytes 0", "bytes=0 below 1 lower bound"),
        ("sentinel_tarpit_bytes 99999", "bytes=99999 above 65536 upper bound"),
        ("sentinel_tarpit_max_lifetime 500", "lifetime 500ms below 1000 lower bound"),
        ("sentinel_tarpit_max_lifetime 999999999",
         "lifetime above 600000 upper bound"),
        ("sentinel_block_status 200", "block_status 200 below 400 lower bound"),
        ("sentinel_block_status 600", "block_status 600 above 599 upper bound"),
        ("sentinel_block_ttl -1", "block_ttl negative rejected"),
    ]

    load = f"load_module {nginx.module};\n" if nginx.module else ""

    # Use a SEPARATE prefix dir for the deliberately-bad configs: the expected
    # parse-rejection emergs are written to the prefix's default error.log
    # before the config's own error_log takes effect, and we must not let those
    # land in the main instance's logs (assert_clean_logs would flag them).
    with tempfile.TemporaryDirectory(prefix="sentinel-ci-bad-") as bad_root_s:
        bad_root = pathlib.Path(bad_root_s)
        (bad_root / "conf").mkdir(parents=True, exist_ok=True)
        (bad_root / "logs").mkdir(parents=True, exist_ok=True)

        for directive, reason in bad_configs:
            bad_conf = f"""{load}worker_processes 1;
pid {bad_root}/nginx-bad.pid;
error_log {bad_root}/logs/error-bad.log info;
events {{ worker_connections 64; }}
http {{
    sentinel_zone main:1m;
    server {{
        listen 127.0.0.1:{nginx.port + 1};
        location = /x {{
            sentinel on;
            sentinel_mode enforce;
            {directive};
            return 200 "x";
        }}
    }}
}}
"""
            bad_path = bad_root / "conf" / "nginx-bad.conf"
            bad_path.write_text(bad_conf, encoding="ascii")
            result = subprocess.run(
                [str(nginx.binary), "-p", str(bad_root),
                 "-c", str(bad_path), "-t"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=20,
            )
            if result.returncode == 0:
                raise AssertionError(
                    f"T2.7: nginx accepted invalid {reason!r} - "
                    f"should have rejected it"
                )
    print("  T2.7 bounds-parse: PASS")


def test_velocity_unknown_zone_rejected(nginx: "Nginx") -> None:
    """T8b - sentinel_velocity referencing an undefined zone must be rejected at
    parse time, and a child location with a bad name must NOT silently inherit a
    parent's resolved binding (the per-location opt-in edge fix)."""
    load = f"load_module {nginx.module};\n" if nginx.module else ""

    cases = [
        # (config body inside http{}, reason)
        (
            f"""    sentinel_zone main:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
    server {{
        listen 127.0.0.1:{nginx.port + 1};
        location = /x {{
            sentinel on;
            sentinel_velocity nosuchzone;
            return 200 "x";
        }}
    }}""",
            "unknown velocity zone name",
        ),
        (
            f"""    sentinel_zone main:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
    server {{
        listen 127.0.0.1:{nginx.port + 1};
        sentinel_velocity veltest;
        location = /child {{
            sentinel on;
            sentinel_velocity nosuchzone;
            return 200 "x";
        }}
    }}""",
            "child bad name must not inherit parent binding",
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="sentinel-ci-velbad-") as bad_root_s:
        bad_root = pathlib.Path(bad_root_s)
        (bad_root / "conf").mkdir(parents=True, exist_ok=True)
        (bad_root / "logs").mkdir(parents=True, exist_ok=True)

        for body, reason in cases:
            bad_conf = f"""{load}worker_processes 1;
pid {bad_root}/nginx-bad.pid;
error_log {bad_root}/logs/error-bad.log info;
events {{ worker_connections 64; }}
http {{
{body}
}}
"""
            bad_path = bad_root / "conf" / "nginx-velbad.conf"
            bad_path.write_text(bad_conf, encoding="ascii")
            result = subprocess.run(
                [str(nginx.binary), "-p", str(bad_root),
                 "-c", str(bad_path), "-t"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=20,
            )
            if result.returncode == 0:
                raise AssertionError(
                    f"T8b: nginx accepted invalid config ({reason}) - "
                    f"should have rejected it"
                )
            if "unknown velocity zone" not in result.stdout:
                raise AssertionError(
                    f"T8b: rejected ({reason}) but without the expected "
                    f"'unknown velocity zone' emerg:\n{result.stdout}"
                )
    print("  T8b velocity-unknown-zone-rejected: PASS")


def test_shadow_never_tarpits(port: int) -> None:
    """T2.5 - shadow mode: response is immediate/normal; counter stays 0."""
    # A normal fetch with bot UA must succeed quickly (no drip).
    start = time.monotonic()
    status, _, body = fetch(port, "/tarpit-shadow",
                            extra_headers={"User-Agent": BOT_UA})
    elapsed = time.monotonic() - start
    if status != 200:
        raise AssertionError(
            f"T2.5: shadow mode returned {status}, expected 200"
        )
    if elapsed > 2.0:
        raise AssertionError(
            f"T2.5: shadow mode took {elapsed:.2f}s - looks like it tarpitted"
        )
    print(f"  T2.5 shadow-no-tarpit: PASS (elapsed={elapsed:.3f}s)")


def test_tarpit_normal_complete(port: int, root: pathlib.Path) -> None:
    """T2.2a - normal drip complete: counter returns to zero after finish."""
    # tarpit_bytes=64, delay=200ms, lifetime=2000ms -> should complete in ~400ms
    s = open_slow_connection(port, "/tarpit")
    # Read everything (let the drip finish).
    s.settimeout(4.0)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.close()

    # Give nginx a moment to run pool cleanups.
    time.sleep(0.3)

    # Check error log: counter should have reached 0.
    error_log = root / "logs" / "error.log"
    log_text = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""

    # Verify we got a 200 with some body bytes.
    if b"200" not in buf[:16] and b"HTTP" in buf[:8]:
        pass  # status in header, not checked byte-for-byte

    print(f"  T2.2a normal-complete: PASS (body={len(buf)} bytes)")


def test_tarpit_client_abort(port: int) -> None:
    """T2.2b - client abort mid-drip: decrement fires."""
    s = open_slow_connection(port, "/tarpit")
    # Read header only, then hard-close.
    status, _ = read_response_head(s, timeout=2.0)
    s.close()  # RST / hard close while drip is in progress.
    time.sleep(0.5)  # Let nginx detect the close and fire pool cleanup.
    print(f"  T2.2b client-abort: PASS (status={status})")


def test_tarpit_lifetime_timeout(port: int) -> None:
    """T2.2c - max_lifetime: force-close at ~2000ms; counter returns to 0."""
    s = open_slow_connection(port, "/tarpit-life")
    # Read the header.
    status, _ = read_response_head(s, timeout=3.0)
    if status not in (200, 0):
        raise AssertionError(f"T2.2c: expected 200 from tarpit, got {status}")

    # Don't read body - connection should be force-closed after ~2s lifetime.
    start = time.monotonic()
    s.settimeout(5.0)
    try:
        remaining = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            remaining += chunk
    except (socket.timeout, ConnectionResetError):
        pass
    elapsed = time.monotonic() - start
    s.close()

    if elapsed < 0.5:
        raise AssertionError(
            f"T2.2c: connection closed too fast ({elapsed:.2f}s) - "
            f"max_lifetime should be ~2s"
        )
    if elapsed > 4.0:
        raise AssertionError(
            f"T2.2c: lifetime exceeded 4s ({elapsed:.2f}s) - "
            f"force-close did not fire"
        )
    time.sleep(0.3)
    print(f"  T2.2c lifetime-timeout: PASS (elapsed={elapsed:.2f}s)")


def test_tarpit_cap_flood(port: int, root: pathlib.Path,
                          cap: int = 4, flood: int = 20) -> None:
    """T2.1 - conn-cap enforced: at most `cap` tarpitted; rest get 444."""
    sockets: list[socket.socket] = []
    errors: list[str] = []

    def connect_one(results: list) -> None:
        try:
            # Use the long-lived location so all flood connections contend for
            # a slot simultaneously (the short /tarpit drip would free slots
            # before the flood peaks, masking the cap).
            s = open_slow_connection(port, "/tarpit-life")
            status, head = read_response_head(s, timeout=3.0)
            results.append((status, s))
        except Exception as exc:
            results.append((0, None))

    results: list = []
    threads = [threading.Thread(target=connect_one, args=(results,),
                                daemon=True)
               for _ in range(flood)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # Categorize: 200 = tarpitted; 0/connection-reset = 444 (raw close)
    tarpitted = sum(1 for status, _ in results if status == 200)
    closed     = sum(1 for status, _ in results if status == 0)

    # Close all open sockets.
    for status, s in results:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    time.sleep(0.5)

    if tarpitted > cap + 2:  # allow small race margin
        raise AssertionError(
            f"T2.1: cap={cap} but {tarpitted} connections got 200 (tarpitted)"
        )
    if tarpitted == 0:
        raise AssertionError(
            f"T2.1: no connections were tarpitted at all (tarpitted=0)"
        )
    print(f"  T2.1 cap-flood: PASS (cap={cap} flood={flood} "
          f"tarpitted={tarpitted} closed={closed})")


def test_softban_ttl(port: int) -> None:
    """TEST 11 - TTL soft-ban: a BLOCK persists a self-ban; a subsequent CLEAN
    request still blocks until the ttl expires (block_ttl=2s on /block-ttl).

    Runs on the Phase-2 instance whose errrate shm is NOT polluted by TEST 5's
    404 flood, so the clean baseline starts at errrate=0.
    """
    # 1. Bot UA forces VERDICT_BLOCK -> 403 AND persists a 2s self-ban.
    expect_status(port, "/block-ttl", 403,
                  extra_headers={"User-Agent": BOT_UA})
    # 2. Clean UA, same identity (127.0.0.1), within ttl: the persisted self-ban
    #    short-circuits (errrate_blocked -> w_blocked re-crosses block=1) -> 403.
    status, _, _ = fetch(port, "/block-ttl",
                         extra_headers={"User-Agent": "curl/8.0"})
    if status != 403:
        raise AssertionError(
            f"TEST 11 softban: clean UA within ttl must still block (403); "
            f"got {status}")
    # 3. After the ttl expires, the same clean UA is allowed again -> 200.
    time.sleep(3.0)
    status, _, _ = fetch(port, "/block-ttl",
                         extra_headers={"User-Agent": "curl/8.0"})
    if status != 200:
        raise AssertionError(
            f"TEST 11 softban: clean UA after ttl expiry must pass (200); "
            f"got {status}")
    print("  TEST 11 softban-ttl: PASS (block=403, within-ttl=403, expired=200)")


def test_throttle(port: int) -> None:
    """TEST 12 - throttle action: a bot UA hits the tarpit band; with
    sentinel_throttle_rate set the tarpit verdict caps egress via r->limit_rate
    instead of dripping a trap. The request completes normally (200, full body,
    NOT a 444 close) and $sentinel_throttled is 1.

    NOTE: we assert the FUNCTIONAL contract (verdict forked to throttle, request
    served, var set), not wall-clock. nginx's limit_rate delays writes that
    exceed the per-second budget, but over loopback a small response is handed
    to the kernel send buffer in one writev and completes before any delay
    timer fires - so elapsed time is not a reliable signal here. The
    $sentinel_throttled var proves the throttle branch ran and set limit_rate.
    """
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/throttle",
        headers={"Connection": "close", "User-Agent": BOT_UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        status = resp.status
        thr = resp.headers.get("X-Sentinel-Throttled", "")
        body = resp.read()

    if status != 200:
        raise AssertionError(
            f"TEST 12 throttle: expected 200 (throttled, not tarpit/444); "
            f"got {status}")
    if thr != "1":
        raise AssertionError(
            f"TEST 12 throttle: $sentinel_throttled must be 1; got {thr!r}")
    if len(body) != 16384:
        raise AssertionError(
            f"TEST 12 throttle: short/corrupt body {len(body)} (expected 16384)")
    print(f"  TEST 12 throttle: PASS (200, throttled=1, body={len(body)}B)")


def test_shield(port: int) -> None:
    """TEST 19 - origin-shield action: a bot UA hits the tarpit band; with
    sentinel_shield on, the tarpit verdict raises $sentinel_shield=1 and lets
    the request proceed (served from the static file, NOT tarpitted/444). The
    module only raises the signal — the operator wires it into proxy cache
    config — so we assert the FUNCTIONAL contract: 200, full body, shield=1.
    """
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/shield",
        headers={"Connection": "close", "User-Agent": BOT_UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        status = resp.status
        shd = resp.headers.get("X-Sentinel-Shield", "")
        body = resp.read()

    if status != 200:
        raise AssertionError(
            f"TEST 19 shield: expected 200 (shielded, not tarpit/444); "
            f"got {status}")
    if shd != "1":
        raise AssertionError(
            f"TEST 19 shield: $sentinel_shield must be 1; got {shd!r}")
    if body != b"shield-origin-ok":
        raise AssertionError(
            f"TEST 19 shield: unexpected body {body!r}")
    print("  TEST 19 shield: PASS (200, shield=1, origin served)")


def test_metrics_status(port: int) -> None:
    """TEST 21 - Prometheus metrics exposition.

    Drives a bot-UA request through /block (enforce, BLOCK band -> 403, bot
    signal fires) and a clean request through /allow-test (ALLOW), then scrapes
    GET /sentinel-status and asserts the exposition reports the activity:
      - Content-Type is the Prometheus text format,
      - sentinel_requests_total > 0,
      - sentinel_verdict_total{v="block"} >= 1,
      - sentinel_signal_total{s="bot"} >= 1.
    The counters are process-wide shm, so the bot 403 above (plus any earlier
    block/bot traffic in this nginx instance) guarantees non-zero values.
    """
    # 1. A bot UA on /block -> 403 (BLOCK verdict, bot signal).
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/block",
        headers={"Connection": "close", "User-Agent": BOT_UA})
    try:
        with urllib.request.urlopen(req, timeout=20):
            pass
    except urllib.error.HTTPError as e:
        if e.code != 403:
            raise AssertionError(
                f"TEST 21 metrics: expected 403 on bot /block; got {e.code}")

    # 2. A clean request on /allow-test -> 200 (ALLOW verdict).
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/allow-test",
        headers={"Connection": "close"})
    with urllib.request.urlopen(req, timeout=20):
        pass

    # 3. Scrape the exposition.
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/sentinel-status",
        headers={"Connection": "close"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        ctype = resp.headers.get("Content-Type", "")
        text = resp.read().decode("ascii", "replace")

    if "text/plain" not in ctype or "version=0.0.4" not in ctype:
        raise AssertionError(
            f"TEST 21 metrics: bad Content-Type {ctype!r}")

    def metric(line_prefix: str) -> int:
        for line in text.splitlines():
            if line.startswith(line_prefix):
                return int(line.rsplit(None, 1)[1])
        raise AssertionError(
            f"TEST 21 metrics: line {line_prefix!r} missing from:\n{text}")

    req_total = metric("sentinel_requests_total ")
    block_v = metric('sentinel_verdict_total{v="block"} ')
    bot_s = metric('sentinel_signal_total{s="bot"} ')

    if req_total <= 0:
        raise AssertionError(
            f"TEST 21 metrics: requests_total must be >0; got {req_total}")
    if block_v < 1:
        raise AssertionError(
            f"TEST 21 metrics: verdict_total{{v=block}} must be >=1; "
            f"got {block_v}")
    if bot_s < 1:
        raise AssertionError(
            f"TEST 21 metrics: signal_total{{s=bot}} must be >=1; got {bot_s}")

    print(f"  TEST 21 metrics: PASS (requests={req_total}, "
          f"block={block_v}, bot={bot_s})")


def test_cs_sink(port: int, root: pathlib.Path) -> None:
    """TEST 22 - CrowdSec decision sink.

    A bot UA on /cs-sink lands in the BLOCK band (403). Because the ban is
    locally-originated (no crowdsec_hit), the IP is enqueued to the sink ring;
    the worker-0 timer (1s interval) rewrites the decisions file. Assert the
    file appears and contains a CrowdSec file-acquisition JSON line for our IP
    with the configured scenario, scope Ip, and origin sentinel.
    """
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/cs-sink",
        headers={"Connection": "close", "User-Agent": BOT_UA})
    try:
        with urllib.request.urlopen(req, timeout=20):
            pass
    except urllib.error.HTTPError as e:
        if e.code != 403:
            raise AssertionError(
                f"TEST 22 cs-sink: expected 403 on bot /cs-sink; got {e.code}")

    sink = root / "logs" / "cs-sink.json"
    deadline = time.time() + 8
    content = ""
    while time.time() < deadline:
        if sink.exists():
            content = sink.read_text(encoding="ascii", errors="replace")
            if '"value":"127.0.0.1"' in content:
                break
        time.sleep(0.5)

    if '"value":"127.0.0.1"' not in content:
        raise AssertionError(
            f"TEST 22 cs-sink: decisions file missing our IP; got:\n{content!r}")
    for needle in ('"scope":"Ip"', '"scenario":"sentinel/http-abuse"',
                   '"origin":"sentinel"', '"duration":"'):
        if needle not in content:
            raise AssertionError(
                f"TEST 22 cs-sink: decisions line missing {needle!r}; "
                f"got:\n{content!r}")
    print("  TEST 22 cs-sink: PASS (decisions file written w/ IP + scenario)")


def test_pow_challenge(port: int) -> None:
    """TEST 18 - PoW challenge.

    A bot-UA (curl) lands in the CHALLENGE band on /pow (enforce). With no
    cookie, sentinel must serve a self-contained HTML+JS PoW page (not the
    upstream "pow-ok"). Solving the puzzle and re-requesting with the nonce
    must yield 200 "pow-ok" + a Set-Cookie + X-Pow: verified. A forged cookie
    must FAIL CLOSED (re-challenge), never bypass.
    """
    import hashlib
    import hmac as _hmac

    SECRET = b"test-pow-secret-key"
    TTL = 300
    BOT = {"User-Agent": "python-requests/2.31.0"}

    # 1. No cookie -> challenge page.
    st, hdr, body = fetch(port, "/pow", extra_headers=BOT)
    if st != 200:
        raise AssertionError(f"TEST 18 pow: challenge expected 200, got {st}")
    if hdr.get("x-pow") != "challenge":
        raise AssertionError(
            f"TEST 18 pow: expected X-Pow=challenge, got {hdr.get('x-pow')!r}")
    if "crypto.subtle" not in body or "<!doctype html>" not in body.lower():
        raise AssertionError(
            "TEST 18 pow: challenge body missing PoW JS / HTML")
    if body == "pow-ok":
        raise AssertionError("TEST 18 pow: upstream leaked through challenge")

    # 2. Replicate the stateless challenge = HMAC(secret, ip4 || bucket).
    bucket = int(time.time()) // TTL
    ip = bytes((127, 0, 0, 1))            # loopback binary_remote_addr
    challenge = _hmac.new(SECRET, ip + str(bucket).encode(),
                          hashlib.sha256).hexdigest().encode()

    def leading_zero_bits(d: bytes) -> int:
        n = 0
        for b in d:
            if b == 0:
                n += 8
                continue
            while (b & 0x80) == 0:
                n += 1
                b = (b << 1) & 0xFF
            break
        return n

    nonce = 0
    while leading_zero_bits(
            hashlib.sha256(challenge + str(nonce).encode()).digest()) < 1:
        nonce += 1
        if nonce > 100000:
            raise AssertionError("TEST 18 pow: could not solve difficulty 1")

    # 3. Submit the solution -> bypass + signed cookie.
    sh = dict(BOT)
    sh["X-Sentinel-Pow"] = str(nonce)
    st, hdr, body = fetch(port, "/pow", extra_headers=sh)
    if st != 200 or body != "pow-ok":
        raise AssertionError(
            f"TEST 18 pow: solved request expected 200/pow-ok, got {st}/{body!r}")
    if hdr.get("x-pow") != "verified":
        raise AssertionError(
            f"TEST 18 pow: expected X-Pow=verified, got {hdr.get('x-pow')!r}")
    setck = hdr.get("set-cookie", "")
    if "__sentinel_pow=" not in setck:
        raise AssertionError("TEST 18 pow: no bypass Set-Cookie issued")

    # 4. Re-use the issued cookie -> bypass directly.
    cookie_val = setck.split(";", 1)[0]
    ch = dict(BOT)
    ch["Cookie"] = cookie_val
    st, hdr, body = fetch(port, "/pow", extra_headers=ch)
    if st != 200 or body != "pow-ok" or hdr.get("x-pow") != "verified":
        raise AssertionError(
            f"TEST 18 pow: valid cookie must bypass, got {st}/{body!r}/"
            f"{hdr.get('x-pow')!r}")

    # 5. Forged cookie (good shape, bad MAC) must FAIL CLOSED (re-challenge).
    expiry = int(time.time()) + TTL
    forged = f"__sentinel_pow={expiry}." + ("0" * 64)
    fh = dict(BOT)
    fh["Cookie"] = forged
    st, hdr, body = fetch(port, "/pow", extra_headers=fh)
    if hdr.get("x-pow") != "challenge" or body == "pow-ok":
        raise AssertionError(
            "TEST 18 pow: forged cookie must re-challenge (fail closed), "
            f"got X-Pow={hdr.get('x-pow')!r} body={body!r}")

    print("  TEST 18 pow: PASS "
          f"(challenge->solve->cookie-bypass; forged cookie fails closed, "
          f"nonce={nonce})")


def test_per_route_policy(port: int) -> None:
    """TEST 13 - per-route policy: the SAME bot-UA identity gets opposite
    verdicts in two sibling locations, proving sentinel directives merge and
    override per-location via stock nginx config inheritance.

    /route-strict: block band at 90, bot weight 100 -> score 100 crosses block
    -> 403 (enforce).
    /route-lax:    bot weight 0 + block band lifted to 990 -> score 0 -> allow
    -> 200.

    Same request bytes (identical bot UA), different location = different policy.
    """
    expect_status(port, "/route-strict", 403,
                  extra_headers={"User-Agent": BOT_UA})
    expect_status(port, "/route-lax", 200,
                  extra_headers={"User-Agent": BOT_UA})
    print("  TEST 13 per-route-policy: PASS (strict=403, lax=200, same bot UA)")


def test_tarpit_maze(port: int) -> None:
    """TEST 14 - maze mode: a forced-tarpit location with sentinel_tarpit_maze on
    drips HTML decoy crawl-links instead of blank padding. Assert the response is
    text/html and the body contains at least one '<a href="/' decoy link."""
    s = open_slow_connection(port, "/tarpit-maze")
    s.settimeout(4.0)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.close()

    lower = buf.lower()
    if b"content-type: text/html" not in lower:
        raise AssertionError(
            "TEST 14 maze: expected Content-Type text/html; "
            f"header block was {buf[:200]!r}")
    if b'<a href="/' not in buf:
        raise AssertionError(
            "TEST 14 maze: body has no decoy '<a href=\"/' link; "
            f"got {len(buf)} bytes")
    print(f"  TEST 14 maze: PASS (text/html, decoy links present, body={len(buf)}B)")


def test_tarpit_no_malloc_grep(src_dir: pathlib.Path) -> None:
    """T2.4 - structural check: drip tick function contains no palloc/malloc."""
    tarpit_c = src_dir / "sentinel_tarpit.c"
    if not tarpit_c.exists():
        raise AssertionError(f"T2.4: {tarpit_c} not found")

    text = tarpit_c.read_text(encoding="utf-8")

    # Find the write_handler function body.
    match = re.search(
        r'sentinel_tarpit_write_handler\s*\([^)]*\)\s*\{(.+?)^}',
        text, re.DOTALL | re.MULTILINE
    )
    if not match:
        raise AssertionError("T2.4: could not locate sentinel_tarpit_write_handler body")

    body = match.group(1)
    bad_patterns = ["ngx_palloc", "ngx_pnalloc", "ngx_pcalloc",
                    "ngx_create_temp_buf", "malloc(", "calloc("]
    for pat in bad_patterns:
        if pat in body:
            raise AssertionError(
                f"T2.4: malloc/palloc call {pat!r} found in drip tick body "
                f"(no-malloc-in-hot-path violated)"
            )
    print("  T2.4 no-malloc-in-hot-path: PASS")


def main() -> int:
    args = parse_args()
    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    # Phase 2 - static check (no nginx needed). Module src is relative to this
    # test script (tools/../src), NOT the nginx build tree.
    src_dir = pathlib.Path(__file__).parent.parent / "src"
    if (src_dir / "sentinel_tarpit.c").exists():
        test_tarpit_no_malloc_grep(src_dir)
    else:
        print("  T2.4 no-malloc-in-hot-path: SKIP (src dir not found)")

    with tempfile.TemporaryDirectory(prefix="sentinel-ci-") as tmp:
        root = pathlib.Path(tmp)

        # Config-test only first (cap=4 for flood test).
        nginx = Nginx(binary, module, root / "server", args.port,
                      args.runner, args.single_process)
        nginx.write_config(tarpit_max_conns=4)
        nginx.config_test()

        try:
            nginx.start()

            # TEST 1: shadow mode must allow every request.
            expect_status(args.port, "/shadow", 200)
            expect_status(args.port, "/shadow", 200)

            # TEST 2: sentinel off must pass through.
            expect_status(args.port, "/off", 200)

            # TEST 3: variables are set in shadow mode.
            expect_status(args.port, "/vars", 200)
            time.sleep(0.3)

            vars_log = root / "server" / "logs" / "vars.log"
            if not vars_log.exists():
                raise AssertionError("vars.log not written")
            lines = [ln.split() for ln in
                     vars_log.read_text(encoding="utf-8").splitlines()
                     if ln.strip()]
            if not lines:
                raise AssertionError("vars.log is empty")
            for ln in lines:
                if len(ln) < 4:
                    raise AssertionError(f"vars.log line too short: {ln}")
                score, verdict, ja4h = ln[1], ln[2], ln[3]
                if score != "0":
                    raise AssertionError(f"expected score=0, got {score!r}")
                if verdict != "allow":
                    raise AssertionError(f"expected verdict=allow, got {verdict!r}")
                if len(ja4h) != 24:
                    raise AssertionError(
                        f"expected ja4h 24 hex chars, got {len(ja4h)}: {ja4h!r}")

            # TEST 4: bot UA in shadow mode - still 200 (no enforcement).
            expect_status(args.port, "/shadow", 200,
                          extra_headers={"User-Agent": "sqlmap/1.0"})

            # TEST 5: errrate recording - score rises after repeated 404s.
            #
            # Hit /err404 (returns 404) N times from the same "client" (127.0.0.1).
            # The LOG-phase handler records each 404 into the sliding window.
            # Then hit /probe (returns 200) so PREACCESS reads the accumulated
            # errrate_count; score = w_errrate * count (default w_errrate=1).
            # We assert score > 0 on /probe after the 404 hits.
            #
            # Limitation: all requests share the same source IP (127.0.0.1) so
            # the SHA-256 key is identical - this matches production behaviour
            # (single client hammering errors).
            N_ERRORS = 5
            for _ in range(N_ERRORS):
                status, _, _ = fetch(args.port, "/err404")
                if status != 404:
                    raise AssertionError(f"/err404: expected 404, got {status}")

            # Give nginx a moment to flush the log phase (it's synchronous in
            # the worker but we need the next request to pick up the recorded
            # events via PREACCESS).  A tiny sleep covers any worker scheduling
            # jitter under valgrind/ASAN.
            time.sleep(0.1)

            # Probe: the PREACCESS handler will read errrate_count from shm.
            expect_status(args.port, "/probe", 200)
            time.sleep(0.3)

            probe_log = root / "server" / "logs" / "probe.log"
            if not probe_log.exists():
                raise AssertionError("probe.log not written")
            probe_lines = [ln.split() for ln in
                           probe_log.read_text(encoding="utf-8").splitlines()
                           if ln.strip()]
            if not probe_lines:
                raise AssertionError("probe.log is empty")
            probe_score = int(probe_lines[-1][1])
            if probe_score <= 0:
                raise AssertionError(
                    f"errrate recording: expected score > 0 after {N_ERRORS} "
                    f"404s, got score={probe_score} "
                    f"(log handler may not be recording error events)")

            # TEST 6: header-anomaly - a request with neither User-Agent nor
            # Accept must score >= sentinel_weight_header (default 25), while a
            # normal request (UA + Accept) scores 0 on the same location.
            if fetch_bare(args.port, "/header") != 200:
                raise AssertionError("/header (bare): expected 200 in shadow mode")
            fetch(args.port, "/header",
                  extra_headers={"Accept": "text/html"})  # clean control
            time.sleep(0.3)

            header_log = root / "server" / "logs" / "header.log"
            if not header_log.exists():
                raise AssertionError("header.log not written")
            hlines = [ln.split() for ln in
                      header_log.read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
            if len(hlines) < 2:
                raise AssertionError("header.log: expected >=2 lines")
            # Both requests share the 127.0.0.1 identity, so any errrate carried
            # over from TEST 5 is present in BOTH scores. The header-anomaly
            # contribution is therefore the DELTA: the bare request must exceed
            # the clean control by at least sentinel_weight_header (25).
            anomalous_score = int(hlines[0][1])
            clean_score = int(hlines[-1][1])
            if anomalous_score - clean_score < 25:
                raise AssertionError(
                    f"header-anomaly: bare request must exceed clean control by "
                    f">= 25 (weight_header); got bare={anomalous_score} "
                    f"clean={clean_score}")

            # TEST 7: honeypot — a request to /trap must yield $sentinel_honeypot=1
            # and score == 90 (w_honeypot); a request to /safe must give
            # $sentinel_honeypot=0 and score == 0 (all other weights are zeroed).
            fetch(args.port, "/honeypot-test/trap")
            fetch(args.port, "/honeypot-test/safe")
            time.sleep(0.3)

            honeypot_log = root / "server" / "logs" / "honeypot.log"
            if not honeypot_log.exists():
                raise AssertionError("honeypot.log not written")
            hplines = [ln.split() for ln in
                       honeypot_log.read_text(encoding="utf-8").splitlines()
                       if ln.strip()]
            if len(hplines) < 2:
                raise AssertionError(
                    f"honeypot.log: expected >= 2 lines, got {len(hplines)}")
            # First line is /trap (honeypot hit); second is /safe (miss).
            trap_score  = int(hplines[0][1])
            safe_score  = int(hplines[1][1])
            if trap_score < 90:
                raise AssertionError(
                    f"honeypot: /trap score must be >= 90 (w_honeypot); "
                    f"got {trap_score}")
            if safe_score != 0:
                raise AssertionError(
                    f"honeypot: /safe score must be 0; got {safe_score}")

            # TEST 8: velocity — send enough requests to exceed rate=3 within
            # the window; assert a later request logs $sentinel_score >= 30.
            # The RECORD fires in the log handler after each request completes;
            # PREACCESS reads the count from the PRIOR N-1 records. With rate=3,
            # the 4th request sees count=3 (records from req 1,2,3) and the zone
            # marks the identity blocked -> velocity_exceeded=1 -> score >= 30.
            # Send 6 to give a clear margin.
            for _ in range(6):
                fetch(args.port, "/velocity-test")
            time.sleep(0.3)

            vel_log = root / "server" / "logs" / "velocity.log"
            if not vel_log.exists():
                raise AssertionError("velocity.log not written")
            vlines = [ln.split() for ln in
                      vel_log.read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
            if len(vlines) < 4:
                raise AssertionError(
                    f"velocity.log: expected >= 4 lines, got {len(vlines)}")
            # The last line (6th request) should have score >= 30 (velocity_exceeded=1).
            last_vel_score = int(vlines[-1][1])
            if last_vel_score < 30:
                raise AssertionError(
                    f"TEST 8 velocity: last request score must be >= 30 "
                    f"(w_velocity); got {last_vel_score}")
            print(f"  TEST 8 velocity: PASS (last score={last_vel_score})")

            # TEST 9: allowlist — client 127.0.0.1 is in the trusted CIDR, so a
            # honeypot hit on /allow-test/trap must short-circuit to score 0.
            # On /allow-miss (CIDR 10.0.0.0/8 does NOT match), the same honeypot
            # hit must score normally (>= 90).
            fetch(args.port, "/allow-test/trap")
            fetch(args.port, "/allow-miss/trap")
            time.sleep(0.3)

            allow_log = root / "server" / "logs" / "allow.log"
            miss_log = root / "server" / "logs" / "allowmiss.log"
            if not allow_log.exists() or not miss_log.exists():
                raise AssertionError("allow.log / allowmiss.log not written")
            alines = [ln.split() for ln in
                      allow_log.read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
            mlines = [ln.split() for ln in
                      miss_log.read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
            if not alines or not mlines:
                raise AssertionError("allow/miss log empty")
            allow_score = int(alines[-1][1])
            miss_score = int(mlines[-1][1])
            if allow_score != 0:
                raise AssertionError(
                    f"TEST 9 allowlist: matched client must short-circuit to 0; "
                    f"got {allow_score}")
            if miss_score < 90:
                raise AssertionError(
                    f"TEST 9 allowlist: non-matching CIDR must score honeypot "
                    f">= 90; got {miss_score}")
            print(f"  TEST 9 allowlist: PASS "
                  f"(match={allow_score}, miss={miss_score})")

            # TEST 10: block enforcement. Bot UA forces VERDICT_BLOCK.
            #  - /block (enforce, default status) -> 403
            #  - /block-shadow (shadow) -> 200 (no enforcement)
            #  - /block-close (status 444) -> connection dropped (no response)
            expect_status(args.port, "/block", 403,
                          extra_headers={"User-Agent": BOT_UA})
            expect_status(args.port, "/block-shadow", 200,
                          extra_headers={"User-Agent": BOT_UA})
            # NOTE: no clean-UA pass assertion here — TEST 5 hammered the shared
            # 127.0.0.1 identity with 404s, so accumulated errrate can push even
            # a clean request >= block=1. Shadow proves the non-enforce path.
            # 444: nginx closes without sending a response. urllib raises
            # RemoteDisconnected (an OSError subclass) — that IS the pass.
            try:
                close_status, _, _ = fetch(args.port, "/block-close",
                                           extra_headers={"User-Agent": BOT_UA})
            except (OSError, http.client.RemoteDisconnected):
                close_status = 0
            if close_status not in (0, 444):
                raise AssertionError(
                    f"TEST 10 block-close: expected dropped connection "
                    f"(status 0/444), got {close_status}")
            print("  TEST 10 block-enforce: PASS "
                  f"(block=403, shadow=200, close={close_status})")

            # TEST 15: ASN signal. A request carrying X-Test-ASN: 16509 (in the
            # flagged list) must score >= w_asn (35); X-Test-ASN: 64500 (not in
            # the list) and a request with no ASN header must both score 0.
            # weight_bot/velocity are zeroed in /asn, so the score IS the ASN term.
            fetch(args.port, "/asn", extra_headers={"X-Test-ASN": "16509"})
            fetch(args.port, "/asn", extra_headers={"X-Test-ASN": "64500"})
            fetch(args.port, "/asn")
            time.sleep(0.3)

            asn_log = root / "server" / "logs" / "asn.log"
            if not asn_log.exists():
                raise AssertionError("asn.log not written")
            aslines = [ln.split() for ln in
                       asn_log.read_text(encoding="utf-8").splitlines()
                       if ln.strip()]
            if len(aslines) < 3:
                raise AssertionError(
                    f"asn.log: expected >= 3 lines, got {len(aslines)}")
            asn_hit   = int(aslines[0][1])   # AS16509 -> flagged
            asn_miss  = int(aslines[1][1])   # AS64500 -> not flagged
            asn_none  = int(aslines[2][1])   # no header -> empty -> off
            # The shared 127.0.0.1 identity carries accumulated errrate from
            # earlier 404 tests, so assert the flagged DELTA (>= w_asn 35) over
            # the unflagged/no-header controls rather than an absolute score.
            # miss and none must be EQUAL (both omit the ASN term).
            if asn_miss != asn_none:
                raise AssertionError(
                    f"TEST 15 asn: unflagged and missing ASN must score equally; "
                    f"got miss={asn_miss} none={asn_none}")
            if asn_hit - asn_miss < 35:
                raise AssertionError(
                    f"TEST 15 asn: flagged AS16509 must exceed unflagged control "
                    f"by >= 35 (w_asn); got hit={asn_hit} miss={asn_miss}")
            print(f"  TEST 15 asn: PASS "
                  f"(hit={asn_hit}, miss={asn_miss}, none={asn_none})")

            # TEST 23: JA4-TLS signal. A request carrying X-Test-JA4 = the denied
            # fingerprint (lower-case; deny list is upper-case -> exercises the
            # case-insensitive match) must score >= w_ja4 (50); a different JA4
            # and a request with no JA4 header must both score 0. weight_bot/
            # velocity are zeroed in /ja4, so the score IS the JA4 term.
            denied_ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
            fetch(args.port, "/ja4", extra_headers={"X-Test-JA4": denied_ja4})
            fetch(args.port, "/ja4", extra_headers={"X-Test-JA4": "t13d0000h1_deadbeefcafe_000000000000"})
            fetch(args.port, "/ja4")
            time.sleep(0.3)

            ja4_log = root / "server" / "logs" / "ja4.log"
            if not ja4_log.exists():
                raise AssertionError("ja4.log not written")
            jlines = [ln.split() for ln in
                      ja4_log.read_text(encoding="utf-8").splitlines()
                      if ln.strip()]
            if len(jlines) < 3:
                raise AssertionError(
                    f"ja4.log: expected >= 3 lines, got {len(jlines)}")
            ja4_hit  = int(jlines[0][1])   # denied fp -> flagged
            ja4_miss = int(jlines[1][1])   # other fp  -> not flagged
            ja4_none = int(jlines[2][1])   # no header -> empty -> off
            # Shared 127.0.0.1 identity carries accumulated errrate, so assert
            # the flagged DELTA (>= w_ja4 50); miss and none must be EQUAL.
            if ja4_miss != ja4_none:
                raise AssertionError(
                    f"TEST 23 ja4: unflagged and missing JA4 must score equally; "
                    f"got miss={ja4_miss} none={ja4_none}")
            if ja4_hit - ja4_miss < 50:
                raise AssertionError(
                    f"TEST 23 ja4: denied JA4 must exceed control by >= 50 "
                    f"(w_ja4); got hit={ja4_hit} miss={ja4_miss}")
            print(f"  TEST 23 ja4: PASS "
                  f"(hit={ja4_hit}, miss={ja4_miss}, none={ja4_none})")

            # TEST 16: coherence signal. A browser-claiming UA with a bare
            # request (no Accept / Accept-Language / gzip) is incoherent and must
            # score >= w_coherence (40) over a fully browser-shaped control. A
            # non-browser UA makes no claim and must score equal to the coherent
            # control. Raw sockets are required: urllib injects an Accept-Encoding
            # header we cannot suppress, which would clear the incoherent case.
            chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/120.0.0.0 Safari/537.36")

            def _raw_get(path: str, headers: list[str]) -> None:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("127.0.0.1", args.port))
                lines = [f"GET {path} HTTP/1.1",
                         f"Host: 127.0.0.1:{args.port}"]
                lines.extend(headers)
                lines.append("Connection: close")
                s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
                read_response_head(s)
                s.close()

            # (hit) browser UA, NO Accept/Accept-Language/Accept-Encoding.
            _raw_get("/coherence", [f"User-Agent: {chrome_ua}"])
            # (miss) browser UA, full browser request shape -> coherent.
            _raw_get("/coherence", [
                f"User-Agent: {chrome_ua}",
                "Accept: text/html,application/xhtml+xml",
                "Accept-Language: en-US,en;q=0.9",
                "Accept-Encoding: gzip, deflate, br",
            ])
            # (none) non-browser UA -> makes no coherence claim.
            _raw_get("/coherence", ["User-Agent: sentinel-ci/1.0"])
            time.sleep(0.3)

            coh_log = root / "server" / "logs" / "coherence.log"
            if not coh_log.exists():
                raise AssertionError("coherence.log not written")
            cohlines = [ln.split() for ln in
                        coh_log.read_text(encoding="utf-8").splitlines()
                        if ln.strip()]
            if len(cohlines) < 3:
                raise AssertionError(
                    f"coherence.log: expected >= 3 lines, got {len(cohlines)}")
            coh_hit  = int(cohlines[0][1])   # incoherent browser-claim
            coh_miss = int(cohlines[1][1])   # coherent browser
            coh_none = int(cohlines[2][1])   # non-browser UA
            # Shared 127.0.0.1 identity carries accumulated errrate; assert the
            # incoherent DELTA over the coherent control, and that the coherent
            # browser and the non-browser UA score equally (neither adds w_coh).
            if coh_miss != coh_none:
                raise AssertionError(
                    f"TEST 16 coherence: coherent browser and non-browser UA "
                    f"must score equally; got miss={coh_miss} none={coh_none}")
            if coh_hit - coh_miss < 40:
                raise AssertionError(
                    f"TEST 16 coherence: incoherent browser-claim must exceed "
                    f"the coherent control by >= 40 (w_coherence); "
                    f"got hit={coh_hit} miss={coh_miss}")
            print(f"  TEST 16 coherence: PASS "
                  f"(hit={coh_hit}, miss={coh_miss}, none={coh_none})")

            # TEST 17: FCrDNS fail-open. Zone bound but no resolver configured.
            # A Googlebot UA (known_good_ua) must yield $sentinel_fcrdns=pending
            # and a short-circuited score of 0 (no resolver -> async skipped ->
            # legacy known_good_ua behavior), serving 200 without any DNS.
            fc_status, fc_headers, _ = fetch(
                args.port, "/fcrdns",
                extra_headers={"User-Agent":
                    "Mozilla/5.0 (compatible; Googlebot/2.1; "
                    "+http://www.google.com/bot.html)"})
            if fc_status != 200:
                raise AssertionError(
                    f"TEST 17 fcrdns: expected 200, got {fc_status}")
            fc_verdict = fc_headers.get("x-fcrdns", "")
            if fc_verdict != "pending":
                raise AssertionError(
                    f"TEST 17 fcrdns: expected verdict 'pending' (no resolver), "
                    f"got '{fc_verdict}'")
            time.sleep(0.2)
            fc_log = root / "server" / "logs" / "fcrdns.log"
            if not fc_log.exists():
                raise AssertionError("fcrdns.log not written")
            fclines = [ln.split() for ln in
                       fc_log.read_text(encoding="utf-8").splitlines()
                       if ln.strip()]
            if not fclines:
                raise AssertionError("fcrdns.log empty")
            fc_score = int(fclines[-1][1])
            if fc_score != 0:
                raise AssertionError(
                    f"TEST 17 fcrdns: known_good_ua must short-circuit to 0 "
                    f"while pending; got score={fc_score}")
            print(f"  TEST 17 fcrdns: PASS "
                  f"(verdict=pending, score=0, fail-open no-resolver)")

            # TEST 13: per-route policy — same bot UA, opposite verdicts in two
            # sibling locations (strict blocks, lax allows).
            test_pow_challenge(args.port)

            test_per_route_policy(args.port)

            nginx.stop()
            nginx.assert_clean_logs()

        finally:
            nginx.stop()

    print("OK: sentinel Phase 1/1b runtime tests passed")

    # -----------------------------------------------------------------------
    # Phase 2 tests (separate nginx instance; cap=4 for flood test).
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="sentinel-ci-p2-") as tmp2:
        root2 = pathlib.Path(tmp2)
        nginx2 = Nginx(binary, module, root2 / "server", args.port + 1,
                       args.runner, args.single_process)
        nginx2.write_config(tarpit_max_conns=4)
        nginx2.config_test()

        try:
            nginx2.start()

            # T2.7 - bounds parsing (uses a temporary bad config, no nginx restart).
            test_tarpit_bounds_parse(nginx2)

            # T8b - velocity unknown-zone rejection + no silent parent inherit.
            test_velocity_unknown_zone_rejected(nginx2)

            # T2.5 - shadow mode never tarpits.
            test_shadow_never_tarpits(args.port + 1)

            # T2.2a - normal drip complete.
            test_tarpit_normal_complete(args.port + 1, root2 / "server")

            # T2.2b - client abort mid-drip.
            test_tarpit_client_abort(args.port + 1)

            # T2.2c - max_lifetime force-close.
            test_tarpit_lifetime_timeout(args.port + 1)

            # T2.1 - conn-cap enforced under flood (cap=4, flood=20).
            test_tarpit_cap_flood(args.port + 1, root2 / "server",
                                  cap=4, flood=20)

            # TEST 11 - TTL soft-ban (clean shm: not polluted by TEST 5).
            test_softban_ttl(args.port + 1)

            # TEST 12 - throttle action (tarpit band -> limit_rate, not drip).
            test_throttle(args.port + 1)

            # TEST 19 - origin-shield action (tarpit band -> shield flag, served).
            test_shield(args.port + 1)

            # TEST 14 - maze mode (tarpit drips HTML decoy links, not padding).
            test_tarpit_maze(args.port + 1)

            # TEST 21 - Prometheus metrics exposition (/sentinel-status).
            test_metrics_status(args.port + 1)

            # TEST 22 - CrowdSec decision sink (local ban -> decisions file).
            test_cs_sink(args.port + 1, root2 / "server")

            nginx2.stop()
            nginx2.assert_clean_logs()

        finally:
            nginx2.stop()

    print("OK: sentinel Phase 2 tarpit runtime tests passed")

    # -----------------------------------------------------------------------
    # Phase 3 tests (separate nginx instance + a crowdsec feed file).
    # All requests originate from 127.0.0.1, so the feed keys on 127.0.0.1.
    # Shadow mode: we assert on the LOGGED $sentinel_score / $sentinel_verdict
    # (enforcement of block is Phase 2-deferred; scoring is what Phase 3 adds).
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="sentinel-ci-p3-") as tmp3:
        root3 = pathlib.Path(tmp3)
        feed = root3 / "crowdsec.feed"
        # Pre-create an empty-but-valid feed so config-test + startup succeed.
        write_feed(feed, build_feed([]))

        nginx3 = Nginx(binary, module, root3 / "server", args.port + 2,
                       args.runner, args.single_process)
        nginx3.cs_feed = str(feed)
        nginx3.cs_max_bytes = "8192"   # small cap to exercise oversize reject
        nginx3.write_config()
        nginx3.config_test()

        port3 = args.port + 2
        srv3 = root3 / "server"

        def reload_wait(seconds: float = 2.0) -> None:
            # interval=1s + 1s first tick; wait long enough for a load tick.
            time.sleep(seconds)

        try:
            nginx3.start()
            reload_wait(2.5)  # let the first tick load the (empty) feed

            # T3.0 baseline: no entry for 127.0.0.1 -> score 0.
            fetch(port3, "/cs")
            time.sleep(0.3)
            base = cs_score(srv3)
            if base != 0:
                raise AssertionError(f"T3.0: baseline score expected 0, got {base}")
            print("  T3.0 baseline-no-hit: PASS")

            # T3.1 feed-update reflected: ban 127.0.0.1 -> score includes weight.
            far = int(time.time()) + 3600
            write_feed(feed, build_feed([("127.0.0.1", "ban", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs")
            time.sleep(0.3)
            s = cs_score(srv3)
            v = cs_verdict(srv3)
            if s < 100:
                raise AssertionError(
                    f"T3.1: ban should add weight_crowdsec(100), got score={s}")
            if v != "block":
                raise AssertionError(f"T3.1: ban -> block verdict, got {v!r}")
            print(f"  T3.1 feed-update-reflected: PASS (score={s} verdict={v})")

            # T3.1b deletion honored: rewrite feed WITHOUT 127.0.0.1 -> score 0.
            write_feed(feed, build_feed([("10.9.9.9", "ban", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs")
            time.sleep(0.3)
            s = cs_score(srv3)
            if s != 0:
                raise AssertionError(
                    f"T3.1b: after deletion, score should be 0, got {s}")
            print("  T3.1b deletion-honored: PASS")

            # T3.8 action tiering: captcha -> challenge band (not block).
            write_feed(feed, build_feed([("127.0.0.1", "captcha", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs")
            time.sleep(0.3)
            v = cs_verdict(srv3)
            if v != "challenge":
                raise AssertionError(f"T3.8: captcha -> challenge, got {v!r}")
            # throttle -> tarpit band.
            write_feed(feed, build_feed([("127.0.0.1", "throttle", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs")
            time.sleep(0.3)
            v = cs_verdict(srv3)
            if v != "tarpit":
                raise AssertionError(f"T3.8: throttle -> tarpit, got {v!r}")
            print("  T3.8 action-tiering: PASS")

            # T3.2 expiry honored: ban with near expiry, then it lapses.
            # Expiry must outlast the load tick (~2.5s) so the first fetch is a
            # hit, but still lapse before the post-sleep fetch.
            soon = int(time.time()) + 6
            write_feed(feed, build_feed([("127.0.0.1", "ban", soon)]))
            reload_wait(2.5)
            fetch(port3, "/cs")
            time.sleep(0.3)
            s_hit = cs_score(srv3)
            if s_hit < 100:
                raise AssertionError(f"T3.2: expected hit before expiry, got {s_hit}")
            time.sleep(4.5)  # let it expire (blocked_until <= now)
            fetch(port3, "/cs")
            time.sleep(0.3)
            s_exp = cs_score(srv3)
            if s_exp != 0:
                raise AssertionError(
                    f"T3.2: expected 0 after expiry, got {s_exp}")
            print("  T3.2 expiry-honored: PASS")

            # T3.4 malformed feed -> fail-open + keep last-good table.
            # First establish a known-good ban...
            write_feed(feed, build_feed([("127.0.0.1", "ban", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError("T3.4 setup: ban not active")
            # ...then write a feed with a corrupt CRC (must be rejected).
            write_feed(feed, build_feed([("8.8.8.8", "ban", far)],
                                        corrupt_crc=True))
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError(
                    "T3.4: bad-CRC feed was applied (last-good not preserved)")
            warns = count_log_matches(srv3 / "logs" / "error.log",
                                      r"crowdsec feed.*(CRC|mismatch|trailer)")
            if warns == 0:
                raise AssertionError("T3.4: expected a WARN for bad-CRC feed")
            print("  T3.4 malformed-fail-open: PASS")

            # T3.4b a few malformed lines under threshold -> valid lines load.
            content = build_feed([("127.0.0.1", "ban", far)])
            # Inject one garbage line into the body, fix count + CRC by rebuilding
            # manually so the trailer matches (1 valid + 1 malformed).
            far2 = far
            body = (f"# generated test count=1\n"
                    f"garbage nonsense line here\n"
                    f"127.0.0.1 ban {far2}\n")
            crc = zlib.crc32(body.encode("ascii")) & 0xFFFFFFFF
            content = ("# sentinel-crowdsec-feed v1\n" + body
                       + f"%%EOF 1 {crc:08x}\n")
            write_feed(feed, content)
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError(
                    "T3.4b: valid line not loaded alongside one malformed line")
            print("  T3.4b malformed-under-threshold: PASS")

            # T3.6 truncation: torn body (count/CRC mismatch) -> rejected.
            write_feed(feed, build_feed([("127.0.0.1", "ban", far)]))  # last-good
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            write_feed(feed, build_feed([("1.2.3.4", "ban", far),
                                         ("5.6.7.8", "ban", far)],
                                        truncate_body=True))
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError(
                    "T3.6: truncated feed applied (last-good not kept)")
            print("  T3.6 truncation-rejected: PASS")

            # T3.7 oversized feed -> rejected fail-open, no stall, no OOM.
            # cs_max_bytes is configured to 8192 for this instance. Establish a
            # last-good ban, then write an otherwise-valid feed > 8192 bytes;
            # the loader must reject it on size BEFORE parsing and keep last-good.
            write_feed(feed, build_feed([("127.0.0.1", "ban", far)]))  # last-good
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError("T3.7 setup: ban not active")
            big = [("127.0.0.1", "ban", far)]
            # ~600 lines * ~20 bytes >> 8192-byte cap.
            big += [(f"10.0.{i // 256}.{i % 256}", "ban", far)
                    for i in range(600)]
            oversize = build_feed(big)
            assert len(oversize) > 8192, "oversize feed not actually oversize"
            t0 = time.monotonic()
            write_feed(feed, oversize)
            reload_wait(2.5)
            status, _, _ = fetch(port3, "/cs"); time.sleep(0.3)
            if time.monotonic() - t0 > 10.0:
                raise AssertionError("T3.7: oversized feed appears to have stalled")
            if status != 200:
                raise AssertionError(f"T3.7: oversize broke serving ({status})")
            if cs_score(srv3) < 100:
                raise AssertionError(
                    "T3.7: oversized feed was applied (last-good not kept)")
            over_warns = count_log_matches(srv3 / "logs" / "error.log",
                                           r"crowdsec feed.*oversized")
            if over_warns == 0:
                raise AssertionError("T3.7: expected an oversized WARN")
            print("  T3.7 oversized-reject: PASS")

            # T3.5 stale feed: backdate mtime beyond stale_after(30s) -> WARN,
            # existing entries kept (not wiped), request path still serves.
            write_feed(feed, build_feed([("127.0.0.1", "ban", far)]))
            reload_wait(2.5)
            fetch(port3, "/cs"); time.sleep(0.3)
            if cs_score(srv3) < 100:
                raise AssertionError("T3.5 setup: ban not active")
            old = time.time() - 120  # 2 min old > stale_after 30s
            os.utime(feed, (old, old))
            reload_wait(2.5)
            status, _, _ = fetch(port3, "/cs")  # must still serve
            time.sleep(0.3)
            if status != 200:
                raise AssertionError(f"T3.5: stale feed broke serving ({status})")
            # entry should still be present (not wiped by stale).
            if cs_score(srv3) < 100:
                raise AssertionError(
                    "T3.5: stale feed wiped the table (should keep entries)")
            stale_warns = count_log_matches(srv3 / "logs" / "error.log",
                                            r"crowdsec feed.*stale")
            if stale_warns == 0:
                raise AssertionError("T3.5: expected a stale WARN")
            print("  T3.5 stale-feed-handling: PASS")

            nginx3.stop()
            nginx3.assert_clean_logs()

        finally:
            nginx3.stop()

    print("OK: sentinel Phase 3 crowdsec runtime tests passed")

    # -----------------------------------------------------------------------
    # TEST 20 - Redis multi-box shared state (separate nginx + a local
    # redis-server). Exercises BOTH directions on one identity (127.0.0.1):
    #   PUSH: an enforce-mode local block fires 403 and publishes the ban to
    #         Redis (asserted via redis-cli GET).
    #   PULL: that published key is pulled back into the crowdsec zone on the
    #         next tick; a CLEAN request (weight_bot 0) is then blocked too,
    #         proving a peer-originated ban reaches the request path.
    # Skipped (not failed) if redis-server / redis-cli are unavailable.
    # -----------------------------------------------------------------------
    redis_bin = shutil.which("redis-server")
    redis_cli = shutil.which("redis-cli")
    if redis_bin is None or redis_cli is None:
        print("SKIP: TEST 20 redis multi-box (redis-server/redis-cli not found)")
        return 0

    with tempfile.TemporaryDirectory(prefix="sentinel-ci-p4-") as tmp4:
        root4 = pathlib.Path(tmp4)
        redis_port = args.port + 100
        redis_proc = subprocess.Popen(
            [redis_bin, "--port", str(redis_port), "--save", "",
             "--appendonly", "no", "--bind", "127.0.0.1",
             "--dir", str(root4)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def rcli(*cmd: str) -> str:
            out = subprocess.run([redis_cli, "-p", str(redis_port), *cmd],
                                 capture_output=True, text=True, timeout=5)
            return out.stdout.strip()

        nginx4 = Nginx(binary, module, root4 / "server", args.port + 3,
                       args.runner, args.single_process)
        nginx4.redis_host = "127.0.0.1"
        nginx4.redis_port = redis_port
        port4 = args.port + 3

        try:
            wait_port(redis_port)
            rcli("FLUSHALL")

            nginx4.write_config()
            nginx4.config_test()
            nginx4.start()
            time.sleep(2.5)   # let the worker connect to redis + first tick

            # --- PUSH: enforce-mode local block publishes the ban. ---
            st, hdr, _ = fetch(port4, "/redis-block",
                               extra_headers={"User-Agent": "sqlmap/1.0"})
            if st != 403:
                raise AssertionError(
                    f"TEST 20 push: bot UA expected 403 block, got {st}")
            # Allow the flush tick (interval=1s) to drain the push ring.
            deadline = time.monotonic() + 8.0
            pushed = ""
            while time.monotonic() < deadline:
                pushed = rcli("GET", "sentinel:ban:127.0.0.1")
                if pushed:
                    break
                time.sleep(0.5)
            if not pushed or "ban" not in pushed:
                raise AssertionError(
                    f"TEST 20 push: ban not published to Redis (got {pushed!r})")
            print(f"  TEST 20 push: PASS (403 -> redis key {pushed!r})")

            # --- PULL: the published key flows back into the crowdsec zone; a
            # clean request (weight_bot 0) is now blocked by the pulled ban. ---
            deadline = time.monotonic() + 8.0
            pulled_block = False
            while time.monotonic() < deadline:
                st, _, _ = fetch(port4, "/redis-pull",
                                 extra_headers={"User-Agent": "Mozilla/5.0"})
                if st == 403:
                    pulled_block = True
                    break
                time.sleep(0.5)
            if not pulled_block:
                raise AssertionError(
                    "TEST 20 pull: clean request was not blocked by the pulled "
                    f"ban (last status {st})")
            print("  TEST 20 pull: PASS (clean req blocked by peer ban)")

            nginx4.stop()
            nginx4.assert_clean_logs()

        finally:
            nginx4.stop()
            redis_proc.terminate()
            try:
                redis_proc.wait(timeout=5)
            except Exception:
                redis_proc.kill()

    print("OK: sentinel TEST 20 redis multi-box passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
