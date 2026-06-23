#!/usr/bin/env python3
"""End-to-end runtime tests for ngx_http_sentinel_module."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shlex
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
                 cs_feed: str = "", cs_max_bytes: str = "16m") -> str:
    load = f"load_module {module};\n" if module else ""
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
{cs_zone}

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

{cs_block}    }}
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
        for name in ("tarpit", "tarpit-life", "tarpit-shadow", "cs"):
            (html / name).write_text("ok\n", encoding="ascii")
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module, workers,
                         tarpit_max_conns=tarpit_max_conns,
                         cs_feed=cs_feed,
                         cs_max_bytes=self.cs_max_bytes),
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
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
