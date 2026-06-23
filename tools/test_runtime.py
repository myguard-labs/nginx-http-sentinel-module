#!/usr/bin/env python3
"""End-to-end runtime tests for ngx_http_sentinel_module."""

from __future__ import annotations

import argparse
import os
import pathlib
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
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
                 module: pathlib.Path | None, workers: int) -> str:
    load = f"load_module {module};\n" if module else ""
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

    server {{
        listen 127.0.0.1:{port};

        # Shadow mode: sentinel on, shadow (default) - must pass every request.
        location = /shadow {{
            sentinel on;
            sentinel_mode shadow;
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
            access_log {root}/logs/vars.log sentinelvars;
            return 200 "vars";
        }}

        # errrate recording: returns 404 so the log handler records each hit.
        location = /err404 {{
            sentinel on;
            sentinel_mode shadow;
            access_log {root}/logs/err404.log sentinelvars;
            return 404 "not found";
        }}

        # Score probe: returns 200 so PREACCESS reads accumulated errrate count.
        location = /probe {{
            sentinel on;
            sentinel_mode shadow;
            access_log {root}/logs/probe.log sentinelvars;
            return 200 "probe";
        }}
    }}
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
        self.process: subprocess.Popen[str] | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self) -> None:
        workers = 1 if self.single_process else 2
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module, workers),
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


def main() -> int:
    args = parse_args()
    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    with tempfile.TemporaryDirectory(prefix="sentinel-ci-") as tmp:
        root = pathlib.Path(tmp)

        # Config-test only first.
        nginx = Nginx(binary, module, root / "server", args.port,
                      args.runner, args.single_process)
        nginx.write_config()
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

            nginx.stop()
            nginx.assert_clean_logs()

        finally:
            nginx.stop()

    print("OK: sentinel Phase 1/1b runtime tests passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
