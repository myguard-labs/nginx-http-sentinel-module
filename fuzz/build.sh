#!/bin/sh
# Copyright (c) 2026 Eilander
# SPDX-License-Identifier: MIT
#
# fuzz/build.sh -- Build all libFuzzer targets for ngx_http_sentinel_module.
#
# Usage:
#   bash fuzz/build.sh             # build all targets into fuzz/bin/
#   bash fuzz/build.sh clean       # remove fuzz/bin/
#
# Requirements: clang with -fsanitize=fuzzer support, libssl-dev.
# The nginx source tree must be present at .build/nginx-<VER>/ (as populated
# by tools/ci-build.sh or a prior module build).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN_DIR="$REPO_ROOT/fuzz/bin"

if [ "${1:-}" = "clean" ]; then
    rm -rf "$BIN_DIR"
    echo "fuzz/bin/ removed"
    exit 0
fi

# --- Locate nginx source headers. ------------------------------------------
# Accept NGINX_VERSION from the environment or auto-detect from .build/.
if [ -z "${NGINX_VERSION:-}" ]; then
    NGINX_VERSION=$(ls "$REPO_ROOT/.build/" 2>/dev/null \
        | grep '^nginx-' | grep -v '\.tar' | sed 's/^nginx-//' | sort -V | tail -1)
fi
if [ -z "$NGINX_VERSION" ]; then
    echo "ERROR: could not determine NGINX_VERSION; run tools/ci-build.sh first" >&2
    exit 1
fi

NGX_SRC="$REPO_ROOT/.build/nginx-$NGINX_VERSION"
if [ ! -d "$NGX_SRC/src/core" ]; then
    echo "ERROR: nginx source not found at $NGX_SRC" >&2
    echo "       Run: bash tools/ci-build.sh nginx $NGINX_VERSION" >&2
    exit 1
fi

echo "Using nginx source: $NGX_SRC"
echo "Building into: $BIN_DIR"
mkdir -p "$BIN_DIR"

# --- Compiler flags. --------------------------------------------------------
CC="${CC:-clang}"
SANITIZERS="-fsanitize=fuzzer,address,undefined"
COMMON_CFLAGS="-std=c99 -g -O1 $SANITIZERS -fno-omit-frame-pointer"

# fuzz_feed does not need OpenSSL SHA256 (uses a no-op stub).
# fuzz_ja4h links against OpenSSL for the real SHA256 call.
OPENSSL_CFLAGS=""
OPENSSL_LDFLAGS="-lssl -lcrypto"

# --- Build fuzz_feed (CrowdSec feed parser). --------------------------------
# Standalone: all nginx types are stubbed in the target file itself;
# no nginx headers are included.
echo
echo "==> Building fuzz_feed ..."
"$CC" $COMMON_CFLAGS \
    -I "$REPO_ROOT/src" \
    -o "$BIN_DIR/fuzz_feed" \
    "$REPO_ROOT/fuzz/fuzz_feed.c"
echo "    OK: $BIN_DIR/fuzz_feed"

# --- Build fuzz_botua (bot-UA substring scanner). ---------------------------
# Standalone: no OpenSSL, no nginx headers.
echo
echo "==> Building fuzz_botua ..."
"$CC" $COMMON_CFLAGS \
    -I "$REPO_ROOT/src" \
    -o "$BIN_DIR/fuzz_botua" \
    "$REPO_ROOT/fuzz/fuzz_botua.c"
echo "    OK: $BIN_DIR/fuzz_botua"

# --- Build fuzz_ja4h_canon (JA4H canonical-string builder). ----------------
# Needs OpenSSL SHA256.
echo
echo "==> Building fuzz_ja4h_canon ..."
"$CC" $COMMON_CFLAGS \
    -I "$REPO_ROOT/src" \
    $OPENSSL_CFLAGS \
    -o "$BIN_DIR/fuzz_ja4h_canon" \
    "$REPO_ROOT/fuzz/fuzz_ja4h_canon.c" \
    $OPENSSL_LDFLAGS
echo "    OK: $BIN_DIR/fuzz_ja4h_canon"

echo
echo "Build complete. Binaries in $BIN_DIR/"
echo
echo "Quick smoke-run (each target 15 s):"
echo "  $BIN_DIR/fuzz_feed    -max_total_time=15 $REPO_ROOT/fuzz/corpus/fuzz_feed"
echo "  $BIN_DIR/fuzz_botua   -max_total_time=15 $REPO_ROOT/fuzz/corpus/fuzz_botua"
echo "  $BIN_DIR/fuzz_ja4h_canon -max_total_time=15 $REPO_ROOT/fuzz/corpus/fuzz_ja4h"
