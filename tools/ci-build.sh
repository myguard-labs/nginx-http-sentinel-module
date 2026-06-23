#!/usr/bin/env bash

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODE="${3:-debug}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        BINARY="nginx"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        BINARY="angie"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

mkdir -p "$ROOT"
if [ ! -f "$ROOT/${DIR}.tar.gz" ]; then
    curl -fsSL "$URL" -o "$ROOT/${DIR}.tar.gz"
fi
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
fi

CC_OPT="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"
if [ "$MODE" = "asan" ]; then
    # nginx core's own debug logging (ngx_vslprintf/ngx_sprintf_str) passes a
    # NULL+len=0 buffer that UBSan flags as nonnull-attribute/pointer-overflow.
    # These fire in nginx core, not the module, and abort the run under
    # -fno-sanitize-recover. Suppress just those two core-noise checks on BOTH
    # compilers (gcc + clang); keep every other UBSan check live. `function` is
    # clang-only (gcc rejects it), so add it only on clang.
    SAN="-fsanitize=address,undefined -fno-sanitize=nonnull-attribute,pointer-overflow -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
        SAN="-fsanitize=address,undefined -fno-sanitize=function,nonnull-attribute,pointer-overflow -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    fi
    CC_OPT="$SAN"
    LD_OPT="$SAN"
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

WITH_CC=""
if [ -n "${CC:-}" ]; then
    WITH_CC="--with-cc=$CC"
fi

cd "$ROOT/$DIR"
# shellcheck disable=SC2086
./configure \
    --with-compat \
    --with-debug \
    --with-threads \
    --with-http_realip_module \
    $WITH_CC \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" != "asan" ]; then
    make -j"$(nproc)" modules
fi

if [ "$MODE" != "module" ]; then
    make -j"$(nproc)"
    printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
fi

if [ "$MODE" != "asan" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_sentinel_module.so"
fi

# ---------------------------------------------------------------------------
# Unit tests: pure-C score functions (no nginx link required).
# ---------------------------------------------------------------------------
UNIT_BIN="$ROOT/test_score"
cc -std=c99 -I "$MODULE_DIR/src" -o "$UNIT_BIN" "$MODULE_DIR/t/test_score.c"
"$UNIT_BIN"

# ---------------------------------------------------------------------------
# Test::Nginx black-box suite (t/basic.t). Needs the dynamic module + a real
# binary, so skip on asan (no module built) and module-only modes. Soft-skip
# if Test::Nginx / prove are absent so a bare dev box still builds.
# NOTE: Test::Nginx injects its own Host header; pass extra request headers via
# `--- more_headers`, NOT a raw `--- request eval` (that yields a dup-Host
# anomaly and skews the score). See t/basic.t header comment.
# ---------------------------------------------------------------------------
if [ "$MODE" != "asan" ] && [ "$MODE" != "module" ]; then
    if command -v prove >/dev/null 2>&1 \
       && perl -MTest::Nginx::Socket -e1 >/dev/null 2>&1; then
        echo "[ci-build] running t/basic.t (Test::Nginx)"
        # Test::Nginx derives servroot from the .t file's dir, which for an
        # out-of-tree binary can resolve under the (non-writable / absent)
        # build tree. Pin it to a writable path next to the test file.
        SERVROOT="$MODULE_DIR/t/servroot"
        rm -rf "$SERVROOT"
        TEST_NGINX_BINARY="$ROOT/$DIR/objs/$BINARY" \
        TEST_NGINX_SERVROOT="$SERVROOT" \
        TEST_NGINX_LOAD_MODULES="$ROOT/$DIR/objs/ngx_http_sentinel_module.so" \
        prove "$MODULE_DIR/t/basic.t"
    else
        echo "[ci-build] SKIP t/basic.t (prove / Test::Nginx not installed)"
    fi
fi
