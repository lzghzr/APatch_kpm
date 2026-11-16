#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Build upstream NoMount nm; added by Codex (OpenAI), 2026-10-13.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${1:?Pass an output path for nm}"
if [ -n "${ZIG:-}" ]; then
    exec "$ZIG" cc -target aarch64-linux-musl -Oz -static \
        -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident \
        -Wl,--build-id=none "$SCRIPT_DIR/nm.c" -o "$1"
fi
# Existing NDK CI entry point builds the same source with static Android libc.
: "${ANDROID_NDK:?Set ZIG to zig, or ANDROID_NDK to the Android NDK root}"
if [ -z "${NDK_HOST_TAG:-}" ]; then
    case "$(uname -s)" in
        Darwin) NDK_HOST_TAG=darwin-x86_64 ;;
        Linux) NDK_HOST_TAG=linux-x86_64 ;;
        *) printf '%s\n' 'Set NDK_HOST_TAG for this host.' >&2; exit 1 ;;
    esac
fi
exec "$ANDROID_NDK/toolchains/llvm/prebuilt/$NDK_HOST_TAG/bin/clang" \
    --target=aarch64-linux-android21 -Oz -static \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident \
    -Wl,--build-id=none "$SCRIPT_DIR/nm.c" -o "$1"
