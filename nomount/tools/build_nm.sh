#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Build upstream NoMount nm; added by Codex (OpenAI), 2026-10-13.
set -eu

: "${ANDROID_NDK:?Set ANDROID_NDK to the Android NDK root}"
if [ -z "${NDK_HOST_TAG:-}" ]; then
    case "$(uname -s)" in
        Darwin) NDK_HOST_TAG=darwin-x86_64 ;;
        Linux) NDK_HOST_TAG=linux-x86_64 ;;
        *) printf '%s\n' 'Set NDK_HOST_TAG for this host.' >&2; exit 1 ;;
    esac
fi
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${1:?Pass an output path for nm}"
exec "$ANDROID_NDK/toolchains/llvm/prebuilt/$NDK_HOST_TAG/bin/clang" \
    --target=aarch64-linux-android21 -Oz -mcmodel=tiny -static -nostdlib \
    -ffreestanding -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -fno-stack-protector -fno-ident -Wno-invalid-noreturn \
    -Wl,--entry=_start -Wl,--build-id=none "$SCRIPT_DIR/nm.c" -o "$1"
