/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include "zs_memory.h"
// freestanding block API；ARM64 标量位扫描使用编译器 intrinsic，不需要 SIMD 上下文。
#define LZ4_FREESTANDING 1
#define LZ4_FAST_DEC_LOOP 0
#define LZ4_memcpy zs_memcpy
#define LZ4_memmove zs_memmove
#define LZ4_memset zs_memset
