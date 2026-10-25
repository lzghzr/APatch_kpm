/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
// freestanding block API；禁用分配、汇编优化循环及硬件 bitcount 路径。
#define LZ4_FREESTANDING 1
#define LZ4_FAST_DEC_LOOP 0
#define LZ4_FORCE_SW_BITCOUNT
#define LZ4_memcpy __builtin_memcpy
#define LZ4_memmove __builtin_memmove
#define LZ4_memset __builtin_memset
