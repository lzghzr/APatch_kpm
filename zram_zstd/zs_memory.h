/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include <stddef.h>

extern void* (*kf_memcpy)(void* dest, const void* src, size_t n);
extern void* (*kf_memmove)(void* dest, const void* src, size_t n);
extern void* (*kf_memset)(void* dest, int value, size_t n);

// 小的已知长度保留编译器展开；外调直接走 KP 指针，不经本模块 libc 符号。
// 阈值仅选择代码生成方式，不限制调用长度；NDK 标量 O2 的 copy/move=128、zero-fill=256。
static inline __attribute__((always_inline)) void* zs_memcpy(void* dest, const void* src, size_t n) {
  if (__builtin_constant_p(n) && n <= 128)
    return __builtin_memcpy(dest, src, n);
  return kf_memcpy(dest, src, n);
}

static inline __attribute__((always_inline)) void* zs_memmove(void* dest, const void* src, size_t n) {
  if (__builtin_constant_p(n) && n <= 128)
    return __builtin_memmove(dest, src, n);
  return kf_memmove(dest, src, n);
}

static inline __attribute__((always_inline)) void* zs_memset(void* dest, int value, size_t n) {
  if (__builtin_constant_p(n) && n <= 256)
    return __builtin_memset(dest, value, n);
  return kf_memset(dest, value, n);
}
