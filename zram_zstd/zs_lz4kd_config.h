/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
// 为上游普通 block 编解码器提供 freestanding 类型及内核标记，不启用 delta 字典。
#include <linux/module.h>
#include <linux/types.h>
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error LZ4KD block format requires little endian
#endif
