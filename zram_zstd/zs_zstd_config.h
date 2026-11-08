/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include "common/error_private.h"

// 与固定上游 ZSTD_isError 使用同一 predicate，不复制版本相关错误阈值。
static inline __attribute__((always_inline)) unsigned int zs_zstd_is_error(size_t code) { return ERR_isError(code); }
