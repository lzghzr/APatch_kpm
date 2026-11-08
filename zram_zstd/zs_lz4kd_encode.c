/* SPDX-License-Identifier: GPL-2.0-only */
// 平台 private 头必须先于原始编码器解析，确保原始 private 头被同 guard 替代。
// clang-format off
#include "zs_lz4kd_private.h"
#include "upstream/lz4kd/lz4kd_encode.c"
// clang-format on
