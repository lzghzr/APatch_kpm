/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include <linux/types.h>

/* Experimental v1: 16 KiB block, 14-bit distance, 5-bit repeat/literal lengths. */
#define ZS_LZ4KD16_BLOCK 16384U
#define ZS_LZ4KD16_HEADER 0x10U
#define ZS_LZ4KD16_HASH_SLOTS 4096U
/* Largest literal-only block: header + tag + extensions + input. */
#define ZS_LZ4KD16_BOUND (4U + (ZS_LZ4KD16_BLOCK - 31U) / 255U + 1U + ZS_LZ4KD16_BLOCK)

struct zs_lz4kd16_ctx {
  uint16_t hash[ZS_LZ4KD16_HASH_SLOTS];
  uint8_t scratch[ZS_LZ4KD16_BOUND];
};

/* Nonoverlapping input/output; context is caller-owned and reused, never stack-allocated in a KPM. */
int zs_lz4kd16_compress(struct zs_lz4kd16_ctx* ctx, const uint8_t* src, unsigned int slen, uint8_t* dst,
                        unsigned int* dlen);
/* On error dlen is unchanged; decompression may have written a partial output. */
int zs_lz4kd16_decompress(const uint8_t* src, unsigned int slen, uint8_t* dst, unsigned int* dlen);
