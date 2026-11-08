/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ZRAM_CODEC_BENCH_BRIDGE_H
#define ZRAM_CODEC_BENCH_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#define ZS4_BENCH_SIZE 4096U
#define ZS4_BENCH_PAGES 64U

#define ZS4_ALGO_ZSTD 0
#define ZS4_ALGO_LZ4 1
#define ZS4_ALGO_LZ4KD 2

const char* zs4_device_bridge_name(unsigned int algorithm);
void zs4_device_bridge_init(unsigned int algorithm, size_t* compression_size, size_t* decompression_size);
void zs4_device_bridge_release(void);
unsigned int zs4_device_bridge_compress(const uint8_t* input, uint8_t* packed);
unsigned int zs4_device_bridge_decompress(const uint8_t* packed, unsigned int length, uint8_t* output);

#endif
