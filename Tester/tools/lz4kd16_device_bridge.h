/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define ZS16_BENCH_SIZE 16384U
#define ZS16_BENCH_PAGES 64U

void zs16_device_bridge_init(unsigned int algorithm, size_t* compression_size, size_t* decompression_size);
void zs16_device_bridge_release(void);
unsigned int zs16_device_bridge_compress(const uint8_t* input, uint8_t* packed);
unsigned int zs16_device_bridge_decompress(const uint8_t* packed, unsigned int length, uint8_t* output);
const char* zs16_device_bridge_name(unsigned int algorithm);
