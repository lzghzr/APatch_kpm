/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

#include "lz4kd16_device_bridge.h"
#include "../../zram_zstd/experimental/lz4kd16.h"
#include "../../zram_zstd/tools/lz4kd16_legacy_fixture.h"
#include "../../zram_zstd/upstream/lz4/lz4.h"

static unsigned int current_codec;
static void *comp_ctx, *comp_work;
static struct lz4kd_ctx legacy_ctx;

const char* zs16_device_bridge_name(unsigned int algorithm) {
  switch (algorithm) {
    case 0: return "lz4kd16";
    case 1: return "lz4kd4_chunks";
    case 2: return "lz4";
    default: return "unknown";
  }
}

void zs16_device_bridge_init(unsigned int algorithm, size_t* compression_size, size_t* decompression_size) {
  current_codec = algorithm;
  assert(current_codec <= 2);
  size_t csize = 0, dsize = 0;
  if (current_codec == 0) {
    csize = sizeof(struct zs_lz4kd16_ctx);
  } else if (current_codec == 1) {
    csize = 16384;
    assert(!lz4kd_init((void*)&legacy_ctx));
  } else if (current_codec == 2) {
    csize = LZ4_sizeofState();
  }
  comp_work = (current_codec == 1) ? NULL : calloc(1, csize);
  assert(current_codec == 1 || comp_work);
  comp_ctx = comp_work;
  *compression_size = csize;
  *decompression_size = dsize;
}

void zs16_device_bridge_release(void) {
  if (current_codec == 1) {
    lz4kd_exit((void*)&legacy_ctx);
  }
  free(comp_work);
  comp_work = NULL;
  comp_ctx = NULL;
}

unsigned int zs16_device_bridge_compress(const uint8_t* input, uint8_t* packed) {
  unsigned int size = ZS16_BENCH_SIZE * 2;
  if (current_codec == 0) {
    assert(!zs_lz4kd16_compress((struct zs_lz4kd16_ctx*)comp_ctx, input, ZS16_BENCH_SIZE, packed, &size));
    return size;
  }
  if (current_codec == 1) {
    return zs16_chunk_compress(&legacy_ctx, input, packed);
  }
  if (current_codec == 2) {
    return LZ4_compress_fast_extState(comp_ctx, (const char*)input, (char*)packed, ZS16_BENCH_SIZE, ZS16_BENCH_SIZE * 2, 1);
  }
  return 0;
}

unsigned int zs16_device_bridge_decompress(const uint8_t* packed, unsigned int length, uint8_t* output) {
  if (current_codec == 0) {
    unsigned int size = ZS16_BENCH_SIZE;
    assert(!zs_lz4kd16_decompress(packed, length, output, &size));
    return size;
  }
  if (current_codec == 1) {
    return zs16_chunk_decompress(packed, length, output);
  }
  if (current_codec == 2) {
    return LZ4_decompress_safe((const char*)packed, (char*)output, length, ZS16_BENCH_SIZE);
  }
  return 0;
}
