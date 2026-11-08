/* SPDX-License-Identifier: GPL-2.0-only */
/* All codec wrappers use the same scalar-only flags as the KPM; timer code has the host ABI. */
#include <assert.h>

#include "experimental/lz4kd16.h"
#include "linux/zstd.h"
#include "lz4.h"
#include "lz4kd16_benchmark.h"
#include "tools/lz4kd16_legacy_fixture.h"

/* PRODUCTION_ZSTD */
static unsigned int codec;
static void *cc, *dc, *cw, *dw;
static struct lz4kd_ctx legacy;

unsigned int zs16_benchmark_compress(const uint8_t* input, uint8_t* packed) {
  unsigned int size = ZS16_BENCH_SIZE * 2;
  if (codec == 0) {
    assert(!zs_lz4kd16_compress(cc, input, ZS16_BENCH_SIZE, packed, &size));
    return size;
  }
  if (codec == 1)
    return zs16_chunk_compress(&legacy, input, packed);
  if (codec == 2)
    return LZ4_compress_fast_extState(cc, (const char*)input, (char*)packed, ZS16_BENCH_SIZE, ZS16_BENCH_SIZE * 2, 1);
  size_t result = zstd_encode(cc, packed, ZS16_BENCH_SIZE * 2, input, ZS16_BENCH_SIZE);
  assert(!ZSTD_isError(result));
  return result;
}

unsigned int zs16_benchmark_decompress(const uint8_t* packed, unsigned int length, uint8_t* output) {
  if (codec == 0) {
    unsigned int size = ZS16_BENCH_SIZE;
    assert(!zs_lz4kd16_decompress(packed, length, output, &size));
    return size;
  }
  if (codec == 1)
    return zs16_chunk_decompress(packed, length, output);
  if (codec == 2)
    return LZ4_decompress_safe((const char*)packed, (char*)output, length, ZS16_BENCH_SIZE);
  size_t result = ZSTD_decompressDCtx(dc, output, ZS16_BENCH_SIZE, packed, length);
  assert(!ZSTD_isError(result));
  return result;
}

void zs16_benchmark_init(unsigned int algorithm, size_t* compression_size, size_t* decompression_size) {
  codec = algorithm;
  assert(codec < 4);
  size_t csize = 0, dsize = 0;
  if (codec == 0)
    csize = sizeof(struct zs_lz4kd16_ctx);
  else if (codec == 1) {
    csize = 16384;
    assert(!lz4kd_init((void*)&legacy));
  } else if (codec == 2)
    csize = LZ4_sizeofState();
  else {
    csize = ZSTD_estimateCCtxSize_usingCParams(zstd_params().cParams);
    dsize = ZSTD_estimateDCtxSize();
    assert(!ZSTD_isError(csize) && !ZSTD_isError(dsize));
  }
  cw = codec == 1 ? NULL : calloc(1, csize);
  dw = dsize ? calloc(1, dsize) : NULL;
  assert(codec == 1 || cw);
  assert(!dsize || dw);
  cc = codec == 3 ? ZSTD_initStaticCCtx(cw, csize) : cw;
  dc = codec == 3 ? ZSTD_initStaticDCtx(dw, dsize) : NULL;
  assert(codec != 3 || (cc && dc));
  *compression_size = csize;
  *decompression_size = dsize;
}

void zs16_benchmark_release(void) {
  if (codec == 1)
    lz4kd_exit((void*)&legacy);
  free(cw);
  free(dw);
}
