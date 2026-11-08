/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef u8
typedef uint8_t u8;
#endif
#ifndef u32
typedef uint32_t u32;
#endif

#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

// Kernel allocator and function adapters
static void* bench_vzalloc(unsigned long size) { return calloc(1, size); }
static void bench_vfree(const void* ptr) { free((void*)ptr); }
#define vzalloc bench_vzalloc
#define vfree bench_vfree
#define kfunc(name) name

// Crypto tfm context offset dummy
struct crypto_tfm;
static const struct {
  unsigned int crypto_tfm_ctx;
} struct_offset = {0};

#include "zram_codec_bench_bridge.h"

// ZSTD upstream freestanding header
#include "zstd.h"
#include "../../zram_zstd/zs_zstd_config.h"

// LZ4 upstream headers and configs
#include "../../zram_zstd/zs_lz4_config.h"
#include "../../zram_zstd/upstream/lz4/lz4.h"

// LZ4KD upstream headers, configs, and unchanged production adapter
#include "../../zram_zstd/zs_lz4kd_config.h"
#include "../../zram_zstd/upstream/lz4kd/lz4kd.h"
#include "../../zram_zstd/zs_lz4kd.c"

// Production ZSTD encapsulation from zram_zstd.c
struct zstd_ctx {
  void* cwksp;
  void* dwksp;
  ZSTD_CCtx* cctx;
  ZSTD_DCtx* dctx;
};

static ZSTD_parameters zstd_params(void) { return ZSTD_getParams(3, 0, 0); }

static void zstd_release(struct zstd_ctx* ctx) {
  if (ctx->cwksp)
    kfunc(vfree)(ctx->cwksp);
  if (ctx->dwksp)
    kfunc(vfree)(ctx->dwksp);
  ctx->cwksp = NULL;
  ctx->dwksp = NULL;
}

static int zstd_prepare(struct zstd_ctx* ctx) {
  ZSTD_parameters params = zstd_params();
  size_t csize = ZSTD_estimateCCtxSize_usingCParams(params.cParams);
  size_t dsize = ZSTD_estimateDCtxSize();
  if (zs_zstd_is_error(csize) || zs_zstd_is_error(dsize))
    return -EINVAL;
  ctx->cwksp = kfunc(vzalloc)(csize);
  ctx->dwksp = kfunc(vzalloc)(dsize);
  if (!ctx->cwksp || !ctx->dwksp) {
    zstd_release(ctx);
    return -ENOMEM;
  }
  ctx->cctx = ZSTD_initStaticCCtx(ctx->cwksp, csize);
  ctx->dctx = ZSTD_initStaticDCtx(ctx->dwksp, dsize);
  if (!ctx->cctx || !ctx->dctx) {
    zstd_release(ctx);
    return -EINVAL;
  }
  return 0;
}

static size_t zstd_encode(ZSTD_CCtx* cctx, void* dst, size_t capacity, const void* src, size_t size) {
  ZSTD_parameters params = zstd_params();
  size_t rc = ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
  if (zs_zstd_is_error(rc))
    return rc;
  rc = ZSTD_CCtx_setPledgedSrcSize(cctx, size);
  if (zs_zstd_is_error(rc))
    return rc;
  rc = ZSTD_CCtx_setParams(cctx, params);
  if (zs_zstd_is_error(rc))
    return rc;
  return ZSTD_compress2(cctx, dst, capacity, src, size);
}

// Production LZ4 encapsulation from zram_zstd.c
struct lz4_ctx {
  void* workspace;
};

static int lz4_prepare(struct lz4_ctx* ctx) {
  ctx->workspace = kfunc(vzalloc)(LZ4_sizeofState());
  return ctx->workspace ? 0 : -ENOMEM;
}

static void lz4_release(struct lz4_ctx* ctx) {
  kfunc(vfree)(ctx->workspace);
  ctx->workspace = NULL;
}

static int lz4_encode(struct lz4_ctx* ctx, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > LZ4_MAX_INPUT_SIZE || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_compress_fast_extState(ctx->workspace, (const char*)src, (char*)dst, slen, *dlen, 1);
  if (!size)
    return -EINVAL;
  *dlen = size;
  return 0;
}

static int lz4_decompress_block(const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > 0x7fffffffU || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_decompress_safe((const char*)src, (char*)dst, slen, *dlen);
  if (size < 0)
    return -EINVAL;
  *dlen = size;
  return 0;
}

// Global active codec states
static unsigned int current_algorithm;
static struct zstd_ctx zstd_state;
static struct lz4_ctx lz4_state;
static struct lz4kd_ctx lz4kd_state;

const char* zs4_device_bridge_name(unsigned int algorithm) {
  switch (algorithm) {
    case ZS4_ALGO_ZSTD: return "zstd-kpm";
    case ZS4_ALGO_LZ4: return "lz4-kpm";
    case ZS4_ALGO_LZ4KD: return "lz4kd-kpm";
    default: return "unknown";
  }
}

void zs4_device_bridge_init(unsigned int algorithm, size_t* compression_size, size_t* decompression_size) {
  current_algorithm = algorithm;
  assert(current_algorithm <= 2);
  *compression_size = 0;
  *decompression_size = 0;

  if (current_algorithm == ZS4_ALGO_ZSTD) {
    ZSTD_parameters params = zstd_params();
    *compression_size = ZSTD_estimateCCtxSize_usingCParams(params.cParams);
    *decompression_size = ZSTD_estimateDCtxSize();
    assert(!zstd_prepare(&zstd_state));
  } else if (current_algorithm == ZS4_ALGO_LZ4) {
    *compression_size = LZ4_sizeofState();
    *decompression_size = 0;
    assert(!lz4_prepare(&lz4_state));
  } else if (current_algorithm == ZS4_ALGO_LZ4KD) {
    *compression_size = lz4kd_encode_state_bytes_min() + ZS_LZ4KD_SCRATCH;
    *decompression_size = 0;
    assert(!lz4kd_prepare(&lz4kd_state));
  }
}

void zs4_device_bridge_release(void) {
  if (current_algorithm == ZS4_ALGO_ZSTD) {
    zstd_release(&zstd_state);
  } else if (current_algorithm == ZS4_ALGO_LZ4) {
    lz4_release(&lz4_state);
  } else if (current_algorithm == ZS4_ALGO_LZ4KD) {
    lz4kd_release(&lz4kd_state);
  }
}

unsigned int zs4_device_bridge_compress(const uint8_t* input, uint8_t* packed) {
  unsigned int capacity = ZS4_BENCH_SIZE * 2;
  if (current_algorithm == ZS4_ALGO_ZSTD) {
    size_t sz = zstd_encode(zstd_state.cctx, packed, capacity, input, ZS4_BENCH_SIZE);
    assert(!ZSTD_isError(sz) && sz > 0);
    return (unsigned int)sz;
  }
  if (current_algorithm == ZS4_ALGO_LZ4) {
    unsigned int dlen = capacity;
    assert(!lz4_encode(&lz4_state, input, ZS4_BENCH_SIZE, packed, &dlen));
    return dlen;
  }
  if (current_algorithm == ZS4_ALGO_LZ4KD) {
    unsigned int dlen = capacity;
    assert(!lz4kd_encode_block(&lz4kd_state, input, ZS4_BENCH_SIZE, packed, &dlen));
    return dlen;
  }
  return 0;
}

unsigned int zs4_device_bridge_decompress(const uint8_t* packed, unsigned int length, uint8_t* output) {
  if (current_algorithm == ZS4_ALGO_ZSTD) {
    size_t sz = ZSTD_decompressDCtx(zstd_state.dctx, output, ZS4_BENCH_SIZE, packed, length);
    assert(!ZSTD_isError(sz) && sz == ZS4_BENCH_SIZE);
    return (unsigned int)sz;
  }
  if (current_algorithm == ZS4_ALGO_LZ4) {
    unsigned int dlen = ZS4_BENCH_SIZE;
    assert(!lz4_decompress_block(packed, length, output, &dlen));
    assert(dlen == ZS4_BENCH_SIZE);
    return dlen;
  }
  if (current_algorithm == ZS4_ALGO_LZ4KD) {
    unsigned int dlen = ZS4_BENCH_SIZE;
    assert(!lz4kd_decompress(NULL, packed, length, output, &dlen));
    assert(dlen == ZS4_BENCH_SIZE);
    return dlen;
  }
  return 0;
}
