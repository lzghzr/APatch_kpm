/* SPDX-License-Identifier: GPL-2.0-only */
/* Developer host benchmark: fixed synthetic pages, no target-kernel claims. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "linux/zstd.h"
#include "lz4.h"
#define PAGES 256
#define SIZE 4096
/* PRODUCTION_ZSTD */
static double now(void) {
  struct timespec t;
  assert(!clock_gettime(CLOCK_MONOTONIC, &t));
  return t.tv_sec + t.tv_nsec * 1e-9;
}
static size_t compress_page(void* cc, void* dst, const void* src) {
#ifdef CODEC_LZ4
  int n = LZ4_compress_fast_extState(cc, src, dst, SIZE, SIZE * 2, 1);
  assert(n > 0);
  return n;
#elif defined(CODEC_ZSTD_AUTO)
  return ZSTD_compressCCtx(cc, dst, SIZE * 2, src, SIZE, 3);
#else
  return zstd_encode(cc, dst, SIZE * 2, src, SIZE);
#endif
}
static size_t decompress_page(void* dc, void* dst, const void* src, size_t size) {
#ifdef CODEC_LZ4
  return LZ4_decompress_safe(src, dst, size, SIZE);
#else
  return ZSTD_decompressDCtx(dc, dst, SIZE, src, size);
#endif
}
int main(void) {
#ifdef CODEC_LZ4
  size_t csize = LZ4_sizeofState(), dsize = 0;
#else
  ZSTD_parameters params = ZSTD_getParams(3, 0, 0);
  size_t csize = ZSTD_estimateCCtxSize_usingCParams(params.cParams), dsize = ZSTD_estimateDCtxSize();
#endif
  void *cw = calloc(1, csize), *dw = calloc(1, dsize ? dsize : 1);
  assert(cw && dw);
#ifdef CODEC_LZ4
  void *cc = cw, *dc = NULL;
#else
  ZSTD_CCtx* cc = ZSTD_initStaticCCtx(cw, csize);
  ZSTD_DCtx* dc = ZSTD_initStaticDCtx(dw, dsize);
#endif
  assert(cc);
  unsigned char *input = malloc(PAGES * SIZE), *packed = malloc(PAGES * SIZE * 2), decoded[SIZE];
  assert(input && packed);
  static const char text[] = "zram codec baseline: independent pages, reusable workspace, no dictionary. ";
  uint32_t random = 0x32a6fd71;
  for (unsigned int p = 0; p < PAGES; p++) {
    for (unsigned int i = 0; i < SIZE; i++) {
      random ^= random << 13;
      random ^= random >> 17;
      random ^= random << 5;
      unsigned char value;
      switch (p % 4) {
        case 0:
          value = text[(i + p) % (sizeof(text) - 1)];
          break;
        case 1:
          value = ((i / 4 + p) >> (8 * (i % 4))) & 255;
          break;
        case 2:
          value = (i * 31U + i / 19U + p) % 251;
          break;
        default:
          value = random;
          break;
      }
      input[p * SIZE + i] = value;
    }
  }
  size_t lengths[PAGES], total = 0, checksum = 0;
  for (int p = 0; p < PAGES; p++) {
    size_t n = compress_page(cc, packed + p * SIZE * 2, input + p * SIZE);
    assert(n && n <= SIZE * 2);
#ifndef CODEC_LZ4
    assert(!ZSTD_isError(n));
#endif
    lengths[p] = n;
    total += n;
    assert(decompress_page(dc, decoded, packed + p * SIZE * 2, n) == SIZE);
    assert(!memcmp(decoded, input + p * SIZE, SIZE));
  }
  double start = now();
  for (int i = 0; i < 100; i++)
    for (int p = 0; p < PAGES; p++) {
      size_t n = compress_page(cc, packed + p * SIZE * 2, input + p * SIZE);
      assert(n == lengths[p]);
      checksum += n;
    }
  double ct = now() - start;
  start = now();
  for (int i = 0; i < 500; i++)
    for (int p = 0; p < PAGES; p++) assert(decompress_page(dc, decoded, packed + p * SIZE * 2, lengths[p]) == SIZE);
  double dt = now() - start;
  printf(
      "{\"compression_workspace\":%zu,\"decompression_workspace\":%zu,\"compressed_bytes\":%zu,"
      "\"input_bytes\":%d,\"compress_mib_s\":%.3f,\"decompress_mib_s\":%.3f,\"checksum\":%zu}\n",
      csize, dsize, total, PAGES * SIZE, 100.0 / ct, 500.0 / dt, checksum);
  free(cw);
  free(dw);
  free(input);
  free(packed);
  return 0;
}
