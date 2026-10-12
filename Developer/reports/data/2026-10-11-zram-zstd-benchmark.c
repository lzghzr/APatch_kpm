#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "linux/zstd.h"
#define PAGES 256
#define SIZE 4096
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
int main(int argc, char** argv) {
  assert(argc == 2);
#ifdef CODEC_OLD
  ZSTD_parameters params = ZSTD_getParams(3, 0, 0);
  size_t csize = ZSTD_CCtxWorkspaceBound(params.cParams), dsize = ZSTD_DCtxWorkspaceBound();
#else
  size_t csize = ZSTD_estimateCCtxSize(3), dsize = ZSTD_estimateDCtxSize();
#endif
  void* cw = calloc(1, csize); void* dw = calloc(1, dsize); assert(cw && dw);
#ifdef CODEC_OLD
  ZSTD_CCtx* cc = ZSTD_initCCtx(cw, csize); ZSTD_DCtx* dc = ZSTD_initDCtx(dw, dsize);
#else
  ZSTD_CCtx* cc = ZSTD_initStaticCCtx(cw, csize); ZSTD_DCtx* dc = ZSTD_initStaticDCtx(dw, dsize);
#endif
  assert(cc && dc); unsigned char* input = malloc(PAGES * SIZE);
  FILE* f = fopen(argv[1], "rb"); assert(f && fread(input, SIZE, PAGES, f) == PAGES); fclose(f);
  unsigned char packed[PAGES][SIZE * 2], decoded[SIZE]; size_t lengths[PAGES], total = 0;
  for (int p = 0; p < PAGES; p++) {
#ifdef CODEC_OLD
    lengths[p] = ZSTD_compressCCtx(cc, packed[p], sizeof(packed[p]), input + p * SIZE, SIZE, params);
#else
    lengths[p] = ZSTD_compressCCtx(cc, packed[p], sizeof(packed[p]), input + p * SIZE, SIZE, 3);
#endif
    assert(!ZSTD_isError(lengths[p])); total += lengths[p];
    assert(ZSTD_decompressDCtx(dc, decoded, SIZE, packed[p], lengths[p]) == SIZE);
    assert(!memcmp(input + p * SIZE, decoded, SIZE));
  }
  double start = now(); size_t checksum = 0;
  for (int i = 0; i < 100; i++) for (int p = 0; p < PAGES; p++) {
#ifdef CODEC_OLD
    size_t n = ZSTD_compressCCtx(cc, packed[p], sizeof(packed[p]), input + p * SIZE, SIZE, params);
#else
    size_t n = ZSTD_compressCCtx(cc, packed[p], sizeof(packed[p]), input + p * SIZE, SIZE, 3);
#endif
    assert(!ZSTD_isError(n) && n == lengths[p]); checksum += n;
  }
  double ct = now() - start; start = now();
  for (int i = 0; i < 500; i++) for (int p = 0; p < PAGES; p++) assert(ZSTD_decompressDCtx(dc, decoded, SIZE, packed[p], lengths[p]) == SIZE);
  double dt = now() - start;
  printf("{\"compression_workspace\":%zu,\"decompression_workspace\":%zu,\"compressed_bytes\":%zu,\"input_bytes\":%d,\"compress_mib_s\":%.3f,\"decompress_mib_s\":%.3f,\"checksum\":%zu}\n", csize,dsize,total,PAGES * SIZE,100.0/ct,500.0/dt,checksum);
  free(input); free(cw); free(dw); return 0;
}
