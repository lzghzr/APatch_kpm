/* SPDX-License-Identifier: GPL-2.0-only */
/* Host timer follows the floating-point ABI; codec wrappers live in a scalar-only translation unit. */
#include "lz4kd16_benchmark.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
  struct timespec time;
  assert(!clock_gettime(CLOCK_MONOTONIC, &time));
  return time.tv_sec + time.tv_nsec * 1e-9;
}

int main(int argc, char** argv) {
  assert(argc == 4);
  size_t csize, dsize;
  zs16_benchmark_init(strtoul(argv[1], NULL, 10), &csize, &dsize);
  uint8_t *input = malloc(ZS16_BENCH_PAGES * ZS16_BENCH_SIZE), *packed = malloc(ZS16_BENCH_PAGES * ZS16_BENCH_SIZE * 2),
          *output = malloc(ZS16_BENCH_SIZE);
  assert(input && packed && output);
  FILE* file = fopen(argv[2], "rb");
  assert(file && fread(input, ZS16_BENCH_SIZE, ZS16_BENCH_PAGES, file) == ZS16_BENCH_PAGES && fgetc(file) == EOF);
  fclose(file);
  FILE* exported = fopen(argv[3], "wb");
  assert(exported);
  unsigned int lengths[ZS16_BENCH_PAGES], total = 0;
  for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
    unsigned int length = zs16_benchmark_compress(input + p * ZS16_BENCH_SIZE, packed + p * ZS16_BENCH_SIZE * 2);
    assert(length && length <= ZS16_BENCH_SIZE * 2);
    assert(zs16_benchmark_decompress(packed + p * ZS16_BENCH_SIZE * 2, length, output) == ZS16_BENCH_SIZE);
    assert(!memcmp(output, input + p * ZS16_BENCH_SIZE, ZS16_BENCH_SIZE));
    lengths[p] = length;
    total += length;
    uint8_t le[4] = {length, length >> 8, length >> 16, length >> 24};
    assert(fwrite(le, 1, 4, exported) == 4 && fwrite(packed + p * ZS16_BENCH_SIZE * 2, 1, length, exported) == length);
  }
  fclose(exported);
  unsigned long checksum = 0;
  double start = now();
  for (unsigned int round = 0; round < 64; round++)
    for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
      unsigned int length = zs16_benchmark_compress(input + p * ZS16_BENCH_SIZE, packed + p * ZS16_BENCH_SIZE * 2);
      assert(length == lengths[p]);
      checksum += length;
    }
  double compression = now() - start;
  start = now();
  for (unsigned int round = 0; round < 128; round++)
    for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++)
      assert(zs16_benchmark_decompress(packed + p * ZS16_BENCH_SIZE * 2, lengths[p], output) == ZS16_BENCH_SIZE);
  double decompression = now() - start;
  assert(compression > 0 && decompression > 0);
  printf(
      "{\"input_bytes\":%u,\"compressed_bytes\":%u,\"compression_workspace\":%zu,"
      "\"decompression_workspace\":%zu,\"compress_mib_s\":%.3f,\"decompress_mib_s\":%.3f,\"checksum\":%lu}\n",
      ZS16_BENCH_PAGES * ZS16_BENCH_SIZE, total, csize, dsize, 64.0 / compression, 128.0 / decompression, checksum);
  zs16_benchmark_release();
  free(input);
  free(packed);
  free(output);
  return 0;
}
