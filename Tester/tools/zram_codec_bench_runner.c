/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zram_codec_bench_bridge.h"

static uint64_t get_time_ns(void) {
  struct timespec ts;
  int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
  assert(rc == 0);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <algo: 0|1|2> <input_bin>\n", argv[0]);
    return 2;
  }
  unsigned int algo = (unsigned int)strtoul(argv[1], NULL, 10);
  assert(algo <= 2);
  const char* input_path = argv[2];

  size_t csize = 0, dsize = 0;
  zs4_device_bridge_init(algo, &csize, &dsize);

  size_t total_input_size = ZS4_BENCH_PAGES * ZS4_BENCH_SIZE;
  uint8_t* input = (uint8_t*)malloc(total_input_size);
  uint8_t* packed = (uint8_t*)malloc(total_input_size * 2);
  uint8_t* output = (uint8_t*)malloc(ZS4_BENCH_SIZE);
  assert(input && packed && output);

  FILE* fin = fopen(input_path, "rb");
  if (!fin) {
    fprintf(stderr, "error: failed to open input file %s\n", input_path);
    return 1;
  }
  if (fread(input, ZS4_BENCH_SIZE, ZS4_BENCH_PAGES, fin) != ZS4_BENCH_PAGES || fgetc(fin) != EOF) {
    fprintf(stderr, "error: input file %s must be exactly %u bytes (64 pages)\n", input_path,
            ZS4_BENCH_PAGES * ZS4_BENCH_SIZE);
    fclose(fin);
    return 1;
  }
  fclose(fin);

  unsigned int lengths[ZS4_BENCH_PAGES];
  unsigned int total_compressed = 0;

  /* Step 1: Warmup, compress all pages, and verify roundtrip */
  for (unsigned int p = 0; p < ZS4_BENCH_PAGES; p++) {
    const uint8_t* page_in = input + p * ZS4_BENCH_SIZE;
    uint8_t* page_packed = packed + p * ZS4_BENCH_SIZE * 2;

    unsigned int clen = zs4_device_bridge_compress(page_in, page_packed);
    if (clen == 0 || clen > ZS4_BENCH_SIZE * 2) {
      fprintf(stderr, "error: compression failed on page %u\n", p);
      return 1;
    }
    lengths[p] = clen;
    total_compressed += clen;

    unsigned int dlen = zs4_device_bridge_decompress(page_packed, clen, output);
    if (dlen != ZS4_BENCH_SIZE) {
      fprintf(stderr, "error: decompression size mismatch on page %u: expected %u, got %u\n", p, ZS4_BENCH_SIZE, dlen);
      return 1;
    }
    if (memcmp(output, page_in, ZS4_BENCH_SIZE) != 0) {
      fprintf(stderr, "error: roundtrip corruption on page %u\n", p);
      return 1;
    }
  }

  /* Step 2: Compression throughput timing (256 rounds = 64 MiB processed) */
  unsigned long checksum = 0;
  uint64_t t0 = get_time_ns();
  for (unsigned int round = 0; round < 256; round++) {
    for (unsigned int p = 0; p < ZS4_BENCH_PAGES; p++) {
      const uint8_t* page_in = input + p * ZS4_BENCH_SIZE;
      uint8_t* page_packed = packed + p * ZS4_BENCH_SIZE * 2;
      unsigned int clen = zs4_device_bridge_compress(page_in, page_packed);
      assert(clen == lengths[p]);
      checksum += clen;
    }
  }
  uint64_t comp_ns = get_time_ns() - t0;
  assert(comp_ns > 0);

  /* Step 3: Decompression throughput timing (512 rounds = 128 MiB processed) */
  t0 = get_time_ns();
  for (unsigned int round = 0; round < 512; round++) {
    for (unsigned int p = 0; p < ZS4_BENCH_PAGES; p++) {
      uint8_t* page_packed = packed + p * ZS4_BENCH_SIZE * 2;
      unsigned int dlen = zs4_device_bridge_decompress(page_packed, lengths[p], output);
      assert(dlen == ZS4_BENCH_SIZE);
    }
  }
  uint64_t decomp_ns = get_time_ns() - t0;
  assert(decomp_ns > 0);

  /* Step 4: Final verification pass */
  for (unsigned int p = 0; p < ZS4_BENCH_PAGES; p++) {
    const uint8_t* page_in = input + p * ZS4_BENCH_SIZE;
    uint8_t* page_packed = packed + p * ZS4_BENCH_SIZE * 2;
    unsigned int dlen = zs4_device_bridge_decompress(page_packed, lengths[p], output);
    assert(dlen == ZS4_BENCH_SIZE);
    assert(memcmp(output, page_in, ZS4_BENCH_SIZE) == 0);
  }

  double comp_mib_s = (64.0 * 1000000000.0) / (double)comp_ns;
  double decomp_mib_s = (128.0 * 1000000000.0) / (double)decomp_ns;
  double ratio = (double)total_input_size / (double)total_compressed;

  printf(
      "{\"codec\":\"%s\",\"algorithm\":%u,\"input_bytes\":%u,\"compressed_bytes\":%u,"
      "\"compression_ratio\":%.4f,\"compression_workspace\":%zu,\"decompression_workspace\":%zu,"
      "\"compress_mib_s\":%.3f,\"decompress_mib_s\":%.3f,\"checksum\":%lu,\"roundtrip_ok\":true}\n",
      zs4_device_bridge_name(algo), algo, (unsigned int)total_input_size, total_compressed, ratio, csize, dsize,
      comp_mib_s, decomp_mib_s, checksum);

  zs4_device_bridge_release();
  free(input);
  free(packed);
  free(output);
  return 0;
}
