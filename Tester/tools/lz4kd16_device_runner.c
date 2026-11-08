/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lz4kd16_device_bridge.h"

static double get_time_sec(void) {
  struct timespec ts;
  assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <algo: 0|1|2> <input_bin> [output_blocks]\n", argv[0]);
    return 2;
  }
  unsigned int algo = (unsigned int)strtoul(argv[1], NULL, 10);
  assert(algo <= 2);
  const char* input_path = argv[2];
  const char* output_blocks_path = (argc >= 4) ? argv[3] : NULL;

  size_t csize = 0, dsize = 0;
  zs16_device_bridge_init(algo, &csize, &dsize);

  size_t total_input_size = ZS16_BENCH_PAGES * ZS16_BENCH_SIZE;
  uint8_t* input = (uint8_t*)malloc(total_input_size);
  uint8_t* packed = (uint8_t*)malloc(total_input_size * 2);
  uint8_t* output = (uint8_t*)malloc(ZS16_BENCH_SIZE);
  assert(input && packed && output);

  FILE* fin = fopen(input_path, "rb");
  if (!fin) {
    fprintf(stderr, "error: failed to open input file %s\n", input_path);
    return 1;
  }
  if (fread(input, ZS16_BENCH_SIZE, ZS16_BENCH_PAGES, fin) != ZS16_BENCH_PAGES || fgetc(fin) != EOF) {
    fprintf(stderr, "error: input file %s must be exactly %u bytes (64 pages)\n", input_path,
            ZS16_BENCH_PAGES * ZS16_BENCH_SIZE);
    fclose(fin);
    return 1;
  }
  fclose(fin);

  FILE* fexport = NULL;
  if (output_blocks_path) {
    fexport = fopen(output_blocks_path, "wb");
    if (!fexport) {
      fprintf(stderr, "error: failed to open output blocks file %s\n", output_blocks_path);
      return 1;
    }
  }

  unsigned int lengths[ZS16_BENCH_PAGES];
  unsigned int total_compressed = 0;

  /* Step 1: Warmup, compress all pages, verify roundtrip, and export blocks */
  for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
    const uint8_t* page_in = input + p * ZS16_BENCH_SIZE;
    uint8_t* page_packed = packed + p * ZS16_BENCH_SIZE * 2;

    unsigned int clen = zs16_device_bridge_compress(page_in, page_packed);
    if (clen == 0 || clen > ZS16_BENCH_SIZE * 2) {
      fprintf(stderr, "error: compression failed on page %u\n", p);
      return 1;
    }
    lengths[p] = clen;
    total_compressed += clen;

    unsigned int dlen = zs16_device_bridge_decompress(page_packed, clen, output);
    if (dlen != ZS16_BENCH_SIZE) {
      fprintf(stderr, "error: decompression size mismatch on page %u: expected %u, got %u\n", p, ZS16_BENCH_SIZE, dlen);
      return 1;
    }
    if (memcmp(output, page_in, ZS16_BENCH_SIZE) != 0) {
      fprintf(stderr, "error: roundtrip corruption on page %u\n", p);
      return 1;
    }

    if (fexport) {
      uint8_t le[4] = {(uint8_t)clen, (uint8_t)(clen >> 8), (uint8_t)(clen >> 16), (uint8_t)(clen >> 24)};
      if (fwrite(le, 1, 4, fexport) != 4 || fwrite(page_packed, 1, clen, fexport) != clen) {
        fprintf(stderr, "error: failed to write blocks file %s\n", output_blocks_path);
        fclose(fexport);
        return 1;
      }
    }
  }
  if (fexport) {
    fclose(fexport);
  }

  /* Step 2: Compression throughput timing (64 rounds) */
  unsigned long checksum = 0;
  double t0 = get_time_sec();
  for (unsigned int round = 0; round < 64; round++) {
    for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
      const uint8_t* page_in = input + p * ZS16_BENCH_SIZE;
      uint8_t* page_packed = packed + p * ZS16_BENCH_SIZE * 2;
      unsigned int clen = zs16_device_bridge_compress(page_in, page_packed);
      assert(clen == lengths[p]);
      checksum += clen;
    }
  }
  double comp_sec = get_time_sec() - t0;
  assert(comp_sec > 0.0);

  /* Step 3: Decompression throughput timing (128 rounds) */
  t0 = get_time_sec();
  for (unsigned int round = 0; round < 128; round++) {
    for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
      uint8_t* page_packed = packed + p * ZS16_BENCH_SIZE * 2;
      unsigned int dlen = zs16_device_bridge_decompress(page_packed, lengths[p], output);
      assert(dlen == ZS16_BENCH_SIZE);
    }
  }
  double decomp_sec = get_time_sec() - t0;
  assert(decomp_sec > 0.0);

  /* Step 4: Final verification pass */
  for (unsigned int p = 0; p < ZS16_BENCH_PAGES; p++) {
    const uint8_t* page_in = input + p * ZS16_BENCH_SIZE;
    uint8_t* page_packed = packed + p * ZS16_BENCH_SIZE * 2;
    unsigned int dlen = zs16_device_bridge_decompress(page_packed, lengths[p], output);
    assert(dlen == ZS16_BENCH_SIZE);
    assert(memcmp(output, page_in, ZS16_BENCH_SIZE) == 0);
  }

  double comp_mib_s = 64.0 / comp_sec;
  double decomp_mib_s = 128.0 / decomp_sec;

  printf(
      "{\"codec\":\"%s\",\"algorithm\":%u,\"input_bytes\":%u,\"compressed_bytes\":%u,"
      "\"compression_workspace\":%zu,\"decompression_workspace\":%zu,"
      "\"compress_mib_s\":%.3f,\"decompress_mib_s\":%.3f,\"checksum\":%lu,\"roundtrip_ok\":true}\n",
      zs16_device_bridge_name(algo), algo, (unsigned int)total_input_size, total_compressed, csize, dsize,
      comp_mib_s, decomp_mib_s, checksum);

  zs16_device_bridge_release();
  free(input);
  free(packed);
  free(output);
  return 0;
}
