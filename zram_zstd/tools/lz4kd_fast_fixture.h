/* SPDX-License-Identifier: GPL-2.0-only */
/* Real zram geometry: 4 KiB input, 8 KiB physical output; old small-output contracts stay above. */
static void lz4kd_fast_tests(void) {
  static const unsigned int lengths[] = {1, 4, 31, 32, 63, 64, 255, 256, 4095, 4096};
  unsigned char* tfm = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct lz4kd_ctx));
  unsigned char *input = malloc(4096), *direct = malloc(8192), *staged = malloc(8191), *decoded = malloc(4096);
  assert(tfm && input && direct && staged && decoded);
  assert(!lz4kd_init((void*)tfm));
  struct lz4kd_ctx* ctx = lz4kd_context((void*)tfm);
  unsigned int blocks = 0;
  for (unsigned int period = 1; period <= 33; period++) {
    for (unsigned int j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
      unsigned int n = lengths[j];
      for (unsigned int i = 0; i < n; i++) input[i] = period == 33 ? next_random() : i % period;
      memset(ctx->scratch, 0xa5, ZS_LZ4KD_SCRATCH);
      unsigned int direct_size = 8192;
      assert(!lz4kd_compress((void*)tfm, input, n, direct, &direct_size));
      for (unsigned int i = 0; i < ZS_LZ4KD_SCRATCH; i++) assert(ctx->scratch[i] == 0xa5);
      unsigned int staged_size = 8191;
      assert(!lz4kd_compress((void*)tfm, input, n, staged, &staged_size));
      assert(staged_size == direct_size && !memcmp(direct, staged, direct_size));
      unsigned int decoded_size = n;
      assert(!lz4kd_decompress((void*)tfm, direct, direct_size, decoded, &decoded_size));
      assert(decoded_size == n && !memcmp(input, decoded, n));
      blocks++;
    }
  }
  lz4kd_exit((void*)tfm);
  free(tfm);
  free(input);
  free(direct);
  free(staged);
  free(decoded);
  assert(allocations == frees);
  printf("PASS: LZ4KD %u direct/staged blocks, identical format, untouched scratch, periods 1..32 and random\n",
         blocks);
}
