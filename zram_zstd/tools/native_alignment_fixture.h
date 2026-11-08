/* SPDX-License-Identifier: GPL-2.0-only */
/* Same codec version, Linux 6.6 parameter protocol; not target-kernel execution. */
/* NATIVE_ZSTD_PARAMETERS */

static void native_alignment_tests(void) {
  ZSTD_parameters params = ZSTD_getParams(3, 0, 0);
  size_t csize = ZSTD_estimateCCtxSize_usingCParams(params.cParams);
  size_t dsize = ZSTD_estimateDCtxSize();
  assert(!ZSTD_isError(csize) && !ZSTD_isError(dsize));
  void* native_workspace = calloc(1, csize);
  void* old_workspace = calloc(1, ZSTD_estimateCCtxSize(3));
  assert(native_workspace && old_workspace);
  ZSTD_CCtx* native = ZSTD_initStaticCCtx(native_workspace, csize);
  ZSTD_CCtx* automatic = ZSTD_initStaticCCtx(old_workspace, ZSTD_estimateCCtxSize(3));
  assert(native && automatic);
  void* tfm = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct zstd_ctx));
  assert(tfm && !zstd_init(tfm));
  unsigned char *input = malloc(65536), *actual = malloc(66000), *expected = malloc(66000), *decoded = malloc(65536);
  assert(input && actual && expected && decoded);
  unsigned int blocks = 0, different_from_automatic = 0;
  uint32_t random = 0x634ad761;
  const unsigned int sizes[] = {0, 1, 31, 255, 4096, 16384, 65536};
  const ZSTD_cParameter keys[] = {ZSTD_c_windowLog,    ZSTD_c_hashLog,      ZSTD_c_chainLog, ZSTD_c_searchLog,
                                  ZSTD_c_minMatch,     ZSTD_c_targetLength, ZSTD_c_strategy, ZSTD_c_contentSizeFlag,
                                  ZSTD_c_checksumFlag, ZSTD_c_dictIDFlag};
  const int values[] = {params.cParams.windowLog,         params.cParams.hashLog,
                        params.cParams.chainLog,          params.cParams.searchLog,
                        params.cParams.minMatch,          params.cParams.targetLength,
                        params.cParams.strategy,          params.fParams.contentSizeFlag != 0,
                        params.fParams.checksumFlag != 0, !params.fParams.noDictIDFlag};
  for (unsigned int pattern = 0; pattern < 4; pattern++) {
    for (unsigned int i = 0; i < 65536; i++) {
      random ^= random << 13;
      random ^= random >> 17;
      random ^= random << 5;
      input[i] = pattern == 0 ? 0 : pattern == 1 ? i % 251 : pattern == 2 ? random : (i * 31U + i / 19U) % 251;
    }
    for (unsigned int i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
      unsigned int n = sizes[i], len = 66000, out = 65536;
      // 前一个调用的参数/字典不能污染下一块；原生入口也先 reset_session_and_parameters。
      assert(!ZSTD_isError(ZSTD_CCtx_setParameter(zstd_context(tfm)->cctx, ZSTD_c_checksumFlag, 1)));
      assert(!ZSTD_isError(ZSTD_CCtx_setParameter(zstd_context(tfm)->cctx, ZSTD_c_contentSizeFlag, 0)));
      assert(!ZSTD_isError(ZSTD_CCtx_refPrefix(zstd_context(tfm)->cctx, input, 256)));
      assert(!zstd_compress(tfm, input, n, actual, &len));
      assert(!reference_zstd_cctx_init(native, &params, n));
      size_t native_size = ZSTD_compress2(native, expected, 66000, input, n);
      assert(!ZSTD_isError(native_size) && native_size == len && !memcmp(actual, expected, len));
      for (unsigned int k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        int value = -1;
        assert(!ZSTD_CCtx_getParameter(zstd_context(tfm)->cctx, keys[k], &value));
        assert(value == values[k]);
      }
      assert(!zstd_decompress(tfm, actual, len, decoded, &out));
      assert(out == n && !memcmp(input, decoded, n));
      assert(ZSTD_getFrameContentSize(actual, len) == n);
      size_t old_size = ZSTD_compressCCtx(automatic, expected, 66000, input, n, 3);
      assert(!ZSTD_isError(old_size));
      different_from_automatic += old_size != len || memcmp(actual, expected, len);
      len = 0;
      assert(zstd_compress(tfm, input, n, actual, &len) == -EINVAL && len == 0);
      len = 66000;
      assert(!zstd_compress(tfm, input, n, actual, &len));
      assert(len == native_size);
      assert(!reference_zstd_cctx_init(native, &params, n));
      assert(ZSTD_compress2(native, expected, 66000, input, n) == len && !memcmp(actual, expected, len));
      blocks++;
    }
  }
  zstd_exit(tfm);
  assert(!zstd_context(tfm)->cwksp && !zstd_context(tfm)->dwksp);
  assert(!lz4_init(tfm));
  unsigned int lz4_blocks = 0;
  for (unsigned int n = 1; n <= 65536; n *= 4) {
    unsigned int len = 66000;
    assert(!lz4_compress(tfm, input, n, actual, &len));
    int native_size = LZ4_compress_default((char*)input, (char*)expected, n, 66000);
    assert(native_size > 0 && len == (unsigned int)native_size && !memcmp(actual, expected, len));
    lz4_blocks++;
  }
  lz4_exit(tfm);
  free(tfm);
  free(native_workspace);
  free(old_workspace);
  free(input);
  free(actual);
  free(expected);
  free(decoded);
  assert(allocations == frees);
  printf(
      "PASS: native ZSTD parameter protocol and byte identity %u blocks; prior automatic outputs differing=%u; "
      "LZ4 default identity %u blocks; ZSTD cworkspace=%zu dworkspace=%zu bytes\n",
      blocks, different_from_automatic, lz4_blocks, csize, dsize);
}
