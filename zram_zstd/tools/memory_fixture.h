/* SPDX-License-Identifier: GPL-2.0-only */
static unsigned int memory_copy_calls, memory_move_calls, memory_set_calls;
static void* counted_copy(void* dst, const void* src, size_t n) {
  memory_copy_calls++;
  return memcpy(dst, src, n);
}
static void* counted_move(void* dst, const void* src, size_t n) {
  memory_move_calls++;
  return memmove(dst, src, n);
}
static void* counted_set(void* dst, int value, size_t n) {
  memory_set_calls++;
  return memset(dst, value, n);
}
static void zs_memory_tests(void) {
  static const size_t sizes[] = {0, 1, 7, 8, 16, 31, 64, 127, 128, 129, 255, 256, 257, 4096};
  void* (*copy)(void*, const void*, size_t) = kf_memcpy;
  void* (*move)(void*, const void*, size_t) = kf_memmove;
  void* (*set)(void*, int, size_t) = kf_memset;
  kf_memcpy = counted_copy;
  kf_memmove = counted_move;
  kf_memset = counted_set;
  unsigned char input[8192], actual[8192], expected[8192];
  for (size_t i = 0; i < sizeof(input); i++) input[i] = i % 251;
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    volatile size_t requested = sizes[i];
    size_t n = requested;
    memset(actual, 0xa5, sizeof(actual));
    memset(expected, 0xa5, sizeof(expected));
    unsigned int count = memory_copy_calls;
    assert(zs_memcpy(actual + 1, input + 3, n) == actual + 1);
    memcpy(expected + 1, input + 3, n);
    assert(memory_copy_calls == count + 1 && !memcmp(actual, expected, sizeof(actual)));
    for (unsigned int direction = 0; direction < 2; direction++) {
      memcpy(actual, input, sizeof(actual));
      memcpy(expected, input, sizeof(expected));
      unsigned int to = direction ? 1 : 3, from = direction ? 3 : 1;
      count = memory_move_calls;
      assert(zs_memmove(actual + to, actual + from, n) == actual + to);
      memmove(expected + to, expected + from, n);
      assert(memory_move_calls == count + 1 && !memcmp(actual, expected, sizeof(actual)));
    }
    count = memory_set_calls;
    assert(zs_memset(actual + 1, 0x6d, n) == actual + 1);
    memset(expected + 1, 0x6d, n);
    assert(memory_set_calls == count + 1 && !memcmp(actual, expected, sizeof(actual)));
  }
  unsigned int count = memory_copy_calls;
  assert(zs_memcpy(actual + 1, input + 3, 16) == actual + 1);
  assert(memory_copy_calls == count && !memcmp(actual + 1, input + 3, 16));
  count = memory_move_calls;
  memcpy(expected, actual, sizeof(actual));
  assert(zs_memmove(actual + 3, actual + 1, 16) == actual + 3);
  memmove(expected + 3, expected + 1, 16);
  assert(memory_move_calls == count && !memcmp(actual, expected, sizeof(actual)));
  count = memory_set_calls;
  assert(zs_memset(actual, 0, 256) == actual);
  memset(expected, 0, 256);
  assert(memory_set_calls == count && !memcmp(actual, expected, sizeof(actual)));
  count = memory_set_calls;
  assert(zs_memset(actual, 0, 4096) == actual);
  memset(expected, 0, 4096);
  assert(memory_set_calls == count + 1 && !memcmp(actual, expected, sizeof(actual)));
  // Verify the real encoder translation unit consumed the generated platform header.
  struct lz4kd_ctx kd = {0};
  assert(!lz4kd_prepare(&kd));
  unsigned int encoded_size = sizeof(actual);
  count = memory_set_calls;
  assert(!lz4kd_encode_block(&kd, input, 4096, actual, &encoded_size));
  assert(memory_set_calls == count + 1);
  lz4kd_release(&kd);
  assert(allocations == frees);
  kf_memcpy = copy;
  kf_memmove = move;
  kf_memset = set;
  printf(
      "PASS: production inline memory adapter, dynamic 0..4096, overlap both directions, fixed copies/fill and large "
      "clear\n");
}
static void zs_zstd_error_tests(void) {
  for (size_t i = 0; i < 1024; i++) {
    assert(zs_zstd_is_error(i) == ZSTD_isError(i));
    assert(zs_zstd_is_error((size_t)0 - i) == ZSTD_isError((size_t)0 - i));
  }
  assert(zs_zstd_is_error((size_t)1 << (sizeof(size_t) * 8 - 1))
         == ZSTD_isError((size_t)1 << (sizeof(size_t) * 8 - 1)));
  printf("PASS: inline ZSTD error predicate equals the linked upstream public API\n");
}
