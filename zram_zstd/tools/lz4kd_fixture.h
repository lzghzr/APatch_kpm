/* SPDX-License-Identifier: GPL-2.0-only */
/* Extra production contracts; upstream decode is a differential reference, not an independent audit. */
static uint32_t lz4kd_random = 0x48793a15;
static unsigned int next_random(void) {
  lz4kd_random ^= lz4kd_random << 13;
  lz4kd_random ^= lz4kd_random >> 17;
  lz4kd_random ^= lz4kd_random << 5;
  return lz4kd_random;
}

static void lz4kd_tests(void) {
  for (int mask = 0; mask < 8; mask++) {
    reset_registration();
    fail_register = mask;
    int rc = zram_zstd_init("", "post-kernel-init", NULL);
    assert(rc == ((mask & 1) ? -EIO : 0));
    assert(calls == ((mask & 1) ? 1 : 3) && !undone);
    assert(registered == !(mask & 1));
    for (int i = 0; i < 3; i++) assert(algorithm_registered[i] == (!(mask & 1) && !(mask & (1 << i))));
  }
  reset_registration();
  assert(!zram_zstd_init("", "post-kernel-init", NULL));
  algorithm_registered[2] = false;
  static char page[4096] __attribute__((aligned(4096)));
  strcpy(page, "[lzo]\n");
  hook_fargs2_t args = {.arg1 = (uintptr_t)page, .ret = strlen(page)};
  zstd_list_after(&args, NULL);
  assert(!strcmp(page, "[lzo] zstd-kpm lz4-kpm\n"));
  algorithm_registered[2] = true;
  strcpy(page, "[lz4kd-kpm] lz4kd-kpm-extra\n");
  args.ret = strlen(page);
  zstd_list_after(&args, NULL);
  assert(!strcmp(page, "[lz4kd-kpm] lz4kd-kpm-extra zstd-kpm lz4-kpm\n"));

  unsigned char* tfm = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct lz4kd_ctx));
  unsigned char* second = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct lz4kd_ctx));
  assert(tfm && second);
  fail_alloc = 1;
  assert(lz4kd_init((void*)tfm) == -ENOMEM);
  assert(!lz4kd_context((void*)tfm)->workspace && !lz4kd_context((void*)tfm)->scratch);
  fail_alloc = 0;
  assert(!lz4kd_init((void*)tfm) && !lz4kd_init((void*)second));
  assert(lz4kd_context((void*)tfm)->workspace != lz4kd_context((void*)second)->workspace);
  assert(lz4kd_encode_state_bytes_min() == 8192);
  unsigned int reference_blocks = 0, blocks = 0;
  for (unsigned int n = 1; n <= 4096; n++) {
    unsigned char *in = malloc(n), *decoded = malloc(n), *encoded = malloc(n + 32), *small = malloc(n + 32);
    assert(in && decoded && encoded && small);
    for (unsigned int pattern = 0; pattern < 4; pattern++) {
      for (unsigned int i = 0; i < n; i++)
        in[i] = pattern == 0 ? 0 : pattern == 1 ? i % 7 : pattern == 2 ? next_random() : (i / 31 + i % 3);
      unsigned int len = n + 32, dlen = n;
      assert(!lz4kd_compress((void*)tfm, in, n, encoded, &len));
      assert(encoded[0] == 0 && len <= n + 32);
      assert(!lz4kd_decompress((void*)second, encoded, len, decoded, &dlen));
      assert(dlen == n && !memcmp(in, decoded, n));
      // 上游 length==8 的 pattern 误判另由固定普通块向量验证，不能作该长度的参考。
      if (len != 8) {
        assert(lz4kd_decode(encoded, decoded, len, n) == (int)n);
        assert(!memcmp(in, decoded, n));
        reference_blocks++;
      }
      unsigned int exact = len;
      assert(!lz4kd_compress((void*)second, in, n, small, &exact));
      assert(exact == len && !memcmp(small, encoded, len));
      memset(small, 0xa5, n + 32);
      unsigned int too_small = len - 1;
      assert(lz4kd_compress((void*)tfm, in, n, small, &too_small) == -EINVAL && too_small == len - 1);
      for (unsigned int i = 0; i < n + 32; i++) assert(small[i] == 0xa5);
      dlen = n - 1;
      assert(lz4kd_decompress((void*)tfm, encoded, len, decoded, &dlen) == -EINVAL && dlen == n - 1);
      blocks++;
    }
    free(in);
    free(decoded);
    free(encoded);
    free(small);
  }
  const unsigned char literal[] = {0, 0, 0, 16, 't', 'e', 's', 't'};
  const unsigned char repeat[] = {0, 3, 0x20, 0x0c, 'a', 'b', 'c'};
  unsigned char out[4096];
  unsigned int size = sizeof(out);
  assert(!lz4kd_decompress((void*)tfm, literal, sizeof(literal), out, &size));
  assert(size == 4 && !memcmp(out, "test", 4));
  size = sizeof(out);
  assert(!lz4kd_decompress((void*)tfm, repeat, sizeof(repeat), out, &size));
  assert(size == 9 && !memcmp(out, "abcabcabc", 9));
  const unsigned char bad[][5] = {{1, 0, 0, 4, 'x'}, {0, 0, 0, 0, 0}, {0, 1, 0, 0, 0}, {0, 0, 0, 252, 255}};
  for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    size = sizeof(out);
    assert(lz4kd_decompress((void*)tfm, bad[i], sizeof(bad[i]), out, &size) == -EINVAL && size == sizeof(out));
  }
  size = sizeof(out);
  assert(lz4kd_compress((void*)tfm, out, 0, out, &size) == -EINVAL && size == sizeof(out));
  assert(lz4kd_compress((void*)tfm, out, 4097, out, &size) == -EINVAL && size == sizeof(out));
  assert(lz4kd_compress((void*)tfm, out, UINT_MAX, out, &size) == -EINVAL && size == sizeof(out));
  assert(lz4kd_decompress((void*)tfm, literal, UINT_MAX, out, &size) == -EINVAL && size == sizeof(out));
  // 真正按声明长度分配，ASan 覆盖短输入、截断、长度扩展和不足输出。
  for (unsigned int i = 0; i < 50000; i++) {
    unsigned int len = next_random() % 128, cap = next_random() % 256;
    unsigned char *input = malloc(len ? len : 1), *output = malloc(cap ? cap : 1);
    assert(input && output);
    for (unsigned int j = 0; j < len; j++) input[j] = next_random();
    if (len)
      input[0] = 0;
    size = cap;
    int rc = lz4kd_decompress((void*)tfm, input, len, output, &size);
    assert(rc == 0 || rc == -EINVAL);
    assert(rc ? size == cap : size <= cap);
    free(input);
    free(output);
  }
  lz4kd_exit((void*)tfm);
  lz4kd_exit((void*)second);
  assert(!lz4kd_context((void*)tfm)->workspace && !lz4kd_context((void*)tfm)->scratch);
  assert(!lz4kd_context((void*)second)->workspace && !lz4kd_context((void*)second)->scratch);
  free(tfm);
  free(second);
  assert(allocations == frees);
  printf(
      "PASS: LZ4KD %u blocks (1..4096, four patterns), %u upstream decodes, exact/short output, golden vectors, 50000 "
      "malformed blocks\n",
      blocks, reference_blocks);
}
