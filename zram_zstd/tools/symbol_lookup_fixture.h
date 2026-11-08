/* SPDX-License-Identifier: GPL-2.0-only */
/* Additional entry-point contracts; the existing codec/display assertions stay intact. */
static int symbol_mode, old_alloc_queries, noprof_queries, noprof_allocations;

static void* symbol_noprof_allocate(unsigned long size) {
  noprof_allocations++;
  return allocate(size);
}

static void* lookup(const char* name) {
  if (!strcmp(name, "vzalloc")) {
    old_alloc_queries++;
    if (symbol_mode == 2 || symbol_mode == 3)
      return NULL;
  }
  if (!strcmp(name, "vzalloc_noprof")) {
    noprof_queries++;
    return symbol_mode == 1 || symbol_mode == 2 ? symbol_noprof_allocate : NULL;
  }
  if ((!strcmp(name, "vfree") && symbol_mode == 4) || (!strcmp(name, "crypto_register_alg") && symbol_mode == 5)
      || (!strcmp(name, "crypto_has_alg") && symbol_mode == 6))
    return NULL;
  return codec_lookup(name);
}

static void symbol_lookup_tests(void) {
  display_mode = 0;
  for (int mode = 1; mode <= 6; mode++) {
    reset_registration();
    symbol_mode = mode;
    old_alloc_queries = noprof_queries = noprof_allocations = 0;
    int before_alloc = allocations, before_free = frees;
    long rc = zram_zstd_init("", "post-fs-data", NULL);
    if (mode <= 2) {
      assert(rc == 0 && calls == 3 && query_count == 3 && registered);
      assert(kf_vzalloc == (mode == 1 ? allocate : symbol_noprof_allocate));
      assert(kf_vfree == release && kf_crypto_register_alg == crypto_register_alg);
      assert(old_alloc_queries == 1 && noprof_queries == (mode == 2));
      unsigned char input[4096], encoded[8192], decoded[4096];
      for (unsigned int i = 0; i < sizeof(input); i++) input[i] = i % 251;
      for (unsigned int i = 0; i < ZS_CODEC_COUNT; i++) {
        void* tfm = calloc(1, struct_offset.crypto_tfm_ctx + algorithms[i].ctxsize);
        assert(tfm && !algorithms[i].init(tfm));
        unsigned int size = sizeof(encoded), length = sizeof(decoded);
        assert(!algorithms[i].compress(tfm, input, sizeof(input), encoded, &size));
        assert(!algorithms[i].decompress(tfm, encoded, size, decoded, &length));
        assert(length == sizeof(input) && !memcmp(input, decoded, sizeof(input)));
        algorithms[i].exit(tfm);
        free(tfm);
      }
      assert(noprof_allocations == (mode == 2 ? allocations - before_alloc : 0));
      assert(allocations - before_alloc == frees - before_free);
    } else {
      assert(rc == -ENOENT && !calls && !registered);
      assert(allocations == before_alloc && frees == before_free);
      assert(query_count == (mode == 6 ? 0 : 3));
      assert(noprof_queries == (mode == 3));
      for (unsigned int i = 0; i < ZS_CODEC_COUNT; i++) assert(!algorithm_registered[i]);
    }
  }
  symbol_mode = 0;
  reset_registration();
  puts(
      "PASS: entry symbol lookup: old-name priority, noprof-only allocator, three codec roundtrips, missing "
      "allocator/free/register/query fail closed before allocation/publication");
}
