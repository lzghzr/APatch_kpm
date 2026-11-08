/* SPDX-License-Identifier: GPL-2.0-only */
/* DEV-074: production TG1 decoding, pre-registration guard and immutable shared cache. */
static void page_size_tests(void) {
  static char list[4096] __attribute__((aligned(4096)));
  const unsigned int pages[] = {0, 16384, 4096, 65536};
  display_mode = 0;
  for (unsigned int tg1 = 0; tg1 < 4; tg1++) {
    for (unsigned int tg0 = 0; tg0 < 4; tg0++) {
      reset_registration();
      // User TG0 and unrelated high/low bits must not select the kernel granule.
      page_tcr = (uint64_t)tg1 << 30 | (uint64_t)tg0 << 14 | 0xa50000002000123fULL;
      assert(!zram_zstd_init("", "post-kernel-init", NULL));
      assert(zs_page_size == pages[tg1] && page_tcr_reads == 1);
      assert(query_count == 3 && calls == (tg1 == 2 ? 3 : 2) && !undone && registered);
      assert(algorithm_registered[0] && algorithm_registered[1]);
      assert(algorithm_registered[2] == (tg1 == 2));
      assert(accepted[0] == algorithms[0].storage && accepted[1] == algorithms[1].storage);
      assert(accepted[2] == (tg1 == 2 ? algorithms[2].storage : NULL));
      // Display and native selection consume the same cached value, never another register read.
      page_tcr = 0;
      strcpy(list, "[lzo]\n");
      hook_fargs2_t show = {.arg1 = (uintptr_t)list, .ret = strlen(list)};
      zstd_list_after(&show, NULL);
      assert(strstr(list, "zstd-kpm") && strstr(list, "lz4-kpm"));
      assert(!!strstr(list, "lz4kd-kpm") == (tg1 == 2));
      zs_native_seen = zs_native_ready = true;
      assert(zs_codec_selectable(0) && zs_codec_selectable(1));
      assert(zs_codec_selectable(2) == (tg1 == 2));
      assert(zs_page_size == pages[tg1] && page_tcr_reads == 1);
    }
    for (int mask = 0; mask < 8; mask++) {
      reset_registration();
      page_tcr = (uint64_t)tg1 << 30;
      fail_register = mask;
      long rc = zram_zstd_init("", "post-kernel-init", NULL);
      assert(rc == ((mask & 1) ? -EIO : 0));
      assert(page_tcr_reads == 1 && zs_page_size == pages[tg1]);
      assert(calls == ((mask & 1) ? 1 : tg1 == 2 ? 3 : 2) && !undone);
      for (unsigned int i = 0; i < 3; i++)
        assert(algorithm_registered[i] == (!(mask & 1) && !(mask & (1 << i)) && (i != 2 || tg1 == 2)));
    }
  }
  reset_registration();
  conflicts = 2;
  page_tcr = 1ULL << 30;
  assert(zram_zstd_init("", "post-kernel-init", NULL) == -EEXIST);
  assert(query_count == 3 && !calls && !registered && !page_tcr_reads);
  reset_registration();
  assert(zram_zstd_init("", "pre-kernel-init", NULL) == -EINVAL && !page_tcr_reads);
  assert(allocations == frees);
  puts(
      "PASS: TG1 4/16/64 KiB/reserved, TG0 isolation, one pre-registration read, shared cache, lists and all partial "
      "failures");
}
