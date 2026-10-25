/* SPDX-License-Identifier: GPL-2.0-only */
/* Host contract tests; native registration/LSM/swap concurrency remain device work. */
#include <limits.h>

#include "lz4.h"
static int conflicts = -1, query_count, fail_register, calls, undone;
static void* accepted[2];
static int allocations, frees, fail_alloc;
static unsigned int name_length = 64;
static void* allocate(unsigned long n) {
  if (fail_alloc)
    return NULL;
  void* result = calloc(1, n);
  if (result)
    allocations++;
  return result;
}
static void release(const void* p) {
  if (p)
    frees++;
  free((void*)p);
}
static int crypto_has_alg(const char* name, u32 type, u32 mask);
static int crypto_register_alg(void* alg);
static void* lookup(const char* name);
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { return (uintptr_t)lookup(name); }
static int hook_wrap(void* func, int args, void* before, void* after, void* data) { return 0; }
static int compat_copy_to_user(void* dest, const void* src, int len) {
  memcpy(dest, src, len);
  return len;
}
/* UTILITIES */
/* BTF */
/* PRODUCTION */
static int crypto_has_alg(const char* name, u32 type, u32 mask) {
  assert(type == 2 && mask == 15);
  assert(query_count < 2 && !strcmp(name, algorithms[query_count].name));
  return query_count++ == conflicts;
}
static int crypto_register_alg(void* raw) {
  assert(calls < 2);
  int index = calls++;
  assert(index < 2 && raw == algorithms[index].storage);
  const struct zs_algorithm* codec = &algorithms[index];
  struct zs_crypto_alg_prefix* prefix = raw;
  assert(prefix->cra_flags == 2 && prefix->cra_ctxsize == codec->ctxsize);
  assert(!strcmp((char*)raw + struct_offset.crypto_alg_name, codec->name));
  assert(!strcmp((char*)raw + struct_offset.crypto_alg_driver_name, codec->name));
  struct zs_compress_alg* api = (void*)((char*)raw + struct_offset.crypto_alg_compress);
  struct zs_alg_lifecycle* life = (void*)((char*)raw + struct_offset.crypto_alg_init);
  assert(api->coa_compress == codec->compress && api->coa_decompress == codec->decompress);
  assert(life->cra_init == codec->init && life->cra_exit == codec->exit && !life->cra_module);
  if (fail_register & (1 << index))
    return -EIO;
  accepted[index] = raw;
  return 0;
}
static void* lookup(const char* name) {
  if (!strcmp(name, "crypto_has_alg"))
    return crypto_has_alg;
  if (!strcmp(name, "crypto_register_alg"))
    return crypto_register_alg;
  if (!strcmp(name, "vzalloc"))
    return allocate;
  if (!strcmp(name, "vfree"))
    return release;
  return btf_lookup(name);
}
static void reset_registration(void) {
  registered = false;
  conflicts = -1;
  fail_register = 0;
  calls = undone = query_count = 0;
  memset(accepted, 0, sizeof(accepted));
  memset(algorithm_registered, 0, sizeof(algorithm_registered));
  btf_mode = 1;
  host_layout(name_length);
}
static void registration_tests(void) {
  reset_registration();
  assert(zram_zstd_init("", "pre-kernel-init", NULL) == -EINVAL && !query_count && !calls);
  for (int i = 0; i < 2; i++) {
    reset_registration();
    conflicts = i;
    assert(zram_zstd_init("", "post-kernel-init", NULL) == -EEXIST && !calls && !undone);
    assert(query_count == i + 1 && !registered);
  }
  for (int i = 0; i < 2; i++) {
    reset_registration();
    fail_register = 1 << i;
    if (i == 0) {
      assert(zram_zstd_init("", "post-kernel-init", NULL) == -EIO && !registered);
      assert(calls == 1 && !undone);
      assert(!algorithm_registered[0] && !algorithm_registered[1]);
    } else {
      assert(zram_zstd_init("", "post-kernel-init", NULL) == 0 && registered);
      assert(calls == 2 && !undone);
      for (int j = 0; j < 2; j++) assert(algorithm_registered[j] == (i != j));
    }
  }
  reset_registration();
  fail_register = 3;
  assert(zram_zstd_init("", "post-kernel-init", NULL) == -EIO && !registered && calls == 1);
  assert(!algorithm_registered[0] && !algorithm_registered[1]);
  reset_registration();
  assert(zram_zstd_init("", "post-kernel-init", NULL) == 0 && calls == 2 && !undone && registered);
  assert(!strcmp(algorithms[0].name, "zstd-kpm"));
  assert(!strcmp(algorithms[1].name, "lz4-kpm"));
  assert(sizeof(algorithms) / sizeof(algorithms[0]) == 2);
  assert(algorithms[0].compress == zstd_compress && algorithms[0].init == zstd_init);
  assert(algorithms[1].compress == lz4_compress && algorithms[1].init == lz4_init);
  assert(algorithms[0].ctxsize == sizeof(struct zstd_ctx));
  assert(algorithms[1].ctxsize == sizeof(void*) && sizeof(struct lz4_ctx) == sizeof(void*));
  assert(zram_zstd_exit(NULL) == 0 && !undone);  // resident: exit is not a safe hot-unload path
  int old_driver = struct_offset.crypto_alg_driver_name;
  struct_offset.crypto_alg_driver_name = struct_offset.crypto_alg_name + 8;
  assert(prepare_algorithm(&algorithms[0]) == -EINVAL);
  struct_offset.crypto_alg_driver_name = struct_offset.crypto_alg_name + 9;
  assert(prepare_algorithm(&algorithms[0]) == 0);
  struct_offset.crypto_alg_driver_name = old_driver;
  assert(allocations == frees);
}
static void display_tests(void) {
  static char page[4096] __attribute__((aligned(4096)));
  static char saved[4096];
  const char* input[] = {"[lzo] lz4 \n",
                         "[zstd-kpm] lzo\n",
                         "[lz4-kpm] zstd-kpm\n",
                         "[zstd-kpm] lz4-kpm\n",
                         "[lzo] zstd-kpm-extra foo[zstd-kpm]\n",
                         "\n",
                         "[zstd-kpm] lz4-kpm\n",
                         "zstd-kpm\n"};
  const char* output[] = {"[lzo] lz4 zstd-kpm lz4-kpm\n",
                          "[zstd-kpm] lzo lz4-kpm\n",
                          "[lz4-kpm] zstd-kpm\n",
                          "[zstd-kpm] lz4-kpm\n",
                          "[lzo] zstd-kpm-extra foo[zstd-kpm] zstd-kpm lz4-kpm\n",
                          "zstd-kpm lz4-kpm\n",
                          "[zstd-kpm] lz4-kpm\n",
                          "zstd-kpm lz4-kpm\n"};
  for (unsigned int i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
    memset(page, 0x5a, sizeof(page));
    strcpy(page, input[i]);
    hook_fargs2_t args = {.arg1 = (uintptr_t)page, .ret = strlen(page)};
    zstd_list_after(&args, NULL);
    assert(!strcmp(page, output[i]) && args.ret == strlen(output[i]));
    strcpy(saved, page);
    zstd_list_after(&args, NULL);
    assert(!strcmp(page, saved) && args.ret == strlen(output[i]));
  }
  algorithm_registered[0] = false;
  strcpy(page, "[zstd-kpm] lzo\n");
  hook_fargs2_t partial = {.arg1 = (uintptr_t)page, .ret = strlen(page)};
  zstd_list_after(&partial, NULL);
  assert(!strcmp(page, "[zstd-kpm] lzo lz4-kpm\n"));
  algorithm_registered[0] = true;
  algorithm_registered[1] = false;
  strcpy(page, "[lzo]\n");
  partial.ret = strlen(page);
  zstd_list_after(&partial, NULL);
  assert(!strcmp(page, "[lzo] zstd-kpm\n"));
  algorithm_registered[1] = true;
  const long bad[] = {-EINVAL, 0, 4095, 4096};
  for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    memset(page, 0x5a, sizeof(page));
    memcpy(saved, page, sizeof(page));
    hook_fargs2_t args = {.arg1 = (uintptr_t)page, .ret = bad[i]};
    zstd_list_after(&args, NULL);
    assert((long)args.ret == bad[i] && !memcmp(page, saved, sizeof(page)));
  }
  hook_fargs2_t nil = {.ret = 1};
  zstd_list_after(&nil, NULL);
  assert(nil.ret == 1);
  strcpy(page, "[lzo]");
  memcpy(saved, page, sizeof(page));
  hook_fargs2_t missing_newline = {.arg1 = (uintptr_t)page, .ret = strlen(page)};
  zstd_list_after(&missing_newline, NULL);
  assert(!memcmp(page, saved, sizeof(page)));
  memset(page, 0x5a, sizeof(page));
  strcpy(page + 4080, "[lzo] zstd-kpm\n");
  hook_fargs2_t tight_foreign_name = {.arg1 = (uintptr_t)(page + 4080), .ret = strlen(page + 4080)};
  memcpy(saved, page, sizeof(page));
  zstd_list_after(&tight_foreign_name, NULL);
  assert(!strcmp(page + 4080, "[lzo] zstd-kpm\n") && tight_foreign_name.ret == 15);
  assert(!memcmp(page, saved, sizeof(page)));
  const char* result = "[lzo] zstd-kpm lz4-kpm\n";
  size_t required = strlen(result) + 1;
  for (int spare = 0; spare < 2; spare++) {
    size_t off = 4096 - required + spare;
    memset(page, 0x5a, sizeof(page));
    strcpy(page + off, "[lzo]\n");
    memcpy(saved, page, sizeof(page));
    hook_fargs2_t args = {.arg1 = (uintptr_t)(page + off), .ret = 6};
    zstd_list_after(&args, NULL);
    if (!spare) {
      assert(!strcmp(page + off, result) && args.ret == strlen(result));
      assert(!memcmp(page, saved, off));
    } else
      assert(args.ret == 6 && !memcmp(page, saved, sizeof(page)));
  }
}
static void codec_tests(const char* library, const char* zstd_library) {
  void* zstd_handle = dlopen(zstd_library, RTLD_NOW | RTLD_LOCAL);
  assert(zstd_handle);
  size_t (*other_zstd_compress)(void*, size_t, const void*, size_t, int) = dlsym(zstd_handle, "ZSTD_compress");
  size_t (*other_zstd_decompress)(void*, size_t, const void*, size_t) = dlsym(zstd_handle, "ZSTD_decompress");
  assert(other_zstd_compress && other_zstd_decompress);
  void* handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
  assert(handle);
  int (*other_compress)(const char*, char*, int, int) = dlsym(handle, "LZ4_compress_default");
  int (*other_decompress)(const char*, char*, int, int) = dlsym(handle, "LZ4_decompress_safe");
  assert(other_compress && other_decompress);
  unsigned char* tfm = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct zstd_ctx));
  assert(tfm);
  unsigned char* second = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct zstd_ctx));
  assert(second);
  fail_alloc = 1;
  assert(lz4_init((void*)tfm) == -ENOMEM);
  fail_alloc = 0;
  assert(!lz4_init((void*)tfm) && !lz4_init((void*)second));
  assert(lz4_context((void*)tfm)->workspace != lz4_context((void*)second)->workspace);
  assert(LZ4_sizeofState() > 0 && !((uintptr_t)lz4_context((void*)tfm)->workspace & 7));
  const unsigned int sizes[] = {0, 1, 4096, 16384, 65536};
  unsigned char *data = malloc(65536), *compressed = malloc(66000), *decoded = malloc(65536);
  assert(data && compressed && decoded);
  for (unsigned int i = 0; i < 65536; i++) data[i] = (i * 31U + i / 19U) % 251;
  for (unsigned int i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    unsigned int len = 66000, dlen = sizes[i];
    assert(!lz4_compress((void*)tfm, data, sizes[i], compressed, &len));
    assert(!lz4_decompress((void*)tfm, compressed, len, decoded, &dlen) && dlen == sizes[i]);
    assert(!memcmp(data, decoded, dlen));
    assert(other_decompress((void*)compressed, (void*)decoded, len, 65536) == sizes[i]
           && !memcmp(data, decoded, sizes[i]));
    int independent = other_compress((void*)data, (void*)compressed, sizes[i], 66000);
    assert(independent > 0);
    dlen = 65536;
    assert(!lz4_decompress((void*)second, compressed, independent, decoded, &dlen) && dlen == sizes[i]);
    assert(!memcmp(data, decoded, dlen));
  }
  unsigned int len = 0;
  assert(lz4_compress((void*)tfm, data, 4096, compressed, &len) == -EINVAL && !len);
  len = 66000;
  assert(lz4_compress((void*)tfm, data, UINT_MAX, compressed, &len) == -EINVAL && len == 66000);
  len = UINT_MAX;
  assert(lz4_compress((void*)tfm, data, 1, compressed, &len) == -EINVAL && len == UINT_MAX);
  compressed[0] = 0xff;
  len = 4096;
  assert(lz4_decompress((void*)tfm, compressed, 1, decoded, &len) == -EINVAL && len == 4096);
  len = 4096;
  assert(lz4_decompress((void*)tfm, compressed, UINT_MAX, decoded, &len) == -EINVAL && len == 4096);
  len = UINT_MAX;
  assert(lz4_decompress((void*)tfm, compressed, 1, decoded, &len) == -EINVAL && len == UINT_MAX);
  lz4_exit((void*)tfm);
  lz4_exit((void*)second);
  assert(!lz4_context((void*)tfm)->workspace && !lz4_context((void*)second)->workspace);
  for (unsigned int i = 0; i < 1; i++) {
    assert(!algorithms[i].init((void*)tfm));
    len = 66000;
    unsigned int decoded_len = 65536;
    assert(!algorithms[i].compress((void*)tfm, data, 65536, compressed, &len));
    assert(!algorithms[i].decompress((void*)tfm, compressed, len, decoded, &decoded_len) && decoded_len == 65536);
    assert(!memcmp(data, decoded, 65536));
    assert(other_zstd_decompress(decoded, 65536, compressed, len) == 65536 && !memcmp(data, decoded, 65536));
    size_t independent = other_zstd_compress(compressed, 66000, data, 65536, 3);
    assert(!ZSTD_isError(independent));
    decoded_len = 65536;
    assert(!algorithms[i].decompress((void*)tfm, compressed, independent, decoded, &decoded_len));
    assert(decoded_len == 65536 && !memcmp(data, decoded, 65536));
    algorithms[i].exit((void*)tfm);
  }
  uint32_t random = 0x12345678;
  for (unsigned int i = 0; i < 65536; i++) {
    random ^= random << 13;
    random ^= random >> 17;
    random ^= random << 5;
    data[i] = random;
  }
  assert(!lz4_init((void*)tfm));
  len = 65536;
  assert(lz4_compress((void*)tfm, data, 65536, compressed, &len) == -EINVAL && len == 65536);
  len = 66000;
  assert(!lz4_compress((void*)tfm, data, 65536, compressed, &len));
  assert(other_decompress((void*)compressed, (void*)decoded, len, 65536) == 65536 && !memcmp(data, decoded, 65536));
  lz4_exit((void*)tfm);
  free(data);
  free(compressed);
  free(decoded);
  free(tfm);
  free(second);
  dlclose(handle);
  dlclose(zstd_handle);
  assert(allocations == frees);
}
int main(int argc, char** argv) {
  assert(argc == 3);
  registration_tests();
  name_length = 128;
  registration_tests();
  display_tests();
  codec_tests(argv[1], argv[2]);
  printf(
      "PASS: registrations/resident partial failure, ctx lifecycle, exact stable names/foreign token preservation, bounded lists, LZ4 "
      "independent interop; state=%d bytes\n",
      LZ4_sizeofState());
}
