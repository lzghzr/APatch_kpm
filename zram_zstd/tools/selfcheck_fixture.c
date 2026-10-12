
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "linux/zstd.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
struct list_head { struct list_head *next, *prev; };
typedef struct { int counter; } atomic_t;
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-4095)
#define PTR_ERR(ptr) ((long)(ptr))
#define IS_ERR_OR_NULL(ptr) (!(ptr) || IS_ERR(ptr))
#define KPM_NAME(...)
#define KPM_VERSION(...)
#define KPM_LICENSE(...)
#define KPM_AUTHOR(...)
#define KPM_DESCRIPTION(...)
#define KPM_INFO(...)
#define KPM_INIT(...)
#define KPM_CTL0(...)
#define KPM_EXIT(...)
#define __user
#define printk printf
#define kfunc_def(name) (*kf_##name)
#define kfunc(name) kf_##name
#define kfunc_lookup_name(name) kf_##name = (typeof(kf_##name))lookup(#name)
typedef struct { uint64_t arg0, arg1, ret; } hook_fargs2_t;
typedef hook_fargs2_t hook_fargs1_t;
static int hook_wrap(void* func, int args, void* before, void* after, void* data);
static void* display_lookup(const char* name);
static void test_display(void);
/* ENTRIES */
static void* btf_lookup(const char* name);
static int function_lookups;
static int registration_mode, has_own_algorithm, registration_count, algorithm_queries;
static int registration_has_alg(const char* name, u32 type, u32 mask);
static int registration_alg(void* alg);
static void* allocate(unsigned long n);
static void release(const void* p);
static void* lookup(const char* name) {
  void* display = display_lookup(name);
  if (display) return display;
  if (registration_mode) {
    if (!strcmp(name, "crypto_has_alg")) return registration_has_alg;
    if (!strcmp(name, "crypto_register_alg")) return registration_alg;
    if (!strcmp(name, "vzalloc")) return allocate;
    if (!strcmp(name, "vfree")) return release;
    return btf_lookup(name);
  }
/* LOOKUP */
  return btf_lookup(name);
}
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { function_lookups++; return (uintptr_t)lookup(name); }
/* UTILITIES */
/* BTF_FIXTURE */
static int copy_limit = -1;
static int compat_copy_to_user(void* to, const void* from, int n) {
  int copied = copy_limit < 0 || copy_limit > n ? n : copy_limit;
  memcpy(to, from, copied);
  return copied;
}
/* PRODUCTION */
static void* allocate(unsigned long n) { return calloc(1, n); }
static void release(const void* p) { free((void*)p); }
static int registration_has_alg(const char* name, u32 type, u32 mask) {
  algorithm_queries++;
  assert(!strcmp(name, "zstd-kpm") && type == 2 && mask == 15);
  return has_own_algorithm;
}
static int registration_alg(void* alg) {
  assert(!strcmp((char*)alg + struct_offset.crypto_alg_name, "zstd-kpm"));
  assert(!strcmp((char*)alg + struct_offset.crypto_alg_driver_name, "zstd-kpm"));
  assert(*(u32*)((char*)alg + struct_offset.crypto_alg_flags) == 2);
  assert(*(u32*)((char*)alg + struct_offset.crypto_alg_flags + 16) == 0);
  assert(*(void**)((char*)alg + struct_offset.crypto_alg_init) == zstd_init);
  assert(*(void**)((char*)alg + struct_offset.crypto_alg_compress) == zstd_compress);
  registration_count++;
  return 0;
}
static int allocation_count;
static int fail_at;
static void* allocate_failing(unsigned long n) {
  return allocation_count++ == fail_at ? NULL : allocate(n);
}
int main(int argc, char** argv) {
  assert(argc == 3);
  kfunc(crypto_register_alg) = (typeof(kfunc(crypto_register_alg)))crypto_register_alg_entry;
  assert(calculate_offsets() == 0);
  /* REFERENCE_BEGIN */
  // 缺省 4.4 参考判据保持；其它目标必须提供绑定镜像哈希的独立参考。
  assert(struct_offset.crypto_alg_flags == 0x20);
  assert(struct_offset.crypto_alg_name == 0x38);
  assert(struct_offset.crypto_alg_compress == 0xc0);
  assert(struct_offset.crypto_alg_init == 0x100);
  assert(struct_offset.crypto_tfm_ctx == 0x80);
  assert(struct_offset.crypto_alg_driver_name == 0x78);
  /* REFERENCE_END */
  const uint32_t adjusted[] = {0x91008000, 0xf9408c01, 0xd65f03c0};
  const uint32_t replaced[] = {0xd2800000, 0xf9408c01, 0xd65f03c0};
  const uint32_t dereferenced[] = {0xf9400000, 0x3941e000, 0xd65f03c0};
  const uint32_t narrowed[] = {0x2a0003e1, 0xf9408c21, 0xd65f03c0};
  const uint32_t pair[] = {0xa9400001, 0x3941e000, 0xd65f03c0};
  const uint32_t writeback[] = {0xf8008401, 0xf9408c01, 0xd65f03c0};
  assert(find_parameter_access(adjusted, 3, false, 3) == -ENOENT);
  assert(find_parameter_access(replaced, 3, false, 3) == -ENOENT);
  assert(find_parameter_access(dereferenced, 3, false, 0) == -ENOENT);
  assert(find_parameter_access(narrowed, 3, false, 3) == -ENOENT);
  // 第一项读取不满足字节宽度；确认 pair 的第二目标和 writeback 的基址也失效。
  assert(find_parameter_access(pair, 3, false, 0) == -ENOENT);
  assert(find_parameter_access(writeback, 3, false, 3) == -ENOENT);
  // 多指令短锚点：基址、寄存器覆盖、窗口边界及真实调用目标。
  uint32_t callback[16] = {0xf9400008, 0x90000009, 0x91000129, 0xf940a108, 0xd65f03c0};
  assert(find_compress_callback(callback) == 0x140);
  callback[0] = 0xd2800000;
  callback[1] = 0xf9400008;
  callback[2] = 0xf940a108;
  assert(find_compress_callback(callback) == -ENOENT);
  callback[0] = 0xf9400008;
  callback[1] = 0xa9402001; // pair 第二目标 x8 覆盖算法寄存器。
  assert(find_compress_callback(callback) == -ENOENT);
  uint32_t cts[8] = {0xf9408000, 0x91020001, 0x94000001, 0xd65f03c0};
  uintptr_t destroy = (uintptr_t)(cts + 3);
  assert(find_cts_context(cts, destroy) == 0x80);
  assert(find_cts_context(cts, destroy + 4) == -ENOENT);
  cts[1] = 0x91020002; // 第二个实参不再是 x1。
  assert(find_cts_context(cts, destroy) == -ENOENT);
  cts[1] = 0x91420001; // 移位立即数不符合 base 偏移。
  assert(find_cts_context(cts, destroy) == -ENOENT);
  cts[0] = 0xd2800000;
  cts[1] = 0xf9408000;
  cts[2] = 0x91020001;
  cts[3] = 0x94000001;
  cts[4] = 0xd65f03c0;
  assert(find_cts_context(cts, (uintptr_t)(cts + 4)) == -ENOENT);
  cts[0] = 0x54000000; // 条件分支不能当作已确认的直线序言。
  assert(find_cts_context(cts, (uintptr_t)(cts + 4)) == -ENOENT);
  memset(cts, 0, sizeof(cts));
  cts[6] = 0xf9408000;
  cts[7] = 0x91020001;
  assert(find_cts_context(cts, 0) == -ENOENT); // BL 不得越出窗口。
  struct struct_offset target_offsets = struct_offset;
  btf_mode = 2;
  assert(calculate_offsets() == 0); // available interfaces, absent data: short functions
  btf_mode = 3; function_lookups = 0;
  assert(calculate_offsets() == -EIO && function_lookups == 0);
  btf_mode = 4;
  assert(calculate_offsets() == -ENOENT && function_lookups == 0);
  btf_mode = 1;
  for (unsigned int length = 64; length <= 128; length *= 2) {
    host_layout(length);
    assert(calculate_offsets() == 0 && function_lookups == 0);
    assert(struct_offset.crypto_alg_driver_name == 0x38 + length);
    assert(struct_offset.crypto_alg_compress == 0x40 + length * 2);
    host_alg.members[3].offset += 8;
    assert(calculate_offsets() == -EINVAL && function_lookups == 0);
    host_layout(length);
    host_alg.members[0].offset++;
    assert(calculate_offsets() == -EINVAL && function_lookups == 0);
    host_layout(length);
    host_alg.type.size = 1025;
    assert(calculate_offsets() == -EINVAL && function_lookups == 0);
  }
  btf_mode = 0;
  struct_offset = target_offsets;
  uint32_t compressed_saved[8];
  memcpy(compressed_saved, crypto_compress_entry, sizeof(compressed_saved));
  const uint32_t after_return[8] = {0xd65f03c0, 0xf9400008, 0xf9406108};
  memcpy(crypto_compress_entry, after_return, sizeof(compressed_saved));
  assert(calculate_offsets() == -ENOENT);
  crypto_compress_entry[0] = 0x14000001;
  assert(calculate_offsets() == -ENOENT);
  memcpy(crypto_compress_entry, compressed_saved, sizeof(compressed_saved));
  struct_offset = target_offsets;
  uint32_t saved[16];
  memcpy(saved, crypto_check_alg_entry, sizeof(saved));
  memset(crypto_check_alg_entry, 0, sizeof(saved));
  assert(calculate_offsets() == -ENOENT);
  memcpy(crypto_check_alg_entry, saved, sizeof(saved));
  struct_offset = target_offsets;
  assert(calculate_offsets() == 0);
  puts("PASS: BTF absence fallback, native error preservation, 64/128 names, layout rejection, missing short anchor");
  registration_mode = 1; btf_mode = 1; host_layout(128);
  assert(zram_zstd_init("", "pre-kernel-init", NULL) == -EINVAL && algorithm_queries == 0);
  has_own_algorithm = 1;
  assert(zram_zstd_init("", "post-kernel-init", NULL) == -EEXIST && registration_count == 0);
  has_own_algorithm = 0;
  assert(zram_zstd_init("", "post-kernel-init", NULL) == 0 && registration_count == 1 && registered);
  test_display();
  registered = false; registration_mode = 0; btf_mode = 0;
  struct_offset = target_offsets;
  puts("PASS: zstd-kpm name, duplicate detection, boot event, callback registration");
  kfunc(vzalloc) = allocate;
  kfunc(vfree) = release;
  assert(codec_check() == 0);
  char reply[8] = {0};
  assert(zram_zstd_ctl0("", reply, sizeof(reply)) == 0);
  assert(!strcmp(reply, "_(._.)_"));
  assert(zram_zstd_ctl0(NULL, reply, sizeof(reply)) == 0);
  assert(zram_zstd_ctl0("example", reply, sizeof(reply)) == 0);
  assert(zram_zstd_ctl0("", NULL, sizeof(reply)) == -EINVAL);
  assert(zram_zstd_ctl0("", reply, sizeof(reply) - 1) == -EINVAL);
  assert(zram_zstd_ctl0("", reply, -1) == -EINVAL);
  copy_limit = 7;
  assert(zram_zstd_ctl0("", reply, sizeof(reply)) == -EFAULT);
  copy_limit = -1;
  kfunc(vzalloc) = allocate_failing;
  for (fail_at = 0; fail_at < 2; fail_at++) {
    struct zstd_ctx ctx = {0};
    allocation_count = 0;
    assert(zstd_prepare(&ctx) == -ENOMEM);
    assert(!ctx.cwksp && !ctx.dwksp);
    zstd_release(&ctx);
  }
  kfunc(vzalloc) = allocate;
  void* tfm = calloc(1, struct_offset.crypto_tfm_ctx + sizeof(struct zstd_ctx));
  assert(tfm && zstd_init(tfm) == 0);
  void* library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  assert(library);
  size_t (*other_compress)(void*, size_t, const void*, size_t, int) = dlsym(library, "ZSTD_compress");
  size_t (*other_decompress)(void*, size_t, const void*, size_t) = dlsym(library, "ZSTD_decompress");
  assert(other_compress && other_decompress);
  FILE* image = fopen(argv[1], "rb");
  assert(image);
  unsigned char input[4096], encoded[8192], decoded[4096];
  for (unsigned int page = 0; page < 256; page++) {
    assert(fread(input, 1, sizeof(input), image) == sizeof(input));
    unsigned int size = sizeof(encoded), out = sizeof(decoded);
    assert(zstd_compress(tfm, input, sizeof(input), encoded, &size) == 0);
    assert(zstd_decompress(tfm, encoded, size, decoded, &out) == 0);
    assert(out == sizeof(input) && !memcmp(input, decoded, sizeof(input)));
    assert(other_decompress(decoded, sizeof(decoded), encoded, size) == sizeof(input));
    assert(!memcmp(input, decoded, sizeof(input)));
    size_t other = other_compress(encoded, sizeof(encoded), input, sizeof(input), 3);
    assert(other <= sizeof(encoded));
    out = sizeof(decoded);
    assert(zstd_decompress(tfm, encoded, other, decoded, &out) == 0);
    assert(out == sizeof(input) && !memcmp(input, decoded, sizeof(input)));
  }
  fclose(image);
  zstd_exit(tfm);
  assert(!zstd_context(tfm)->cwksp && !zstd_context(tfm)->dwksp);
  zstd_exit(tfm);
  free(tfm);
  dlclose(library);
  puts("PASS: actual-entry offsets, codec check, 256 kernel pages, libzstd interoperability");
  puts("PASS: ctl0 reply, output bounds, short copy, partial allocation and serial cleanup");
  return 0;
}

// 显示生产代码的边界与加载顺序自检；原有判据保持。
static pthread_mutex_t display_test_mutex = PTHREAD_MUTEX_INITIALIZER;
static int display_mode, display_ready, display_state_value;
static int display_load_failure, display_show_failure, display_complete_during_setup;
static int display_lock_depth, display_load_hooks, display_show_hooks;
static struct zs_module_prefix display_test_owner;
static void display_test_show(void) {}
static void display_test_load(void) {}
static void display_test_lock(void* lock) {
  assert(lock == &display_test_mutex);
  assert(!pthread_mutex_lock(&display_test_mutex));
  assert(display_lock_depth++ == 0);
}
static void display_test_unlock(void* lock) {
  assert(lock == &display_test_mutex && display_lock_depth-- == 1);
  assert(!pthread_mutex_unlock(&display_test_mutex));
}
static struct module* display_test_text(unsigned long address) {
  assert(display_lock_depth == 1 && address == (unsigned long)display_test_show);
  display_test_owner.state = display_state_value;
  return display_mode == 1 || display_mode == 3 ? NULL : (struct module*)&display_test_owner;
}
static int display_test_core(unsigned long address) {
  assert(display_lock_depth == 1 && address == (unsigned long)display_test_show);
  return display_mode == 1;
}
static void* display_lookup(const char* name) {
  if (!display_mode) return NULL;
  if (!strcmp(name, "module_mutex")) return &display_test_mutex;
  if (!strcmp(name, "mutex_lock")) return display_mode == 4 ? NULL : display_test_lock;
  if (!strcmp(name, "mutex_unlock")) return display_test_unlock;
  if (!strcmp(name, "__module_text_address")) return display_test_text;
  if (!strcmp(name, "core_kernel_text")) return display_test_core;
  if (!strcmp(name, "do_init_module")) return display_test_load;
  if (!strcmp(name, "zcomp_available_show")) return display_ready ? display_test_show : NULL;
  return NULL;
}
static int hook_wrap(void* func, int args, void* before, void* after, void* data) {
  assert(!before && !data);
  if (func == display_test_load) {
    assert(args == 1 && after == zram_module_after);
    display_load_hooks++;
    if (display_load_failure) return -4092;
    if (display_complete_during_setup) {
      display_ready = 1;
      hook_fargs1_t event = {.ret = 0};
      zram_module_after(&event, NULL);
    }
    return 0;
  }
  assert(func == display_test_show && args == 2 && after == zstd_list_after);
  assert(display_lock_depth == 1);
  display_show_hooks++;
  return display_show_failure ? -4092 : 0;
}
static void display_test_reset(int mode, int ready, int state) {
  display_mode = mode; display_ready = ready; display_state_value = state;
  display_load_failure = display_show_failure = display_complete_during_setup = 0;
  display_load_hooks = display_show_hooks = 0;
  __atomic_store_n(&display_installed, false, __ATOMIC_RELEASE);
}
static void* display_test_event(void* unused) {
  hook_fargs1_t event = {.ret = 0};
  zram_module_after(&event, NULL);
  assert(event.ret == 0);
  return NULL;
}
static void test_display(void) {
  static char buf[4096] __attribute__((aligned(4096)));
  static char saved[4096];
  const char* cases[] = {"[lzo] lz4 \n", "[lzo]\n", "[lzo]\t\n", "\n", "[zstd-kpm] lzo \n", "[lzo] zstd-kpm \n",
                         "[lzo] zstd-kpm-extra\n", "[lzo] foo[zstd-kpm]\n"};
  const char* expected[] = {"[lzo] lz4 zstd-kpm\n", "[lzo] zstd-kpm\n", "[lzo]\tzstd-kpm\n", "zstd-kpm\n",
                            "[zstd-kpm] lzo \n", "[lzo] zstd-kpm \n", "[lzo] zstd-kpm-extra zstd-kpm\n",
                            "[lzo] foo[zstd-kpm] zstd-kpm\n"};
  for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    memset(buf, 0x5a, sizeof(buf)); strcpy(buf, cases[i]);
    hook_fargs2_t args = {.arg1 = (uintptr_t)buf, .ret = strlen(buf)};
    zstd_list_after(&args, NULL);
    assert(!strcmp(buf, expected[i]) && args.ret == strlen(expected[i]));
    strcpy(saved, buf); zstd_list_after(&args, NULL);
    assert(!strcmp(buf, saved) && args.ret == strlen(expected[i]));
  }
  const long sizes[] = {-EINVAL, 0, 4096, 4095};
  for (unsigned int i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    memset(buf, 0x5a, sizeof(buf)); memcpy(saved, buf, sizeof(buf));
    hook_fargs2_t args = {.arg1 = (uintptr_t)buf, .ret = sizes[i]};
    zstd_list_after(&args, NULL);
    assert((long)args.ret == sizes[i] && !memcmp(buf, saved, sizeof(buf)));
  }
  hook_fargs2_t missing = {.ret = 1}; zstd_list_after(&missing, NULL); assert(missing.ret == 1);
  for (int offset = 4080; offset <= 4081; offset++) {
    memset(buf, 0x5a, sizeof(buf)); strcpy(buf + offset, "[lzo]\n"); memcpy(saved, buf, sizeof(buf));
    hook_fargs2_t args = {.arg1 = (uintptr_t)(buf + offset), .ret = 6};
    zstd_list_after(&args, NULL);
    if (offset == 4080) {
      assert(!strcmp(buf + offset, "[lzo] zstd-kpm\n") && args.ret == 15);
      assert(!memcmp(buf, saved, offset));
    } else assert(args.ret == 6 && !memcmp(buf, saved, sizeof(buf)));
  }
  strcpy(buf, "[lzo]"); memcpy(saved, buf, sizeof(buf));
  hook_fargs2_t no_newline = {.arg1 = (uintptr_t)buf, .ret = strlen(buf)};
  zstd_list_after(&no_newline, NULL); assert(!memcmp(buf, saved, sizeof(buf)));
  display_test_reset(1, 1, ZS_MODULE_LIVE); start_zram_display();
  assert(display_installed && display_load_hooks == 1 && display_show_hooks == 1);
  display_test_event(NULL); assert(display_show_hooks == 1);
  display_test_reset(2, 0, ZS_MODULE_LIVE); start_zram_display();
  assert(!display_installed && display_load_hooks == 1 && display_show_hooks == 0);
  display_ready = 1;
  hook_fargs1_t failure = {.ret = (uint32_t)-EINVAL}; zram_module_after(&failure, NULL);
  assert(!display_installed && display_show_hooks == 0 && (int)failure.ret == -EINVAL);
  pthread_t threads[8];
  for (int i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, display_test_event, NULL));
  for (int i = 0; i < 8; i++) assert(!pthread_join(threads[i], NULL));
  assert(display_installed && display_show_hooks == 1);
  display_test_reset(2, 1, ZS_MODULE_COMING); start_zram_display(); assert(!display_installed && !display_show_hooks);
  display_state_value = ZS_MODULE_LIVE; display_test_event(NULL); assert(display_installed && display_show_hooks == 1);
  display_test_reset(2, 0, ZS_MODULE_LIVE); display_complete_during_setup = 1; start_zram_display();
  assert(display_installed && display_show_hooks == 1);
  display_test_reset(3, 1, ZS_MODULE_LIVE); start_zram_display(); assert(!display_installed && !display_show_hooks);
  display_test_reset(4, 1, ZS_MODULE_LIVE); start_zram_display(); assert(!display_installed && !display_load_hooks);
  display_test_reset(1, 1, ZS_MODULE_LIVE); display_show_failure = 1; start_zram_display();
  assert(!display_installed && display_show_hooks == 1 && registered);
  display_show_failure = 0; display_test_event(NULL); assert(display_installed && display_show_hooks == 2);
  display_test_reset(1, 1, ZS_MODULE_LIVE); display_load_failure = 1; start_zram_display();
  assert(display_installed && display_show_hooks == 1 && registered);
  display_mode = 0;
  puts("PASS: algorithm list tokens, brackets, capacity, partial page, built-in/late module, COMING rejection, concurrent install, setup event and optional failure");
}
