/* SPDX-License-Identifier: GPL-2.0-only */
/* Real-BTF gate plus a two-CPU model of the pinned native zcomp lifecycle. */
#include "lz4.h"
// 既有断言保留原名，绑定到两个前端的新共享缓存。
#define zs_native_page_size zs_page_size
static void* lookup(const char* name);
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { return (uintptr_t)lookup(name); }
static int compat_copy_to_user(void* dst, const void* src, int size) {
  memcpy(dst, src, size);
  return size;
}
/* PRODUCTION */

static unsigned char owner_bytes[2048] __attribute__((aligned(8)));
static struct module* owner = (void*)owner_bytes;
static unsigned char image_header[64];
static unsigned int callbacks[6][2];
static int create_target, available_target, show_target, marker_target;
static int hook_calls, hook_fail, unwrap_calls, refs, btf_refs, absent_marker, pin_fail, bad_owner, bad_prefix;
static int module_btf_error, alloc_calls, live_allocs, fail_at, fail_cpu = -1;
static const char* missing;
static int native_tcr_reads;
static uint64_t read_tcr(uint32_t el) {
  assert(el == 1);
  native_tcr_reads++;
  // 将既有 Image 头夹具转成等价 TG1 输入，原有成功/未知页大小断言不变。
  // 旧 _text 缺失用例对应未知配置，不表示生产代码仍查找该符号。
  if ((missing && !strcmp(missing, "_text")) || image_header[56] != 0x41)
    return 0;
  unsigned int code = (image_header[24] >> 1) & 3;
  return (uint64_t)(code == 1 ? 2 : code == 2 ? 1 : code == 3 ? 3 : 0) << 30;
}

static void* allocate(unsigned long n) {
  if (++alloc_calls == fail_at)
    return NULL;
  void* p = calloc(1, n);
  assert(p);
  live_allocs++;
  return p;
}
static void release(const void* p) {
  if (p) {
    assert(live_allocs > 0);
    live_allocs--;
    free((void*)p);
  }
}
static void* mock_kmalloc(size_t n, unsigned int flags) {
  assert(n == sizeof(struct zcomp) && flags == 0xdc0);
  return allocate(n);
}
static void* mock_percpu(size_t n, size_t align, bool reserved, unsigned int flags) {
  assert(n == sizeof(struct zcomp_strm) && align == 8 && !reserved && flags == 0xcc0);
  return allocate(n * 2);
}
static struct module* mock_text(unsigned long p) {
  if (bad_owner)
    return NULL;
  if (p == (uintptr_t)&create_target || p == (uintptr_t)&available_target || p == (uintptr_t)&show_target)
    return owner;
  for (unsigned int i = 0; i < 6; i++) {
    if (p == (uintptr_t)&callbacks[i][1])
      return owner;
    if (!bad_prefix && p == (uintptr_t)&callbacks[i][0])
      return owner;
  }
  return NULL;
}
static struct module* mock_address(unsigned long p) {
  return !bad_owner && p == (uintptr_t)&marker_target ? owner : NULL;
}
static bool mock_get(struct module* p) {
  assert(p == owner);
  if (pin_fail)
    return false;
  refs++;
  return true;
}
static void mock_put(struct module* p) {
  assert(p == owner && refs == 1);
  refs--;
}
static struct btf* mock_btf(const struct module* p) {
  assert(p == owner);
  if (module_btf_error)
    return ERR_PTR(-EINVAL);
  btf_refs++;
  return &object;
}
static void mock_btf_put(struct btf* p) {
  assert(p == &object && btf_refs == 1);
  btf_refs--;
}
static unsigned long mock_module_symbol(const char* name) {
  if (missing && !strcmp(name, missing))
    return 0;
  if (!strcmp(name, "zram:backend_lz4"))
    return absent_marker ? 0 : (uintptr_t)&marker_target;
  if (!strcmp(name, "zram:zcomp_create"))
    return (uintptr_t)&create_target;
  if (!strcmp(name, "zram:zcomp_available_algorithm"))
    return (uintptr_t)&available_target;
  const char* names[] = {"zram:lz4_compress", "zram:lz4_decompress",   "zram:lz4_create",
                         "zram:lz4_destroy",  "zram:lz4_setup_params", "zram:lz4_release_params"};
  for (unsigned int i = 0; i < 6; i++)
    if (!strcmp(name, names[i]))
      return (uintptr_t)&callbacks[i][1];
  return 0;
}
static void cpu_free(struct zcomp* comp, int cpu) {
  struct zcomp_strm* strm = (struct zcomp_strm*)comp->stream + cpu;
  comp->ops->destroy_ctx(&strm->ctx);
  release(strm->local_copy);
  release(strm->buffer);
  strm->local_copy = strm->buffer = NULL;
}
static int cpu_up(struct zcomp* comp, int cpu) {
  if (cpu == fail_cpu)
    return -ENOMEM;
  struct zcomp_strm* s = (struct zcomp_strm*)comp->stream + cpu;
  int rc = comp->ops->create_ctx(comp->params, &s->ctx);
  if (rc)
    return rc;
  s->local_copy = allocate(zs_native_page_size);
  s->buffer = allocate(2 * zs_native_page_size);
  if (!s->local_copy || !s->buffer) {
    cpu_free(comp, cpu);
    return -ENOMEM;
  }
  return 0;
}
static int mock_cpuhp(int state, void* node, bool invoke) {
  assert(state == 61 && invoke);
  struct zcomp* comp = (void*)((char*)node - offsetof(struct zcomp, node));
  for (int cpu = 0; cpu < 2; cpu++) {
    int rc = cpu_up(comp, cpu);
    if (rc) {
      while (cpu) cpu_free(comp, --cpu);
      return rc;
    }
  }
  return 0;
}
static void mock_destroy(struct zcomp* comp) {
  for (int cpu = 0; cpu < 2; cpu++) cpu_free(comp, cpu);
  comp->ops->release_params(comp->params);
  release(comp->stream);
  release(comp);
}
static int hook_wrap(void* target, int argc, void* before, void* after, void* data) {
  assert(!zs_native_ready && refs == 1 && !after && !data);
  if (++hook_calls == 1)
    assert(target == &create_target && argc == 2 && before == zs_native_create_before);
  else
    assert(target == &available_target && argc == 1 && before == zs_native_available_before);
  return hook_calls == hook_fail ? -EIO : 0;
}
static void hook_unwrap(void* target, void* before, void* after) {
  assert(!zs_native_ready && target == &create_target && before == zs_native_create_before && !after);
  unwrap_calls++;
}
static void* lookup(const char* name) {
  if (missing && !strcmp(name, missing))
    return NULL;
#define ENTRY(n, fn)    \
  if (!strcmp(name, n)) \
  return (void*)(fn)
  ENTRY("bpf_get_btf_vmlinux", host_get);
  ENTRY("btf_find_by_name_kind", host_find);
  ENTRY("btf_type_by_id", host_type);
  ENTRY("btf_name_by_offset", host_name);
  ENTRY("btf_resolve_size", host_size);
  ENTRY("module_kallsyms_lookup_name", mock_module_symbol);
  ENTRY("btf_get_module_btf", mock_btf);
  ENTRY("btf_put", mock_btf_put);
  ENTRY("try_module_get", mock_get);
  ENTRY("module_put", mock_put);
  ENTRY("__module_address", mock_address);
  ENTRY("__kmalloc_noprof", mock_kmalloc);
  ENTRY("kfree", release);
  ENTRY("pcpu_alloc_noprof", mock_percpu);
  ENTRY("free_percpu", release);
  ENTRY("__cpuhp_state_add_instance", mock_cpuhp);
  ENTRY("_text", image_header);
#undef ENTRY
  return NULL;
}
static void reset(void) {
  assert(!live_allocs && !btf_refs);
  zs_native_ready = zs_native_seen = false;
  zs_native_page_size = 0;
  native_tcr_reads = 0;
  absent_marker = hook_calls = hook_fail = unwrap_calls = refs = pin_fail = bad_owner = bad_prefix = 0;
  module_btf_error = alloc_calls = fail_at = 0;
  fail_cpu = -1;
  missing = NULL;
  for (unsigned int i = 0; i < 3; i++) algorithm_registered[i] = true;
  const u32 hashes[] = {0x6cfa6c9d, 0x6cfa6c9d, 0x99e4d7cb, 0x719f1be7, 0x819d5c54, 0xef7e90ea};
  for (unsigned int i = 0; i < 6; i++) {
    callbacks[i][0] = hashes[i];
    callbacks[i][1] = 0xd503245f;
  }
  memset(image_header, 0, sizeof(image_header));
  u32 magic = 0x644d5241;
  u64 flags = 2;
  memcpy(image_header + 56, &magic, 4);
  memcpy(image_header + 24, &flags, 8);
  display_module_text = mock_text;
  kf_vzalloc = allocate;
  kf_vfree = release;
  struct kpm_btf btf;
  assert(!kpm_btf_init(&btf));
  struct kpm_btf_field f;
  assert(!kpm_btf_member(&btf, kpm_btf_type(&btf, "module", 4), "name", &f, 0));
  assert(f.offset / 8 + f.size <= sizeof(owner_bytes));
  memset(owner_bytes, 0, sizeof(owner_bytes));
  memcpy(owner_bytes + f.offset / 8, "zram", 5);
}
static void install(void) {
  // 宿主模型显式执行注册前步骤；生产 native 安装不再检测页大小。
  if (!zs_native_seen)
    zs_page_size = zs_detect_page_size();
  zs_native_try_install(owner, &show_target);
  assert(!btf_refs);
}
static void gates(void) {
  reset();
  absent_marker = 1;
  install();
  assert(!zs_native_seen && !hook_calls && zs_codec_selectable(2));
  reset();
  zs_native_try_install(NULL, &show_target);
  assert(!zs_native_seen && !hook_calls);
  const char* required[] = {"btf_get_module_btf",
                            "btf_put",
                            "try_module_get",
                            "module_put",
                            "__module_address",
                            "__kmalloc_noprof",
                            "kfree",
                            "pcpu_alloc_noprof",
                            "free_percpu",
                            "__cpuhp_state_add_instance",
                            "bpf_get_btf_vmlinux",
                            "zram:lz4_compress",
                            "zram:zcomp_create",
                            "zram:zcomp_available_algorithm",
                            "_text"};
  for (unsigned int i = 0; i < ARRAY_SIZE(required); i++) {
    reset();
    missing = required[i];
    install();
    assert(zs_native_seen && !zs_native_ready && !refs && !hook_calls && !zs_codec_selectable(0));
  }
  reset();
  module_btf_error = 1;
  install();
  assert(!zs_native_ready && !hook_calls);
  reset();
  bad_owner = 1;
  install();
  assert(!zs_native_ready && !hook_calls);
  reset();
  bad_prefix = 1;
  install();
  assert(!zs_native_ready && !hook_calls);
  reset();
  pin_fail = 1;
  install();
  assert(!zs_native_ready && !hook_calls && !refs);
  for (int i = 0; i < 6; i++) {
    reset();
    callbacks[i][0] ^= 1;
    install();
    assert(!zs_native_ready && !hook_calls);
  }
  for (int i = 1; i <= 2; i++) {
    reset();
    hook_fail = i;
    install();
    assert(!zs_native_ready && !refs && hook_calls == i && unwrap_calls == i - 1);
  }
  reset();
  image_header[56] ^= 1;
  install();
  assert(!zs_native_ready);
  reset();
  image_header[24] = 0;
  install();
  assert(!zs_native_ready);
  reset();
  install();
  assert(zs_native_ready && zs_native_page_size == 4096 && refs == 1 && hook_calls == 2);
  install();
  assert(hook_calls == 2 && refs == 1);
  struct kpm_btf btf;
  assert(!kpm_btf_init(&btf));
  const char* layouts[] = {"zcomp", "zcomp_ops", "zcomp_params", "zcomp_req", "zcomp_ctx", "zcomp_strm"};
  for (unsigned int i = 0; i < ARRAY_SIZE(layouts); i++) {
    struct btf_type* t = (void*)kpm_btf_type(&btf, layouts[i], 4);
    assert(t);
    t->size++;
    assert(!zs_native_layouts(&btf));
    t->size--;
    struct btf_member* m = (void*)(t + 1);
    m->offset += 8;
    assert(!zs_native_layouts(&btf));
    m->offset -= 8;
  }
  struct btf_type* fn = (void*)kpm_btf_type(&btf, "zcomp_create", 12);
  assert(fn);
  struct btf_type* proto = (void*)zs_native_unwrap(&btf, fn->size);
  proto->info--;
  assert(!zs_native_layouts(&btf));
  proto->info++;
  assert(zs_native_layouts(&btf));
  struct btf_type* en = NULL;
  for (u32 id = 1; id < ARRAY_SIZE(records); id++) {
    struct btf_type* t = (void*)host_type(&object, id);
    if (((t->info >> 24) & 31) == 6 && kpm_btf_enum(&btf, t, "___GFP_IO_BIT") >= 0) {
      en = t;
      break;
    }
  }
  assert(en && zs_native_gfp(&btf) && native_gfp == 0xcc0 && native_gfp_zero == 0xdc0);
  struct btf_enum* values = (void*)(en + 1);
  unsigned int at = 0;
  while (strcmp(host_name(&object, values[at].name_off), "___GFP_IO_BIT")) {
    at++;
    assert(at < (en->info & 65535));
  }
  int saved = values[at].value;
  values[at].value = 40;
  assert(!zs_native_gfp(&btf));
  values[at].value = saved;
}
static void names(void) {
  reset();
  install();
  const char* unknown[] = {"", "l", "lz4", "zstd", "lzo", "lz4-kp", "lz4-kpm-extra", "zstd-kpm\n\n"};
  for (unsigned int i = 0; i < ARRAY_SIZE(unknown); i++) {
    char* n = strdup(unknown[i]);
    assert(n);
    hook_fargs1_t a = {.arg0 = (uintptr_t)n, .ret = 99};
    zs_native_available_before(&a, NULL);
    assert(!a.skip_origin && a.ret == 99 && zs_native_index(n) == -1);
    hook_fargs2_t c = {.arg0 = (uintptr_t)n, .ret = 77};
    zs_native_create_before(&c, NULL);
    assert(!c.skip_origin && c.ret == 77);
    free(n);
  }
  for (unsigned int i = 0; i < 3; i++) {
    char name[32];
    snprintf(name, sizeof(name), "%s\n", algorithms[i].name);
    assert(zs_native_index(name) == i);
    hook_fargs1_t a = {.arg0 = (uintptr_t)name};
    zs_native_available_before(&a, NULL);
    assert(a.skip_origin && a.ret == 1);
    algorithm_registered[i] = false;
    a.skip_origin = 0;
    zs_native_available_before(&a, NULL);
    assert(a.skip_origin && !a.ret);
    struct zcomp_params p = {.level = (-0x7fffffff - 1)};
    hook_fargs2_t c = {.arg0 = (uintptr_t)name, .arg1 = (uintptr_t)&p};
    zs_native_create_before(&c, NULL);
    assert(c.skip_origin && (intptr_t)c.ret == -EINVAL);
    algorithm_registered[i] = true;
  }
  static char page[4096] __attribute__((aligned(4096)));
  for (unsigned int code = 1; code <= 3; code++) {
    reset();
    image_header[24] = code * 2;
    install();
    assert(zs_native_page_size == (1U << (10 + 2 * code)));
    strcpy(page, "[lz4] zstd\n");
    hook_fargs2_t a = {.arg1 = (uintptr_t)page, .ret = strlen(page)};
    zstd_list_after(&a, NULL);
    assert(strstr(page, "zstd-kpm") && strstr(page, "lz4-kpm"));
    assert(!!strstr(page, "lz4kd-kpm") == (code == 1));
  }
}
static void codecs(void) {
  for (unsigned int code = 1; code <= 3; code++) {
    reset();
    image_header[24] = code * 2;
    install();
    size_t page = zs_native_page_size;
    unsigned char *input = malloc(page), *encoded = malloc(2 * page), *decoded = malloc(page);
    assert(input && encoded && decoded);
    for (unsigned int index = 0; index < (code == 1 ? 3 : 2); index++) {
      struct zcomp_params params = {.level = (-0x7fffffff - 1)};
      hook_fargs2_t args = {.arg0 = (uintptr_t)algorithms[index].name, .arg1 = (uintptr_t)&params};
      zs_native_create_before(&args, NULL);
      struct zcomp* comp = (void*)args.ret;
      assert(args.skip_origin && !IS_ERR_OR_NULL(comp) && comp->ops == &native_ops[index]);
      struct zcomp_strm* streams = comp->stream;
      assert(streams[0].ctx.context && streams[1].ctx.context && streams[0].ctx.context != streams[1].ctx.context);
      for (int pattern = 0; pattern < 3; pattern++) {
        for (size_t i = 0; i < page; i++)
          input[i] = pattern == 0 ? 0 : pattern == 1 ? i % 251 : (i * 739 + i / 13) & 255;
        struct zcomp_req req = {.src = input, .src_len = page, .dst = encoded, .dst_len = 2 * page};
        assert(!comp->ops->compress(&params, &streams[0].ctx, &req));
        size_t n = req.dst_len;
        assert(n && n <= 2 * page);
        struct zcomp_req dec = {.src = encoded, .src_len = n, .dst = decoded, .dst_len = page};
        assert(!comp->ops->decompress(&params, &streams[1].ctx, &dec) && !memcmp(input, decoded, page));
        req.dst_len = 0;
        assert(comp->ops->compress(&params, &streams[0].ctx, &req) < 0 && !req.dst_len);
        dec.dst_len = page - 1;
        assert(comp->ops->decompress(&params, &streams[1].ctx, &dec) == -EINVAL);
        struct zcomp_req short_in = {.src = input, .src_len = page - 1, .dst = encoded, .dst_len = 2 * page};
        assert(comp->ops->compress(&params, &streams[0].ctx, &short_in) == -EINVAL && short_in.dst_len == 2 * page);
      }
      unsigned int short_size = 2 * page;
      struct zs_native_codec_ctx* private = streams[0].ctx.context;
      if (index == 0) {
        size_t size = zstd_encode(private->codec.zstd.cctx, encoded, short_size, input, page - 1);
        assert(!ZSTD_isError(size));
        short_size = size;
      } else if (index == 1) {
        assert(!lz4_encode(&private->codec.lz4, input, page - 1, encoded, &short_size));
      } else {
        assert(!lz4kd_encode_block(&private->codec.lz4kd, input, page - 1, encoded, &short_size));
      }
      struct zcomp_req short_output = {.src = encoded, .src_len = short_size, .dst = decoded, .dst_len = page};
      assert(comp->ops->decompress(&params, &streams[1].ctx, &short_output) == -EINVAL);
      struct zcomp_req broken = {.src = (const unsigned char*)"", .src_len = 0, .dst = decoded, .dst_len = page};
      assert(comp->ops->decompress(&params, &streams[1].ctx, &broken) < 0);
      mock_destroy(comp);
      assert(!live_allocs);
    }
    free(input);
    free(encoded);
    free(decoded);
  }
  for (unsigned int index = 0; index < 3; index++) {
    reset();
    install();
    for (int kind = 0; kind < 4; kind++) {
      struct zcomp_params p = {.level = (-0x7fffffff - 1)};
      if (kind == 0)
        p.dict = &p;
      if (kind == 1)
        p.dict_sz = 1;
      if (kind == 2)
        p.level = 999;
      if (kind == 3)
        p.drv_data = &p;
      assert(PTR_ERR(zs_native_create(index, &p)) == -EOPNOTSUPP && !live_allocs);
    }
    struct zcomp_params p = {.level = index == 0 ? 3 : index == 1 ? 1 : (-0x7fffffff - 1)};
    assert(!native_ops[index].setup_params(&p));
    alloc_calls = 0;
    struct zcomp* c = zs_native_create(index, &p);
    assert(!IS_ERR_OR_NULL(c));
    int count = alloc_calls;
    mock_destroy(c);
    for (int n = 1; n <= count; n++) {
      alloc_calls = 0;
      fail_at = n;
      p.level = (-0x7fffffff - 1);
      c = zs_native_create(index, &p);
      assert(IS_ERR(c) && PTR_ERR(c) == -ENOMEM && !live_allocs);
    }
    fail_at = 0;
    for (int cpu = 0; cpu < 2; cpu++) {
      fail_cpu = cpu;
      p.level = (-0x7fffffff - 1);
      c = zs_native_create(index, &p);
      assert(IS_ERR(c) && PTR_ERR(c) == -ENOMEM && !live_allocs);
    }
  }
}
static void shared_page_cache(void) {
  const unsigned int pages[] = {0, 4096, 16384, 65536};
  for (unsigned int code = 0; code < 4; code++) {
    reset();
    image_header[24] = code * 2;
    zs_page_size = zs_detect_page_size();
    assert(zs_page_size == pages[code] && native_tcr_reads == 1);
    // 原生安装只用注册前缓存；此后即使寄存器模型改变，也不重新读取。
    image_header[24] = 0;
    zs_native_try_install(owner, &show_target);
    assert(zs_page_size == pages[code] && native_tcr_reads == 1 && !btf_refs);
    assert(zs_native_ready == (code != 0));
    assert(hook_calls == (code ? 2 : 0) && refs == (code ? 1 : 0));
    assert(zs_codec_selectable(2) == (code == 1));
    zs_native_try_install(owner, &show_target);
    assert(zs_page_size == pages[code] && native_tcr_reads == 1);
  }
  puts("PASS: native consumes pre-registration shared page cache, no reread, unknown gate and retained LZ4KD 4 KiB boundary");
}

int main(int argc, char** argv) {
  assert(argc == 2);
  FILE* f = fopen(argv[1], "rb");
  assert(f);
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  blob = malloc(n);
  assert(blob && fread(blob, 1, n, f) == n);
  fclose(f);
  gates();
  names();
  codecs();
  shared_page_cache();
  assert(!live_allocs && !btf_refs);
  free(blob);
  puts(
      "PASS: real base/split BTF, native gates, qualified ownership/KCFI, hook rollback, exact names, 4/16/64 KiB "
      "codecs and two-CPU allocation unwind");
  return 0;
}
