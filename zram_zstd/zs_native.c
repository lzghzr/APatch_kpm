/* SPDX-License-Identifier: GPL-2.0-only */
/* New zram frontend. The original Crypto registrations and entry points remain independent. */
struct zs_native_codec_ctx {
  unsigned int index;
  union {
    struct zstd_ctx zstd;
    struct lz4_ctx lz4;
    struct lz4kd_ctx lz4kd;
  } codec;
};

static void* (*native_kmalloc)(size_t, unsigned int);
static void (*native_kfree)(const void*);
static void* (*native_percpu_alloc)(size_t, size_t, bool, unsigned int);
static void (*native_percpu_free)(void*);
static int (*native_cpuhp_add)(int, void*, bool);
static bool (*native_module_get)(struct module*);
static void (*native_module_put)(struct module*);
static struct module* (*native_module_address)(unsigned long);
static unsigned long (*native_module_symbol)(const char*);
static struct btf* (*native_module_btf)(const struct module*);
static void (*native_btf_put)(struct btf*);
static unsigned int native_gfp, native_gfp_zero;
static int native_cpuhp_state;

static bool zs_codec_selectable(unsigned int index) {
  return algorithm_registered[index]
         && (!__atomic_load_n(&zs_native_seen, __ATOMIC_ACQUIRE)
             || (__atomic_load_n(&zs_native_ready, __ATOMIC_ACQUIRE)
                 && (index != 2 || zs_page_size == ZS_LZ4KD_BLOCK)));
}

static int zs_native_index(const char* name) {
  if (!name)
    return -1;
  size_t actual = strlen(name);
  if (actual && name[actual - 1] == '\n')
    actual--;
  for (unsigned int i = 0; i < ZS_CODEC_COUNT; i++) {
    size_t length = strlen(algorithms[i].name);
    if (actual == length && !memcmp(name, algorithms[i].name, length))
      return i;
  }
  return -1;
}

static int zs_native_setup(unsigned int index, struct zcomp_params* params) {
  int level = index == 0 ? 3 : index == 1 ? 1 : (-0x7fffffff - 1);
  if (params->dict || params->dict_sz || params->drv_data
      || (params->level != (-0x7fffffff - 1) && params->level != level))
    return -EOPNOTSUPP;
  params->level = level;
  return 0;
}

int zs_native_setup_zstd_impl(struct zcomp_params* params) { return zs_native_setup(0, params); }
int zs_native_setup_lz4_impl(struct zcomp_params* params) { return zs_native_setup(1, params); }
int zs_native_setup_lz4kd_impl(struct zcomp_params* params) { return zs_native_setup(2, params); }
void zs_native_release_impl(struct zcomp_params* params) {}

static int zs_native_create_ctx(unsigned int index, struct zcomp_ctx* ctx) {
  struct zs_native_codec_ctx* data = kfunc(vzalloc)(sizeof(*data));
  if (!data)
    return -ENOMEM;
  data->index = index;
  int rc = index == 0   ? zstd_prepare(&data->codec.zstd)
           : index == 1 ? lz4_prepare(&data->codec.lz4)
                        : lz4kd_prepare(&data->codec.lz4kd);
  if (rc) {
    kfunc(vfree)(data);
    return rc;
  }
  ctx->context = data;
  return 0;
}

int zs_native_create_zstd_impl(struct zcomp_params* params, struct zcomp_ctx* ctx) {
  return zs_native_create_ctx(0, ctx);
}
int zs_native_create_lz4_impl(struct zcomp_params* params, struct zcomp_ctx* ctx) {
  return zs_native_create_ctx(1, ctx);
}
int zs_native_create_lz4kd_impl(struct zcomp_params* params, struct zcomp_ctx* ctx) {
  return zs_native_create_ctx(2, ctx);
}

void zs_native_destroy_impl(struct zcomp_ctx* ctx) {
  struct zs_native_codec_ctx* data = ctx->context;
  if (!data)
    return;
  if (data->index == 0)
    zstd_release(&data->codec.zstd);
  else if (data->index == 1)
    lz4_release(&data->codec.lz4);
  else
    lz4kd_release(&data->codec.lz4kd);
  kfunc(vfree)(data);
  ctx->context = NULL;
}

int zs_native_compress_impl(struct zcomp_params* params, struct zcomp_ctx* ctx, struct zcomp_req* req) {
  struct zs_native_codec_ctx* data = ctx->context;
  if (!data || req->src_len != zs_page_size || req->dst_len > 0x7fffffffU)
    return -EINVAL;
  unsigned int length = req->dst_len;
  int rc;
  if (data->index == 0) {
    size_t size = zstd_encode(data->codec.zstd.cctx, req->dst, length, req->src, req->src_len);
    rc = zs_zstd_is_error(size) ? -EINVAL : 0;
    length = rc ? length : size;
  } else if (data->index == 1) {
    rc = lz4_encode(&data->codec.lz4, req->src, req->src_len, req->dst, &length);
  } else {
    rc = lz4kd_encode_block(&data->codec.lz4kd, req->src, req->src_len, req->dst, &length);
  }
  if (!rc)
    req->dst_len = length;
  return rc;
}

int zs_native_decompress_impl(struct zcomp_params* params, struct zcomp_ctx* ctx, struct zcomp_req* req) {
  struct zs_native_codec_ctx* data = ctx->context;
  if (!data || req->src_len > 0x7fffffffU || req->dst_len != zs_page_size)
    return -EINVAL;
  unsigned int length = req->dst_len;
  int rc;
  if (data->index == 0) {
    size_t size = ZSTD_decompressDCtx(data->codec.zstd.dctx, req->dst, length, req->src, req->src_len);
    rc = zs_zstd_is_error(size) ? -EINVAL : 0;
    length = rc ? length : size;
  } else if (data->index == 1) {
    rc = lz4_decompress(NULL, req->src, req->src_len, req->dst, &length);
  } else {
    rc = lz4kd_decompress(NULL, req->src, req->src_len, req->dst, &length);
  }
  return rc ? rc : length == req->dst_len ? 0 : -EINVAL;
}

static const struct zcomp_ops native_ops[] = {
    {zs_native_compress, zs_native_decompress, zs_native_create_zstd, zs_native_destroy, zs_native_setup_zstd,
     zs_native_release, ZS_ZSTD_NAME},
    {zs_native_compress, zs_native_decompress, zs_native_create_lz4, zs_native_destroy, zs_native_setup_lz4,
     zs_native_release, ZS_LZ4_NAME},
    {zs_native_compress, zs_native_decompress, zs_native_create_lz4kd, zs_native_destroy, zs_native_setup_lz4kd,
     zs_native_release, ZS_LZ4KD_NAME},
};

static struct zcomp* zs_native_create(unsigned int index, struct zcomp_params* params) {
  struct zcomp* comp = native_kmalloc(sizeof(*comp), native_gfp_zero);
  if (!comp)
    return (struct zcomp*)(long)-ENOMEM;
  comp->ops = &native_ops[index];
  comp->params = params;
  comp->stream = native_percpu_alloc(sizeof(struct zcomp_strm), 8, false, native_gfp);
  if (!comp->stream) {
    native_kfree(comp);
    return (struct zcomp*)(long)-ENOMEM;
  }
  int rc = zs_native_setup(index, params);
  if (!rc)
    rc = native_cpuhp_add(native_cpuhp_state, &comp->node, true);
  if (rc < 0) {
    /* Native add_instance unwinds already-started CPUs before returning an error. */
    zs_native_release_impl(params);
    native_percpu_free(comp->stream);
    native_kfree(comp);
    return (struct zcomp*)(long)rc;
  }
  return comp;
}

static void zs_native_available_before(hook_fargs1_t* args, void* udata) {
  if (!__atomic_load_n(&zs_native_ready, __ATOMIC_ACQUIRE))
    return;
  int index = zs_native_index((const char*)args->arg0);
  if (index < 0)
    return;
  args->ret = zs_codec_selectable(index);
  args->skip_origin = 1;
}

static void zs_native_create_before(hook_fargs2_t* args, void* udata) {
  if (!__atomic_load_n(&zs_native_ready, __ATOMIC_ACQUIRE))
    return;
  int index = zs_native_index((const char*)args->arg0);
  if (index < 0)
    return;
  args->ret = zs_codec_selectable(index) ? (uintptr_t)zs_native_create(index, (struct zcomp_params*)args->arg1)
                                         : (uintptr_t)(long)-EINVAL;
  args->skip_origin = 1;
}

#include "zs_native_btf.c"

/* Called only under module_mutex, after the zram text has been confirmed LIVE. */
static void zs_native_try_install(struct module* owner, void* show) {
  if (__atomic_load_n(&zs_native_ready, __ATOMIC_ACQUIRE))
    return;
  native_module_symbol = (typeof(native_module_symbol))kallsyms_lookup_name_by_suffix("module_kallsyms_lookup_name");
  if (!owner || !native_module_symbol)
    return;
  const char* marker_names[] = {"backend_lz4",   "backend_zstd",    "backend_lzorle", "backend_lzo",
                                "backend_lz4hc", "backend_deflate", "backend_842"};
  const struct zcomp_ops* marker = NULL;
  const char* marker_name = NULL;
  for (unsigned int i = 0; i < sizeof(marker_names) / sizeof(marker_names[0]); i++) {
    char qualified[64] = "zram:";
    size_t length = strlen(marker_names[i]);
    memcpy(qualified + 5, marker_names[i], length + 1);
    marker = (const struct zcomp_ops*)native_module_symbol(qualified);
    if (marker) {
      marker_name = marker_names[i];
      break;
    }
  }
  if (!marker)
    return;  // Legacy zram retains the existing Crypto/list path.
  __atomic_store_n(&zs_native_seen, true, __ATOMIC_RELEASE);
  void* create = (void*)native_module_symbol("zram:zcomp_create");
  void* available = (void*)native_module_symbol("zram:zcomp_available_algorithm");
  if (!create || !available || !zs_native_validate(owner, marker_name, marker)) {
    logkm("native zram contract unavailable; KPM backend names disabled\n");
    return;
  }
  if (display_module_text((unsigned long)create) != owner || display_module_text((unsigned long)available) != owner
      || display_module_text((unsigned long)show) != owner)
    return;
  if (owner && !native_module_get(owner))
    return;
  int rc = hook_wrap(create, 2, zs_native_create_before, NULL, NULL);
  if (!rc) {
    rc = hook_wrap(available, 1, zs_native_available_before, NULL, NULL);
    if (rc)
      hook_unwrap(create, zs_native_create_before, NULL);
  }
  if (rc) {
    if (owner)
      native_module_put(owner);
    logkm("native zram hook setup failed: %d\n", rc);
    return;
  }
  __atomic_store_n(&zs_native_ready, true, __ATOMIC_RELEASE);
  logkm("native zram enabled (page=%u); zram/KPM remain resident\n", zs_page_size);
}
