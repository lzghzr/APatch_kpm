/* SPDX-License-Identifier: GPL-2.0-only */
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/zstd.h>

#include "../kpm_utils.h"
#include "upstream/lz4/lz4.h"
#include "zs_structs.h"

KPM_NAME("zram_zstd");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_INFO(zstd_version, "1.5.7", 16);
KPM_INFO(lz4_version, LZ4_VERSION_STRING, 16);
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("ZSTD and LZ4 for zram. Embed for boot use; DO NOT UNLOAD.");
#ifdef CONFIG_KPM_BASELINES
KPM_INFO(offset_mode, "static", 16);
#else
KPM_INFO(offset_mode, "dynamic", 16);
#endif

#define logkm(fmt, ...) printk("zram_zstd: " fmt, ##__VA_ARGS__)
#define CRYPTO_ALG_TYPE_COMPRESS 2
#define CRYPTO_ALG_TYPE_MASK 15

struct zstd_ctx {
  ZSTD_CCtx* cctx;
  ZSTD_DCtx* dctx;
  void* cwksp;
  void* dwksp;
};

static unsigned char zstd_alg[1024] __attribute__((aligned(128)));
static unsigned char lz4_alg[1024] __attribute__((aligned(128)));
static bool registered;
static bool algorithm_registered[2];

#define ZS_ZSTD_NAME "zstd-kpm"
#define ZS_LZ4_NAME "lz4-kpm"

static int kfunc_def(crypto_has_alg)(const char* name, u32 type, u32 mask);
static int kfunc_def(crypto_register_alg)(void* alg);
static void* kfunc_def(vzalloc)(unsigned long size);
static void kfunc_def(vfree)(const void* ptr);

#include "zs_display.c"
#include "zs_offsets.c"

static struct zstd_ctx* zstd_context(struct crypto_tfm* tfm) {
  return (struct zstd_ctx*)((uintptr_t)tfm + struct_offset.crypto_tfm_ctx);
}

static void zstd_release(struct zstd_ctx* ctx) {
  if (ctx->cwksp)
    kfunc(vfree)(ctx->cwksp);
  if (ctx->dwksp)
    kfunc(vfree)(ctx->dwksp);
  ctx->cwksp = NULL;
  ctx->dwksp = NULL;
}

static int zstd_prepare(struct zstd_ctx* ctx) {
  size_t csize = ZSTD_estimateCCtxSize(3);
  size_t dsize = ZSTD_estimateDCtxSize();
  if (ZSTD_isError(csize) || ZSTD_isError(dsize))
    return -EINVAL;
  ctx->cwksp = kfunc(vzalloc)(csize);
  ctx->dwksp = kfunc(vzalloc)(dsize);
  if (!ctx->cwksp || !ctx->dwksp) {
    zstd_release(ctx);
    return -ENOMEM;
  }
  ctx->cctx = ZSTD_initStaticCCtx(ctx->cwksp, csize);
  ctx->dctx = ZSTD_initStaticDCtx(ctx->dwksp, dsize);
  if (!ctx->cctx || !ctx->dctx) {
    zstd_release(ctx);
    return -EINVAL;
  }
  return 0;
}

static int zstd_init(struct crypto_tfm* tfm) { return zstd_prepare(zstd_context(tfm)); }

static void zstd_exit(struct crypto_tfm* tfm) { zstd_release(zstd_context(tfm)); }

static int zstd_compress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  struct zstd_ctx* ctx = zstd_context(tfm);
  size_t size = ZSTD_compressCCtx(ctx->cctx, dst, *dlen, src, slen, 3);
  if (ZSTD_isError(size))
    return -EINVAL;
  *dlen = size;
  return 0;
}

static int zstd_decompress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  struct zstd_ctx* ctx = zstd_context(tfm);
  size_t size = ZSTD_decompressDCtx(ctx->dctx, dst, *dlen, src, slen);
  if (ZSTD_isError(size))
    return -EINVAL;
  *dlen = size;
  return 0;
}

static long codec_check(void) {
  struct zstd_ctx ctx = {0};
  int rc = zstd_prepare(&ctx);
  if (rc)
    return rc;
  unsigned char* pages = kfunc(vzalloc)(4096 * 4);
  if (!pages) {
    zstd_release(&ctx);
    return -ENOMEM;
  }
  for (unsigned int i = 0; i < 4096; i++) pages[i] = i % 251;
  size_t size = ZSTD_compressCCtx(ctx.cctx, pages + 4096, 8192, pages, 4096, 3);
  if (ZSTD_isError(size)) {
    rc = -EINVAL;
  } else {
    size_t decoded = ZSTD_decompressDCtx(ctx.dctx, pages + 12288, 4096, pages + 4096, size);
    if (decoded != 4096 || memcmp(pages, pages + 12288, 4096))
      rc = -EINVAL;
  }
  kfunc(vfree)(pages);
  zstd_release(&ctx);
  logkm("codec check=%d\n", rc);
  return rc;
}

// LZ4块间没有字典状态；仅压缩哈希表需要工作区，避免把约16 KiB放在内核栈上。
struct lz4_ctx {
  void* workspace;
};

static struct lz4_ctx* lz4_context(struct crypto_tfm* tfm) {
  return (struct lz4_ctx*)((uintptr_t)tfm + struct_offset.crypto_tfm_ctx);
}

static int lz4_init(struct crypto_tfm* tfm) {
  struct lz4_ctx* ctx = lz4_context(tfm);
  ctx->workspace = kfunc(vzalloc)(LZ4_sizeofState());
  return ctx->workspace ? 0 : -ENOMEM;
}

static void lz4_exit(struct crypto_tfm* tfm) {
  struct lz4_ctx* ctx = lz4_context(tfm);
  kfunc(vfree)(ctx->workspace);
  ctx->workspace = NULL;
}

static int lz4_compress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > LZ4_MAX_INPUT_SIZE || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_compress_fast_extState(lz4_context(tfm)->workspace, (const char*)src, (char*)dst, slen, *dlen, 1);
  if (!size)
    return -EINVAL;
  *dlen = size;
  return 0;
}

static int lz4_decompress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > 0x7fffffffU || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_decompress_safe((const char*)src, (char*)dst, slen, *dlen);
  if (size < 0)
    return -EINVAL;
  *dlen = size;
  return 0;
}

struct zs_algorithm {
  const char* name;
  unsigned char* storage;
  unsigned int ctxsize;
  int (*compress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
  int (*decompress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
  int (*init)(struct crypto_tfm*);
  void (*exit)(struct crypto_tfm*);
};

static const struct zs_algorithm algorithms[] = {
    {ZS_ZSTD_NAME, zstd_alg, sizeof(struct zstd_ctx), zstd_compress, zstd_decompress, zstd_init, zstd_exit},
    {ZS_LZ4_NAME, lz4_alg, sizeof(struct lz4_ctx), lz4_compress, lz4_decompress, lz4_init, lz4_exit},
};

static int prepare_algorithm(const struct zs_algorithm* codec) {
  size_t len = strlen(codec->name) + 1;
  int name_size = struct_offset.crypto_alg_driver_name - struct_offset.crypto_alg_name;
  if (len > name_size)
    return -EINVAL;
  unsigned char* storage = codec->storage;
  memset(storage, 0, sizeof(zstd_alg));
  struct zs_crypto_alg_prefix* alg = (struct zs_crypto_alg_prefix*)storage;
  alg->cra_flags = CRYPTO_ALG_TYPE_COMPRESS;
  alg->cra_ctxsize = codec->ctxsize;
  memcpy(storage + struct_offset.crypto_alg_name, codec->name, len);
  memcpy(storage + struct_offset.crypto_alg_driver_name, codec->name, len);
  struct zs_compress_alg* compress = (struct zs_compress_alg*)(storage + struct_offset.crypto_alg_compress);
  compress->coa_compress = codec->compress;
  compress->coa_decompress = codec->decompress;
  struct zs_alg_lifecycle* lifecycle = (struct zs_alg_lifecycle*)(storage + struct_offset.crypto_alg_init);
  lifecycle->cra_init = codec->init;
  lifecycle->cra_exit = codec->exit;
  // cra_module保持NULL；KPM不属于原生LKM，成功注册后必须常驻。
  return 0;
}

static long zram_zstd_init(const char* args, const char* event, void* reserved) {
  if (event && !strcmp(event, "pre-kernel-init")) {
    logkm("use post-kernel-init\n");
    return -EINVAL;
  }
  kfunc_lookup_name(crypto_has_alg);
  if (!kfunc(crypto_has_alg))
    return -ENOENT;
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    if (kfunc(crypto_has_alg)(algorithms[i].name, CRYPTO_ALG_TYPE_COMPRESS, CRYPTO_ALG_TYPE_MASK)) {
      logkm("%s already available; skip loading\n", algorithms[i].name);
      return -EEXIST;
    }
  }
  kfunc_lookup_name(crypto_register_alg);
  kfunc_lookup_name(vzalloc);
  kfunc_lookup_name(vfree);
  if (!kfunc(crypto_register_alg) || !kfunc(vzalloc) || !kfunc(vfree))
    return -ENOENT;
  long rc = calculate_offsets();
  if (rc)
    return rc;
  rc = codec_check();
  if (rc)
    return rc;
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    rc = prepare_algorithm(&algorithms[i]);
    if (rc)
      return rc;
  }
  // 首项失败时尚未公开资源，可以拒载；一旦注册成功，模块必须常驻。
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    rc = kfunc(crypto_register_alg)(algorithms[i].storage);
    if (rc) {
      logkm("registration failed for %s: %ld\n", algorithms[i].name, rc);
      if (!registered)
        return rc;
      continue;
    }
    algorithm_registered[i] = true;
    registered = true;
  }
  // 注册即公开callback。旧Crypto API注销不会等待活跃transform，不能用回滚释放KPM。
  // 后续算法注册失败时保持关闭，显示层只发布真正可选的名字。
  start_zram_display();
  logkm("registration: %s=%d (ZSTD 1.5.7), %s=%d (LZ4 " LZ4_VERSION_STRING "). DO NOT UNLOAD\n", ZS_ZSTD_NAME,
        algorithm_registered[0], ZS_LZ4_NAME, algorithm_registered[1]);
  return 0;
}

static long zram_zstd_ctl0(const char* args, char __user* out_msg, int outlen) {
  static const char reply[] = "_(._.)_";
  if (!out_msg || outlen < (int)sizeof(reply))
    return -EINVAL;
  return compat_copy_to_user(out_msg, reply, sizeof(reply)) == sizeof(reply) ? 0 : -EFAULT;
}

static long zram_zstd_exit(void* reserved) {
  if (registered)
    logkm("DO NOT UNLOAD: zram may retain codec callbacks\n");
  return 0;
}

KPM_INIT(zram_zstd_init);
KPM_CTL0(zram_zstd_ctl0);
KPM_EXIT(zram_zstd_exit);
