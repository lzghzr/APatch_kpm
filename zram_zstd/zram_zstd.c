/* SPDX-License-Identifier: GPL-2.0-only */
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/zstd.h>

#include "../kpm_utils.h"
#include "zs_structs.h"

KPM_NAME("zram_zstd");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("ZSTD for zram. Embed for boot use; DO NOT UNLOAD.");
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
static bool registered;

static int kfunc_def(crypto_has_alg)(const char* name, u32 type, u32 mask);
static int kfunc_def(crypto_register_alg)(void* alg);
static void* kfunc_def(vzalloc)(unsigned long size);
static void kfunc_def(vfree)(const void* ptr);

#include "zs_offsets.c"
#include "zs_display.c"

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

static long zram_zstd_init(const char* args, const char* event, void* reserved) {
  if (event && !strcmp(event, "pre-kernel-init")) {
    logkm("use post-kernel-init\n");
    return -EINVAL;
  }
  kfunc_lookup_name(crypto_has_alg);
  if (!kfunc(crypto_has_alg))
    return -ENOENT;
  if (kfunc(crypto_has_alg)("zstd-kpm", CRYPTO_ALG_TYPE_COMPRESS, CRYPTO_ALG_TYPE_MASK)) {
    logkm("zstd-kpm already available; skip loading\n");
    return -EEXIST;
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
  struct zs_crypto_alg_prefix* alg = (struct zs_crypto_alg_prefix*)zstd_alg;
  alg->cra_flags = CRYPTO_ALG_TYPE_COMPRESS;
  alg->cra_ctxsize = sizeof(struct zstd_ctx);
  memcpy(zstd_alg + struct_offset.crypto_alg_name, "zstd-kpm", sizeof("zstd-kpm"));
  memcpy(zstd_alg + struct_offset.crypto_alg_driver_name, "zstd-kpm", sizeof("zstd-kpm"));
  struct zs_compress_alg* compress = (struct zs_compress_alg*)(zstd_alg + struct_offset.crypto_alg_compress);
  compress->coa_compress = zstd_compress;
  compress->coa_decompress = zstd_decompress;
  struct zs_alg_lifecycle* lifecycle = (struct zs_alg_lifecycle*)(zstd_alg + struct_offset.crypto_alg_init);
  lifecycle->cra_init = zstd_init;
  lifecycle->cra_exit = zstd_exit;
  // cra_module 保持 NULL，KPM 不属于原生 LKM；算法使用期间模块必须常驻。
  rc = kfunc(crypto_register_alg)(zstd_alg);
  if (rc)
    return rc;
  registered = true;
  start_zram_display();
  logkm("registered zstd-kpm 1.5.7; select zstd-kpm before zram initialization. DO NOT UNLOAD\n");
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
