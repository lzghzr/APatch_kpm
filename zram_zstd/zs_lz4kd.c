/* SPDX-License-Identifier: GPL-2.0-only */
// LZ4KD 2022.03.20 普通 4 KiB block 适配；格式依据 upstream/lz4kd。
#define ZS_LZ4KD_BLOCK 4096U
#define ZS_LZ4KD_SCRATCH 8192U

int zs_lz4kd_decode(const void* in, void* out, unsigned int in_max, unsigned int out_max);

struct lz4kd_ctx {
  void* workspace;
  u8* scratch;
};

static struct lz4kd_ctx* lz4kd_context(struct crypto_tfm* tfm) {
  return (struct lz4kd_ctx*)((uintptr_t)tfm + struct_offset.crypto_tfm_ctx);
}

static int lz4kd_prepare(struct lz4kd_ctx* ctx) {
  unsigned int size = lz4kd_encode_state_bytes_min();
  ctx->workspace = kfunc(vzalloc)(size + ZS_LZ4KD_SCRATCH);
  ctx->scratch = ctx->workspace ? (u8*)ctx->workspace + size : NULL;
  return ctx->workspace ? 0 : -ENOMEM;
}

static void lz4kd_release(struct lz4kd_ctx* ctx) {
  kfunc(vfree)(ctx->workspace);
  ctx->workspace = NULL;
  ctx->scratch = NULL;
}

// 正规 literal-only block：header=0，offset=0，repeat=4，literal 长度占 tag 高 6 位。
static unsigned int lz4kd_literals(const u8* src, unsigned int slen, u8* dst) {
  unsigned int literal = slen < 63 ? slen : 63;
  unsigned int pos = 4;
  dst[0] = dst[1] = dst[2] = 0;
  dst[3] = literal << 2;
  if (slen >= 63) {
    unsigned int remaining = slen - 63;
    while (remaining >= 255) {
      dst[pos++] = 255;
      remaining -= 255;
    }
    dst[pos++] = remaining;
  }
  memcpy(dst + pos, src, slen);
  return pos + slen;
}

static int lz4kd_encode_block(struct lz4kd_ctx* ctx, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (!slen || slen > ZS_LZ4KD_BLOCK)
    return -EINVAL;
  int size = 0;
  u8* encoded = *dlen >= ZS_LZ4KD_SCRATCH ? dst : ctx->scratch;
  // 足够大的真实输出缓冲直接编码；小容量调用仍经 scratch 保留失败不写的契约。
  // 上游入口没有保护短输入；快速 tuple 也会越过逻辑 out_limit 做宽写。
  // 保守上界：4096 literal + 3075 tag + 158 长度扩展 + 16 header/宽写余量 < 8192。
  if (slen >= 32)
    size = lz4kd_encode(ctx->workspace, src, encoded, slen, ZS_LZ4KD_SCRATCH, 0);
  if (size <= 0)
    size = lz4kd_literals(src, slen, encoded);
  if ((unsigned int)size > *dlen)
    return -EINVAL;
  if (encoded != dst)
    memcpy(dst, encoded, size);
  *dlen = size;
  return 0;
}

static int lz4kd_init(struct crypto_tfm* tfm) { return lz4kd_prepare(lz4kd_context(tfm)); }
static void lz4kd_exit(struct crypto_tfm* tfm) { lz4kd_release(lz4kd_context(tfm)); }
static int lz4kd_compress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  return lz4kd_encode_block(lz4kd_context(tfm), src, slen, dst, dlen);
}

// 复用上游优化核心；普通块入口在独立翻译单元局部适配，不按长度识别 pattern。
static int lz4kd_decompress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  unsigned int capacity = *dlen < ZS_LZ4KD_BLOCK ? *dlen : ZS_LZ4KD_BLOCK;
  int size = zs_lz4kd_decode(src, dst, slen, capacity);
  if (size <= 0)
    return -EINVAL;
  *dlen = size;
  return 0;
}
