/* SPDX-License-Identifier: GPL-2.0-only */
/* Execute the unchanged 4 KiB production wrapper with host allocation/context adapters. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../upstream/lz4kd/lz4kd.h"
#include "../zs_lz4kd_config.h"

struct crypto_tfm;
static const struct {
  unsigned int crypto_tfm_ctx;
} struct_offset = {0};
static void* vzalloc(unsigned long size) { return calloc(1, size); }
static void vfree(const void* pointer) { free((void*)pointer); }
#define kfunc(name) name
#include "../zs_lz4kd.c"
#undef kfunc

/* Experimental chunk container: c1, count=4, four LE16 lengths, then four ordinary blocks. */
static unsigned int zs16_chunk_compress(struct lz4kd_ctx* ctx, const uint8_t* src, uint8_t* dst) {
  unsigned int used = 10;
  dst[0] = 0xc1;
  dst[1] = 4;
  for (unsigned int i = 0; i < 4; i++) {
    unsigned int size = 8192;
    if (lz4kd_compress((void*)ctx, src + i * 4096, 4096, dst + used, &size))
      return 0;
    dst[2 + i * 2] = size;
    dst[3 + i * 2] = size >> 8;
    used += size;
  }
  return used;
}

static unsigned int zs16_chunk_decompress(const uint8_t* src, unsigned int slen, uint8_t* dst) {
  if (slen < 10 || src[0] != 0xc1 || src[1] != 4)
    return 0;
  unsigned int pos = 10;
  for (unsigned int i = 0; i < 4; i++) {
    unsigned int size = src[2 + i * 2] | (src[3 + i * 2] << 8), output = 4096;
    if (size > slen - pos || lz4kd_decompress(NULL, src + pos, size, dst + i * 4096, &output) || output != 4096)
      return 0;
    pos += size;
  }
  return pos == slen ? 16384 : 0;
}
