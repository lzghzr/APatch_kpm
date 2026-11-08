/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Derived from Huawei Technologies Co., Ltd. 2022 LZ4KD ordinary encoder.
 * Source: ../upstream/lz4kd, e58761a19874b18c6534810212c66f3140435573.
 * Retains the hash, two-probe search and adaptive skip policy. Bounded indices,
 * exact output copies and the versioned 14/5/5 format support one 16 KiB window.
 */
#include "lz4kd16.h"

#include <linux/errno.h>
#include <linux/string.h>

#include "../upstream/lz4kd/lz4kd_private.h"
#include "../zs_lz4kd_config.h"

struct zs16_writer {
  uint8_t* data;
  unsigned int used;
};

static bool zs16_length(struct zs16_writer* out, unsigned int size) {
  do {
    if (out->used == ZS_LZ4KD16_BOUND)
      return false;
    out->data[out->used++] = size < 255 ? size : 255;
    if (size < 255)
      return true;
    size -= 255;
  } while (true);
}

static bool zs16_tuple(struct zs16_writer* out, const uint8_t* literal, unsigned int literals, unsigned int offset,
                       unsigned int repeat) {
  unsigned int r = repeat - 4;
  unsigned int tag = offset | ((r < 31 ? r : 31) << 14) | ((literals < 31 ? literals : 31) << 19);
  if (ZS_LZ4KD16_BOUND - out->used < 3)
    return false;
  out->data[out->used++] = tag;
  out->data[out->used++] = tag >> 8;
  out->data[out->used++] = tag >> 16;
  if (literals >= 31 && !zs16_length(out, literals - 31))
    return false;
  if (literals > ZS_LZ4KD16_BOUND - out->used)
    return false;
  memcpy(out->data + out->used, literal, literals);
  out->used += literals;
  return r < 31 || zs16_length(out, r - 31);
}

static unsigned int zs16_probe(struct zs_lz4kd16_ctx* ctx, const uint8_t* src, unsigned int at) {
  unsigned int slot = hash64_5b(src + at, 12);
  unsigned int previous = ctx->hash[slot];
  ctx->hash[slot] = at;
  return previous;
}

static unsigned int zs16_match(const uint8_t* src, unsigned int slen, unsigned int at, unsigned int previous) {
  unsigned int size = 4;
  while (slen - at - size >= 8) {
    uint64_t difference = read8_at(src + previous + size) ^ read8_at(src + at + size);
    if (difference)
      return size + (__builtin_ctzll(difference) >> 3);
    size += 8;
  }
  while (size < slen - at && src[previous + size] == src[at + size]) size++;
  return size;
}

static bool zs16_encode(struct zs_lz4kd16_ctx* ctx, const uint8_t* src, unsigned int slen, struct zs16_writer* out) {
  unsigned int at = 1, literal = 0;
  /* Hash probes read 8 bytes; retain upstream's 16-byte search-end margin. */
  unsigned int limit = slen - 16;
  memset(ctx->hash, 0, sizeof(ctx->hash));
  for (;;) {
    unsigned int previous, step = 32;
    for (;;) {
      previous = zs16_probe(ctx, src, at);
      if (equal4(src + previous, src + at))
        break;
      if (++at > limit)
        goto tail;
      previous = zs16_probe(ctx, src, at);
      if (equal4(src + previous, src + at))
        break;
      unsigned int advance = ++step >> 5;
      /* Check before adding: no pointer/index beyond the actual input object. */
      if (advance > limit - at)
        goto tail;
      at += advance;
    }
    unsigned int repeat = zs16_match(src, slen, at, previous);
    if (!zs16_tuple(out, src + literal, at - literal, at - previous, repeat))
      return false;
    at += repeat;
    literal = at;
    if (at > limit)
      break;
    ctx->hash[hash64_5b(src + at - 1, 12)] = at - 1;
  }
tail:
  return literal == slen || zs16_tuple(out, src + literal, slen - literal, 0, 4);
}

int zs_lz4kd16_compress(struct zs_lz4kd16_ctx* ctx, const uint8_t* src, unsigned int slen, uint8_t* dst,
                        unsigned int* dlen) {
  if (!slen || slen > ZS_LZ4KD16_BLOCK)
    return -EINVAL;
  struct zs16_writer out = {.data = ctx->scratch, .used = 1};
  out.data[0] = ZS_LZ4KD16_HEADER;
  if (slen < 32 || !zs16_encode(ctx, src, slen, &out) || out.used > slen) {
    out.used = 1;
    if (!zs16_tuple(&out, src, slen, 0, 4))
      return -EINVAL;
  }
  if (out.used > *dlen)
    return -EINVAL;
  memcpy(dst, out.data, out.used);
  *dlen = out.used;
  return 0;
}

static bool zs16_read_length(const uint8_t* src, unsigned int slen, unsigned int* pos, unsigned int* size) {
  unsigned int extra;
  do {
    if (*pos == slen)
      return false;
    extra = src[(*pos)++];
    if (extra > ZS_LZ4KD16_BLOCK - *size)
      return false;
    *size += extra;
  } while (extra == 255);
  return true;
}

int zs_lz4kd16_decompress(const uint8_t* src, unsigned int slen, uint8_t* dst, unsigned int* dlen) {
  if (slen < 5 || slen > ZS_LZ4KD16_BOUND || src[0] != ZS_LZ4KD16_HEADER)
    return -EINVAL;
  unsigned int pos = 1, written = 0;
  unsigned int capacity = *dlen < ZS_LZ4KD16_BLOCK ? *dlen : ZS_LZ4KD16_BLOCK;
  while (slen - pos >= 3) {
    unsigned int tag = src[pos] | ((unsigned int)src[pos + 1] << 8) | ((unsigned int)src[pos + 2] << 16);
    pos += 3;
    unsigned int offset = tag & 16383;
    unsigned int literal = tag >> 19;
    unsigned int repeat = ((tag >> 14) & 31) + 4;
    if (literal == 31 && !zs16_read_length(src, slen, &pos, &literal))
      return -EINVAL;
    if (literal > slen - pos || literal > capacity - written)
      return -EINVAL;
    memcpy(dst + written, src + pos, literal);
    pos += literal;
    written += literal;
    if (repeat == 35 && !zs16_read_length(src, slen, &pos, &repeat))
      return -EINVAL;
    if (!offset) {
      if (!literal || repeat != 4 || pos != slen)
        return -EINVAL;
      *dlen = written;
      return 0;
    }
    if (offset > written || repeat > capacity - written)
      return -EINVAL;
    unsigned int copied = 0;
    if (offset == 1) {
      memset(dst + written, dst[written - 1], repeat);
      copied = repeat;
    } else if (offset >= 8) {
      for (; repeat - copied >= 8; copied += 8) memcpy(dst + written + copied, dst + written + copied - offset, 8);
    }
    for (; copied < repeat; copied++) dst[written + copied] = dst[written + copied - offset];
    written += repeat;
  }
  if (pos != slen || !written)
    return -EINVAL;
  *dlen = written;
  return 0;
}
