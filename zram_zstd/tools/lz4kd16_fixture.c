/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <limits.h>
#include <stdio.h>

#include "../experimental/lz4kd16.h"
#include "lz4kd16_legacy_fixture.h"

static uint32_t random_state = 0xd2ab71e5;
static uint32_t next_random(void) {
  random_state ^= random_state << 13;
  random_state ^= random_state >> 17;
  random_state ^= random_state << 5;
  return random_state;
}

/* Hand-built streams exercise the wire format independently of the encoder. */
static unsigned int wire_length(uint8_t* out, unsigned int size) {
  unsigned int pos = 0;
  while (size >= 255) {
    out[pos++] = 255;
    size -= 255;
  }
  out[pos++] = size;
  return pos;
}

static void golden_tests(void) {
  const uint8_t literal[] = {0x10, 0, 0, 32, 't', 'e', 's', 't'};
  const uint8_t repeat[] = {0x10, 3, 0x80, 0x18, 'a', 'b', 'c'};
  uint8_t output[16384], input[ZS_LZ4KD16_BOUND];
  unsigned int size = sizeof(output);
  assert(!zs_lz4kd16_decompress(literal, sizeof(literal), output, &size));
  assert(size == 4 && !memcmp(output, "test", 4));
  size = sizeof(output);
  assert(!zs_lz4kd16_decompress(repeat, sizeof(repeat), output, &size));
  assert(size == 9 && !memcmp(output, "abcabcabc", 9));
  const unsigned int offsets[] = {1, 2, 3, 7, 8, 31, 32, 4095, 4096, 4097, 8191, 8192, 8193, 12288, 16380};
  for (unsigned int i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
    unsigned int distance = offsets[i], pos = 4;
    unsigned int tag = distance | ((distance < 31 ? distance : 31) << 19);
    input[0] = ZS_LZ4KD16_HEADER;
    input[1] = tag;
    input[2] = tag >> 8;
    input[3] = tag >> 16;
    if (distance >= 31)
      pos += wire_length(input + pos, distance - 31);
    for (unsigned int j = 0; j < distance; j++) input[pos + j] = j % 251;
    size = sizeof(output);
    assert(!zs_lz4kd16_decompress(input, pos + distance, output, &size) && size == distance + 4);
    for (unsigned int j = 0; j < size; j++) assert(output[j] == (j < distance ? j : j % distance) % 251);
  }
  /* Max field distance cannot fit even one four-byte repeat in a 16 KiB output. */
  unsigned int tag = 16383 | (31U << 19), pos = 4;
  input[0] = ZS_LZ4KD16_HEADER;
  input[1] = tag;
  input[2] = tag >> 8;
  input[3] = tag >> 16;
  pos += wire_length(input + pos, 16383 - 31);
  memset(input + pos, 'x', 16383);
  size = sizeof(output);
  assert(zs_lz4kd16_decompress(input, pos + 16383, output, &size) == -EINVAL && size == sizeof(output));
  const uint8_t bad[][5] = {{0, 0, 0, 8, 'x'},  {0x11, 0, 0, 8, 'x'},   {0x10, 0, 0, 0, 0},
                            {0x10, 1, 0, 0, 0}, {0x10, 0, 0, 248, 255}, {0x10, 0, 0x40, 8, 'x'}};
  for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    size = sizeof(output);
    assert(zs_lz4kd16_decompress(bad[i], sizeof(bad[i]), output, &size) == -EINVAL && size == sizeof(output));
  }
  struct lz4kd_ctx old = {0};
  assert(!lz4kd_init((void*)&old));
  size = sizeof(output);
  assert(lz4kd_decompress((void*)&old, literal, sizeof(literal), output, &size) == -EINVAL);
  const uint8_t old_literal[] = {0, 0, 0, 16, 't', 'e', 's', 't'};
  size = sizeof(output);
  assert(zs_lz4kd16_decompress(old_literal, sizeof(old_literal), output, &size) == -EINVAL);
  lz4kd_exit((void*)&old);
}

static void roundtrip_tests(struct zs_lz4kd16_ctx* first, struct zs_lz4kd16_ctx* second) {
  unsigned int blocks = 0;
  for (unsigned int n = 1; n <= ZS_LZ4KD16_BLOCK; n++) {
    uint8_t *input = malloc(n), *output = malloc(n), *packed = malloc(ZS_LZ4KD16_BOUND);
    uint8_t* exact = malloc(ZS_LZ4KD16_BOUND);
    assert(input && output && packed && exact);
    for (unsigned int pattern = 0; pattern < 4; pattern++) {
      for (unsigned int i = 0; i < n; i++)
        input[i] = pattern == 0 ? 0 : pattern == 1 ? i % 7 : pattern == 2 ? next_random() : (i / 31 + i % 3);
      unsigned int length = ZS_LZ4KD16_BOUND, size = n;
      assert(!zs_lz4kd16_compress(first, input, n, packed, &length));
      assert(length <= n + 4 + (n < 31 ? 0 : (n - 31) / 255 + 1));
      assert(!zs_lz4kd16_decompress(packed, length, output, &size));
      assert(size == n && !memcmp(input, output, n));
      unsigned int capacity = length;
      assert(!zs_lz4kd16_compress(second, input, n, exact, &capacity));
      assert(capacity == length && !memcmp(exact, packed, length));
      memset(exact, 0xa5, ZS_LZ4KD16_BOUND);
      capacity = length - 1;
      assert(zs_lz4kd16_compress(first, input, n, exact, &capacity) == -EINVAL && capacity == length - 1);
      for (unsigned int i = 0; i < ZS_LZ4KD16_BOUND; i++) assert(exact[i] == 0xa5);
      /* An allocation of exactly the advertised capacity catches decoder over-writes. */
      uint8_t* short_output = malloc(n > 1 ? n - 1 : 1);
      assert(short_output);
      capacity = n - 1;
      assert(zs_lz4kd16_decompress(packed, length, short_output, &capacity) == -EINVAL && capacity == n - 1);
      free(short_output);
      blocks++;
    }
    free(input);
    free(output);
    free(packed);
    free(exact);
  }
  printf("PASS: %u blocks, every size 1..16384, four patterns, independent contexts, exact/short capacities\n", blocks);
}

static void malformed_tests(struct zs_lz4kd16_ctx* ctx) {
  uint8_t full[16384], packed[ZS_LZ4KD16_BOUND];
  for (unsigned int i = 0; i < sizeof(full); i++) full[i] = next_random();
  unsigned int length = sizeof(packed);
  assert(!zs_lz4kd16_compress(ctx, full, sizeof(full), packed, &length));
  /* Truncate every prefix of a literal-only maximum-size block. */
  assert(length == ZS_LZ4KD16_BOUND);
  for (unsigned int n = 0; n < length; n++) {
    uint8_t *input = malloc(n ? n : 1), *output = malloc(16384);
    assert(input && output);
    memcpy(input, packed, n);
    unsigned int size = 16384;
    assert(zs_lz4kd16_decompress(input, n, output, &size) == -EINVAL && size == 16384);
    free(input);
    free(output);
  }
  for (unsigned int i = 0; i < 60000; i++) {
    unsigned int len = next_random() % (i < 50000 ? 128 : ZS_LZ4KD16_BOUND + 1);
    unsigned int capacity = next_random() % (ZS_LZ4KD16_BLOCK + 1);
    uint8_t *input = malloc(len ? len : 1), *output = malloc(capacity ? capacity : 1);
    assert(input && output);
    for (unsigned int j = 0; j < len; j++) input[j] = next_random();
    if (len)
      input[0] = ZS_LZ4KD16_HEADER;
    unsigned int size = capacity;
    int rc = zs_lz4kd16_decompress(input, len, output, &size);
    assert(rc == 0 || rc == -EINVAL);
    assert(rc ? size == capacity : size <= capacity);
    free(input);
    free(output);
  }
  /* Extension chain must stop at the block output bound, not integer wraparound. */
  memset(packed, 255, sizeof(packed));
  packed[0] = ZS_LZ4KD16_HEADER;
  packed[1] = packed[2] = 0;
  packed[3] = 248;
  unsigned int size = sizeof(full);
  assert(zs_lz4kd16_decompress(packed, sizeof(packed), full, &size) == -EINVAL && size == sizeof(full));
  assert(zs_lz4kd16_decompress(packed, UINT_MAX, full, &size) == -EINVAL && size == sizeof(full));
  assert(zs_lz4kd16_compress(ctx, full, 0, packed, &size) == -EINVAL && size == sizeof(full));
  assert(zs_lz4kd16_compress(ctx, full, 16385, packed, &size) == -EINVAL && size == sizeof(full));
  assert(zs_lz4kd16_compress(ctx, full, UINT_MAX, packed, &size) == -EINVAL && size == sizeof(full));
  printf("PASS: %u truncated prefixes, 60000 malformed streams, long extensions, invalid input sizes\n", length);
}

int main(void) {
  struct zs_lz4kd16_ctx *first = malloc(sizeof(*first)), *second = malloc(sizeof(*second));
  assert(first && second && first != second);
  golden_tests();
  roundtrip_tests(first, second);
  malformed_tests(first);
  free(first);
  free(second);
  puts("PASS: 15 distance vectors through 16380, field overflow, old/new header isolation");
  return 0;
}
