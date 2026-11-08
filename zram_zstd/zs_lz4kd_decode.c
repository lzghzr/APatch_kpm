/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * Description: LZ4K compression algorithm with delta compression
 * KPM adaptation: ordinary-block entry and overlap-safe fixed-width copies.
 * Source: upstream/lz4kd/lz4kd_decode.c (see upstream/lz4kd/README.md).
 */

#include "upstream/lz4kd/lz4kd.h"
#include "zs_lz4kd_private.h"

static const uint8_t *get_size(
	uint_fast32_t *size,
	const uint8_t *in_at,
	const uint8_t *const in_end)
{
	uint_fast32_t u;
	do {
		if (unlikely(in_at >= in_end))
			return NULL;
		*size += (u = *(const uint8_t*)in_at);
		++in_at;
	} while (BYTE_MAX == u);
	return in_at;
}

static int end_of_block(
	const uint_fast32_t nr_bytes_max,
	const uint_fast32_t r_bytes_max,
	const uint8_t *const in_at,
	const uint8_t *const in_end,
	const uint8_t *const out,
	const uint8_t *const out_at)
{
	if (!nr_bytes_max)
		return LZ4K_STATUS_FAILED; /* should be the last one in block */
	if (r_bytes_max != REPEAT_MIN)
		return LZ4K_STATUS_FAILED; /* should be the last one in block */
	if (in_at != in_end)
		return LZ4K_STATUS_FAILED; /* should be the last one in block */
	return (int)(out_at - out);
}

enum {
	NR_COPY_MIN = 16,
	R_COPY_MIN = 16,
	R_COPY_SAFE = R_COPY_MIN - 1,
	R_COPY_SAFE_2X = (R_COPY_MIN << 1) - 1
};

static bool out_non_repeat(
	const uint8_t **in_at,
	uint8_t **out_at,
	uint_fast32_t nr_bytes_max,
	const uint8_t *const in_end,
	const uint8_t *const out_end)
{
	const uint8_t *const in_copy_end = *in_at + nr_bytes_max;
	uint8_t *const out_copy_end = *out_at + nr_bytes_max;
	if (likely(nr_bytes_max <= NR_COPY_MIN)) {
		if (likely(*in_at <= in_end - NR_COPY_MIN &&
			   *out_at <= out_end - NR_COPY_MIN))
			m_copy(*out_at, *in_at, NR_COPY_MIN);
		else if (in_copy_end <= in_end && out_copy_end <= out_end)
			m_copy(*out_at, *in_at, nr_bytes_max);
		else
			return false;
	} else { /* nr_bytes_max>NR_COPY_MIN */
		if (likely(in_copy_end <= in_end - NR_COPY_MIN &&
			   out_copy_end <= out_end - NR_COPY_MIN)) {
			m_copy(*out_at, *in_at, NR_COPY_MIN);
			copy_x_while_lt(*out_at + NR_COPY_MIN,
					*in_at + NR_COPY_MIN,
					out_copy_end, NR_COPY_MIN);
		} else if (in_copy_end <= in_end && out_copy_end <= out_end) {
			m_copy(*out_at, *in_at, nr_bytes_max);
		} else { /* in_copy_end > in_end || out_copy_end > out_end */
			return false;
		}
	} /* if (nr_bytes_max <= NR_COPY_MIN) */
	*in_at = in_copy_end;
	*out_at = out_copy_end;
	return true;
}

static void out_repeat_overlap(
	uint_fast32_t offset,
	uint8_t *out_at,
	const uint8_t *out_from,
	const uint8_t *const out_copy_end)
{
	enum {
		COPY_MIN = R_COPY_MIN >> 1,
		OFFSET_LIMIT = COPY_MIN >> 1
	};
	/* Snapshot copy: offset can be smaller than the fixed copy width. */
	__builtin_memmove(out_at, out_from, COPY_MIN);
/* (1 < offset < R_COPY_MIN/2) && out_copy_end + R_COPY_SAFE_2X  <= out_end */
	out_at += offset;
	if (offset <= OFFSET_LIMIT)
		offset <<= 1;
	do {
		__builtin_memmove(out_at, out_from, COPY_MIN);
		out_at += offset;
		if (offset <= OFFSET_LIMIT)
			offset <<= 1;
	} while (out_at - out_from < R_COPY_MIN);
	while_lt_copy_2x_as_x2(out_at, out_from, out_copy_end, R_COPY_MIN);
}

static bool out_repeat_slow(
	uint_fast32_t r_bytes_max,
	uint_fast32_t offset,
	uint8_t *out_at,
	const uint8_t *out_from,
	const uint8_t *const out_copy_end,
	const uint8_t *const out_end)
{
	if (offset > 1 && out_copy_end <= out_end - R_COPY_SAFE_2X) {
		out_repeat_overlap(offset, out_at, out_from, out_copy_end);
	} else {
		if (unlikely(out_copy_end > out_end))
			return false;
		if (offset == 1) {
			m_set(out_at, *out_from, r_bytes_max);
		} else {
			do
				*out_at++ = *out_from++;
			while (out_at < out_copy_end);
		}
	}
	return true;
}

static int decode(
	const uint8_t *in_at,
	uint8_t *const out,
	const uint8_t *const in_end,
	const uint8_t *const out_end,
	const uint_fast32_t nr_log2,
	const uint_fast32_t off_log2)
{
	const uint_fast32_t r_log2 = TAG_BITS_MAX - (off_log2 + nr_log2);
	const uint8_t *const in_end_minus_x = in_end - TAG_BYTES_MAX;
	uint8_t *out_at = out;
	while (likely(in_at <= in_end_minus_x)) {
		const uint_fast32_t utag = read4_at(in_at - 1) >> BYTE_BITS;
		const uint_fast32_t offset = utag & mask(off_log2);
		uint_fast32_t nr_bytes_max = utag >> (off_log2 + r_log2),
			      r_bytes_max = ((utag >> off_log2) & mask(r_log2)) +
					    REPEAT_MIN;
		const uint8_t *out_from = 0;
		uint8_t *out_copy_end = 0;
		const uint8_t *out_safe_end = 0;
		in_at += TAG_BYTES_MAX;
		if (unlikely(nr_bytes_max == mask(nr_log2))) {
			in_at = get_size(&nr_bytes_max, in_at, in_end);
			if (unlikely(in_at == NULL))
				return LZ4K_STATUS_READ_ERROR;
		}
		if (!out_non_repeat(&in_at, &out_at, nr_bytes_max, in_end, out_end))
			return LZ4K_STATUS_FAILED;
		if (unlikely(r_bytes_max == mask(r_log2) + REPEAT_MIN)) {
			in_at = get_size(&r_bytes_max, in_at, in_end);
			if (unlikely(in_at == NULL))
				return LZ4K_STATUS_READ_ERROR;
		}
		out_from = out_at - offset;
		if (unlikely(out_from < out))
			return LZ4K_STATUS_FAILED;
		out_copy_end = out_at + r_bytes_max;
		out_safe_end = out_end - R_COPY_SAFE_2X;
		if (likely(offset >= R_COPY_MIN && out_copy_end <= out_safe_end)) {
			copy_2x_as_x2_while_lt(out_at, out_from, out_copy_end,
					       R_COPY_MIN);
		} else if (likely(offset >= (R_COPY_MIN >> 1) &&
				  out_copy_end <= out_safe_end)) {
			__builtin_memmove(out_at, out_from, R_COPY_MIN);
			out_at += offset;
			while_lt_copy_x(out_at, out_from, out_copy_end, R_COPY_MIN);
		} else if (likely(offset > 0)) {
			if (!out_repeat_slow(r_bytes_max, offset, out_at, out_from,
			     out_copy_end, out_end))
				return LZ4K_STATUS_FAILED;
		} else { /* offset == 0: EOB, last literal */
			return end_of_block(nr_bytes_max, r_bytes_max, in_at,
					    in_end, out, out_at);
		}
		out_at = out_copy_end;
	} /* while (likely(in_at <= in_end_minus_x)) */
	return in_at == in_end ? (int)(out_at - out) : LZ4K_STATUS_FAILED;
}

static int decode_4kb(
	const uint8_t *const in,
	uint8_t *const out,
	const uint8_t *const in_end,
	const uint8_t *const out_end)
{
	return decode(in, out, in_end, out_end, NR_4KB_LOG2, BLOCK_4KB_LOG2);
}

int zs_lz4kd_decode(
	const void *in,
	void *const out,
	unsigned in_max,
	unsigned out_max)
{
	/* ++use volatile pointers to prevent compiler optimizations */
	const uint8_t *volatile in_end = (const uint8_t*)in + in_max;
	const uint8_t *volatile out_end = (uint8_t*)out + min_u64(out_max, 1 << BLOCK_4KB_LOG2);
	if (unlikely(in == NULL || out == NULL))
		return LZ4K_STATUS_FAILED;
	if (unlikely(in_max <= 1 + TAG_BYTES_MAX || in_max > 8192 || out_max <= 0))
		return LZ4K_STATUS_FAILED;
	/* invalid buffer size or pointer overflow */
	if (unlikely((const uint8_t*)in >= in_end || (uint8_t*)out >= out_end))
		return LZ4K_STATUS_FAILED;
	/* -- */
	/* Ordinary 8-byte blocks are not the upstream pattern extension. */
	if (unlikely(*(const uint8_t*)in != 0))
		return LZ4K_STATUS_FAILED;
	return decode_4kb((const uint8_t*)in + 1, (uint8_t*)out, in_end, out_end);
}
