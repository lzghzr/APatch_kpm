/* SPDX-License-Identifier: GPL-2.0-only */
/* Host bindings for the exact production KP-pointer memory adapter. */
#include <string.h>

void* (*kf_memcpy)(void* dest, const void* src, size_t n) = memcpy;
void* (*kf_memmove)(void* dest, const void* src, size_t n) = memmove;
void* (*kf_memset)(void* dest, int value, size_t n) = memset;
int (*kf_memcmp)(const void*, const void*, size_t) = memcmp;
void* (*kf_memchr)(const void*, int, size_t) = memchr;
