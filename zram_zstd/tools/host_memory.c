/* SPDX-License-Identifier: GPL-2.0-only */
/* Host bindings for the exact production KP-pointer memory adapter. */
#include <string.h>

void* (*kf_memcpy)(void* dest, const void* src, size_t n) = memcpy;
void* (*kf_memmove)(void* dest, const void* src, size_t n) = memmove;
void* (*kf_memset)(void* dest, int value, size_t n) = memset;
