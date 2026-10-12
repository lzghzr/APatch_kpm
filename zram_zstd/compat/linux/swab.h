#pragma once
#define swab32(x) __builtin_bswap32(x)
#define swab64(x) __builtin_bswap64(x)
