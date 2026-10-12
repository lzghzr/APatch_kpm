#pragma once
#include <linux/compiler.h>
#include <linux/types.h>
#define ALIGN(x, a) (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#define PTR_ALIGN(ptr, a) ((__typeof__(ptr))ALIGN((uintptr_t)(ptr), a))
