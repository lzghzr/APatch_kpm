#pragma once
#include <linux/types.h>
static inline u64 div_u64(u64 value, u32 divisor) { return value / divisor; }
