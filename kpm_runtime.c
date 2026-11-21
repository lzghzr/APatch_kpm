/* SPDX-License-Identifier: GPL-2.0-or-later */
/* External memset for freestanding compiler-generated calls. Compile separately
 * from the SDK header that provides a source-level inline memset.
 */
#include <ksyms.h>
#include <ktypes.h>

extern void* kfunc_def(memset)(void* dest, int value, size_t size);

void* memset(void* dest, int value, size_t size) {
  if (kfunc(memset))
    return kfunc(memset)(dest, value, size);

  // Keep the fallback as byte stores even when the compiler recognizes clearing loops.
  volatile unsigned char* out = dest;
  while (size--)
    *out++ = (unsigned char)value;
  return dest;
}

#ifdef KPM_RUNTIME_COPY
// Modules that emit external copy calls can opt in to these two symbols.
extern void* kfunc_def(memcpy)(void* dest, const void* src, size_t n);
extern void* kfunc_def(memmove)(void* dest, const void* src, size_t n);

// 编译器生成的拷贝调用转接到 KP 的函数指针槽；槽未初始化时走本地
// 逐字节实现，避免首次调用经空指针跳转（加载期另有 -ENOENT 拒载，见 zram_zstd_init）。
void* memcpy(void* dest, const void* src, size_t n) {
  if (!kfunc(memcpy)) {
    unsigned char* out = (unsigned char*)dest;
    const unsigned char* in = (const unsigned char*)src;
    while (n--) *out++ = *in++;
    return dest;
  }
  return kfunc(memcpy)(dest, src, n);
}

void* memmove(void* dest, const void* src, size_t n) {
  if (!kfunc(memmove)) {
    unsigned char* out = (unsigned char*)dest;
    const unsigned char* in = (const unsigned char*)src;
    if ((uintptr_t)out <= (uintptr_t)in) {
      while (n--) *out++ = *in++;
    } else {
      out += n;
      in += n;
      while (n--) *--out = *--in;
    }
    return dest;
  }
  return kfunc(memmove)(dest, src, n);
}
#endif
