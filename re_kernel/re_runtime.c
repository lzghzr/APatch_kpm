#include <ksyms.h>
#include <ktypes.h>

extern void* kfunc_def(memset)(void* dest, int c, size_t n);

// 编译器生成的清零调用也走 KernelPatch 导出的函数指针。
void* memset(void* dest, int c, size_t n) { return kfunc(memset)(dest, c, n); }
