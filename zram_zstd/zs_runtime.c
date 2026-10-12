#include <ksyms.h>
#include <ktypes.h>

extern void* kfunc_def(memcpy)(void* dest, const void* src, size_t n);
extern void* kfunc_def(memmove)(void* dest, const void* src, size_t n);
extern void* kfunc_def(memset)(void* dest, int value, size_t n);

void* memcpy(void* dest, const void* src, size_t n) { return kfunc(memcpy)(dest, src, n); }
void* memmove(void* dest, const void* src, size_t n) { return kfunc(memmove)(dest, src, n); }
void* memset(void* dest, int value, size_t n) { return kfunc(memset)(dest, value, n); }
