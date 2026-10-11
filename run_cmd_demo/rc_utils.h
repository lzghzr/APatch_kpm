#ifndef __RC_UTILS_H
#define __RC_UTILS_H

// 模块私有 IRQ 锁，持锁区仅复制命令或读写状态。
static inline unsigned long run_cmd_lock(unsigned int* lock) {
  unsigned long flags;
  asm volatile("mrs %0, daif\n\tmsr daifset, #2" : "=r"(flags) : : "memory");
  while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) asm volatile("yield" : : : "memory");
  return flags;
}
static inline void run_cmd_unlock(unsigned int* lock, unsigned long flags) {
  __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
  asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

#endif /* __RC_UTILS_H */
