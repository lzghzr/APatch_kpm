/* SPDX-License-Identifier: GPL-2.0-or-later */

// 小对象先作无 reclaim 的 slab 尝试；失败与大对象保留可睡眠的 vzalloc 路径。
// 小对象按二次幂请求至少64字节；含128字节对齐代理头的请求会向上取整至512／1024。
static void* nm_zalloc(unsigned long size) {
  if (!size)
    return NULL;
  if (size <= 1024) {
    unsigned long span = 64;
    while (span < size) span <<= 1;
    void* allocation = kfunc(nm_kmalloc)(span, 0);
    if (allocation) {
      memset(allocation, 0, span);
      return allocation;
    }
  }
  return kfunc(nm_vzalloc)(size);
}

static void nm_free(const void* allocation) {
  if (allocation)
    kfunc(nm_kvfree)(allocation);
}

// RCU回调不承担同步拆除虚拟映射；原生队列在工作线程中释放vmalloc对象。
static void nm_free_rcu(const void* allocation) {
  if (!allocation)
    return;
  if (kfunc(nm_is_vmalloc_addr)(allocation))
    kfunc(nm_vfree_atomic)(allocation);
  else
    kfunc(nm_kfree)(allocation);
}
