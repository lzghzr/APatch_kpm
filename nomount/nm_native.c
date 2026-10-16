/* SPDX-License-Identifier: GPL-2.0-or-later */

// 使用模块自己的绑定，避免同名 SDK 包装改变原生接口的语义。
static void kfunc_def(nm_read_lock)(void);
static void kfunc_def(nm_read_unlock)(void);
static void kfunc_def(nm_synchronize_rcu)(void);
static void kfunc_def(nm_call_rcu)(struct rcu_head*, rcu_callback_t);
static void kfunc_def(nm_kfree)(const void*);
static void* kfunc_def(nm_kmalloc)(unsigned long, unsigned int);
static void kfunc_def(nm_kvfree)(const void*);
static bool kfunc_def(nm_is_vmalloc_addr)(const void*);
static void kfunc_def(nm_vfree_atomic)(const void*);
static void* kfunc_def(nm_vzalloc)(unsigned long);
static bool kfunc_def(nm_capable)(int);
static void* kfunc_def(nm_memdup_user)(const void __user*, size_t);
static int64_t kfunc_def(nm_vfs_setpos)(void*, int64_t, int64_t);
static int kfunc_def(nm_iterate_dir)(void*, struct nm_dir_context*);

static uintptr_t nm_vmalloc_range[2];
static bool nm_vmalloc_address(const void* address) {
  uintptr_t value = (uintptr_t)address;
  return value >= nm_vmalloc_range[0] && value <= nm_vmalloc_range[1];
}

#define NM_NATIVE_LOOKUP(local, symbol)                                         \
  kfunc(local) = (typeof(kfunc(local)))kallsyms_lookup_name_by_suffix(#symbol); \
  if (!kfunc(local)) {                                                          \
    nm_log_error("missing native function %s\n", #symbol);                      \
    return -ENOENT;                                                             \
  }

static int nm_prepare_native(void) {
  NM_NATIVE_LOOKUP(nm_read_lock, __rcu_read_lock);
  NM_NATIVE_LOOKUP(nm_read_unlock, __rcu_read_unlock);
  NM_NATIVE_LOOKUP(nm_synchronize_rcu, synchronize_rcu);
  NM_NATIVE_LOOKUP(nm_call_rcu, call_rcu);
  NM_NATIVE_LOOKUP(nm_kfree, kfree);
  NM_NATIVE_LOOKUP(nm_kmalloc, __kmalloc);
  NM_NATIVE_LOOKUP(nm_kvfree, kvfree);
  kfunc(nm_is_vmalloc_addr) = (typeof(kfunc(nm_is_vmalloc_addr)))kallsyms_lookup_name_by_suffix("is_vmalloc_addr");
  if (!kfunc(nm_is_vmalloc_addr)) {
    int rc = nm_find_vmalloc_range((const void*)kfunc(nm_kvfree), kallsyms_lookup_name_by_suffix("vfree"),
                                   (uintptr_t)kfunc(nm_kfree), nm_vmalloc_range);
    if (rc) {
      nm_log_error("vmalloc address classification unavailable: %d\n", rc);
      return rc;
    }
    kfunc(nm_is_vmalloc_addr) = nm_vmalloc_address;
  }
  NM_NATIVE_LOOKUP(nm_vfree_atomic, vfree_atomic);
  NM_NATIVE_LOOKUP(nm_vzalloc, vzalloc);
  NM_NATIVE_LOOKUP(nm_capable, capable);
  NM_NATIVE_LOOKUP(nm_memdup_user, memdup_user);
  NM_NATIVE_LOOKUP(nm_vfs_setpos, vfs_setpos);
  NM_NATIVE_LOOKUP(nm_iterate_dir, iterate_dir);
  return 0;
}

#undef NM_NATIVE_LOOKUP

#include "nm_memory.c"

static void nm_rcu_read_lock(void) { kfunc(nm_read_lock)(); }
static void nm_rcu_read_unlock(void) { kfunc(nm_read_unlock)(); }
static void nm_rcu_synchronize(void) { kfunc(nm_synchronize_rcu)(); }

static void nm_rcu_call(struct rcu_head* head, rcu_callback_t callback) { kfunc(nm_call_rcu)(head, callback); }

// 上游 children/rule/UID 数组均将 rcu_head 放在分配对象的开头。
static void nm_rcu_free_head(struct rcu_head* head) { kfunc(nm_kfree)(head); }

static void nm_rcu_free(struct rcu_head* allocation) { nm_rcu_call(allocation, nm_rcu_free_head); }

// backing inode 与外层虚拟 inode 不同，必须走原生的权限检查和目录锁。
static int nm_iterate_backing(void* outer_file, void* backing_file, struct nm_dir_context* ctx) {
  if (!outer_file || !backing_file || !ctx)
    return -EINVAL;
  if (nm_file_inode(outer_file) == nm_file_inode(backing_file))
    return -ELOOP;
  int64_t position = kfunc(nm_vfs_setpos)(backing_file, ctx->pos, 0x7fffffffffffffffLL);
  if (position < 0)
    return position;
  return kfunc(nm_iterate_dir)(backing_file, ctx);
}

// 同一 inode 已由外层 iterate_dir 上锁，调用保存的原回调，避免重入。
static int nm_iterate_original(void* file, struct nm_dir_context* ctx, int (*original)(void*, struct nm_dir_context*)) {
  return original ? original(file, ctx) : -ENOTDIR;
}

// preparse 收到的是 add_key 已拷入内核的 32/64 位地址载荷。
static int nm_exchange_payload(const void* data, size_t length, int (*execute)(struct nm_payload*)) {
  if (!kfunc(nm_capable)(21))  // CAP_SYS_ADMIN
    return -EPERM;
  if (!data || !execute || (length != 4 && length != 8))
    return -EINVAL;
  u64 address = 0;
  if (length == 4) {
    u32 compat_address;
    memcpy(&compat_address, data, sizeof(compat_address));
    address = compat_address;
  } else {
    memcpy(&address, data, sizeof(address));
  }
  if (!address)
    return -EINVAL;
  struct nm_payload* payload = kfunc(nm_memdup_user)((const void __user*)(uintptr_t)address, sizeof(*payload));
  if (IS_ERR(payload))
    return PTR_ERR(payload);
  if (!payload)
    return -ENOMEM;
  int rc = -EFAULT;
  if (payload->magic != NOMOUNT_MAGIC_SIG)
    goto out;
  payload->status = 0;
  rc = execute(payload);
  if (rc && !payload->status)
    payload->status = rc;
  rc = compat_copy_to_user((void __user*)(uintptr_t)address, payload, sizeof(*payload)) == sizeof(*payload) ? -ECANCELED
                                                                                                            : -EFAULT;
out:
  kfunc(nm_kfree)(payload);
  return rc;
}
