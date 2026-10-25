/* SPDX-License-Identifier: GPL-2.0-only */
/* Materialization and eviction adapted from the pinned NoMount implementation. */
struct kstat;
struct dentry;

struct nm_inode_engine {
  void* file_ops;
  void* inode_ops;
  void* symlink_ops;
  void (*release_directory)(struct inode*);
  const void* directory_ops;
  void (*put_directory_node)(void*);
  struct dentry* (*materialize_directory)(struct inode*, struct dentry*, struct nomount_rule*, void*, u64);
  struct dentry* (*lookup_backing)(struct inode*, struct dentry*, unsigned int);
  int (*revalidate_backing)(struct inode*, struct inode*, const struct nm_qstr*);
  int (*iterate_backing)(struct file*, struct nm_dir_context*, void*);
  int64_t (*seek_backing)(struct file*, int64_t, int);
  struct nomount_rule* (*inherit_directory)(struct inode*, struct dentry*);
  int (*check_directory_search)(struct inode*);
};
static struct nm_inode_engine nm_inode_engine;

// 调用者的规则引用保护复制；inode仅保留独立path及类型，不持有管理规则。
static void nm_bind_inode_path(struct nm_inode_info* info, const struct nomount_rule* rule) {
  info->r_path = rule->r_path;
  info->flags = rule->flags;
  info->inherited_child = rule->inherited_child;
  if (info->r_path.dentry)
    kfunc(nm_path_get)(&info->r_path);
}

// 仅在进程上下文释放引用，RCU回调只释放info内存。
static void nm_put_inode_binding(struct nm_inode_info* info) {
  if (info->r_path.dentry)
    kfunc(nm_path_put)(&info->r_path);
  if (info->dir_node && nm_inode_engine.put_directory_node)
    nm_inode_engine.put_directory_node(info->dir_node);
}

// 调用者持有path引用及inode生命周期；info读取另受原生RCU保护。
static bool nm_inode_matches_binding(struct inode* inode, const struct nm_path* path, void* node, u16 flags,
                                     u32 secid) {
  const struct nm_inode_info* info = nm_inode_private(inode);
  if (!info || info->dir_node != node || info->flags != flags || info->r_path.mnt != path->mnt
      || info->r_path.dentry != path->dentry || info->secid != secid)
    return false;
  // iget的test可在新inode初始化前运行；匹配后原生iget等待unlock_new_inode。
  if (!__atomic_load_n(&info->initialized, __ATOMIC_ACQUIRE))
    return true;
  if (info->init_error)
    return false;
  if (!path->dentry)
    return true;
  // 从调用者保活的path读取，避免evict释放info的path后解引用退役来源。
  const struct nm_inode_owner_prefix* real = (void*)nm_dentry_inode(path->dentry);
  const struct nm_inode_owner_prefix* owner = (void*)inode;
  return real && owner->i_mode == real->i_mode && owner->i_uid == real->i_uid && owner->i_gid == real->i_gid;
}

// 完整原生表放在 64 字节对齐的私有头部后；公开后驻留，原始表保持不动。
struct nm_super_proxy {
  const void* original;
  unsigned char table[] __attribute__((aligned(64)));
};

static struct inode* kfunc_def(nm_new_inode)(struct super_block*);
static void kfunc_def(nm_iput)(struct inode*);
static struct dentry* kfunc_def(nm_d_splice_alias)(struct inode*, struct dentry*);
static void kfunc_def(nm_truncate_inode_pages_final)(void*);
static void kfunc_def(nm_clear_inode)(struct inode*);
static int kfunc_def(nm_vfs_getattr_nosec)(const struct nm_path*, struct kstat*, u32, unsigned int);
static int (*nm_vfs_getattr_pair)(const struct nm_path*, struct kstat*);
static const char* kfunc_def(nm_vfs_get_link)(struct dentry*, struct delayed_call*);
static uintptr_t nm_plain_link_callbacks[10];
static int kfunc_def(nm_generic_readlink)(struct dentry*, char*, int);
static int kfunc_def(nm_security_inode_readlink)(struct dentry*);
static bool nm_legacy_links;
static int nm_link_read_slot = -1, nm_link_put_slot = -1;
static int nm_link_source_read_slot = -1;
static bool nm_link_default_readlink;
static uintptr_t nm_link_code_start, nm_link_code_end;
struct nm_follow_pair {
  uintptr_t follow, put;
};
static struct nm_follow_pair nm_follow_pairs[3];

static int nm_prepare_inode_functions(void) {
  kfunc(nm_new_inode) = (typeof(kfunc(nm_new_inode)))kallsyms_lookup_name_by_suffix("new_inode");
  kfunc(nm_iput) = (typeof(kfunc(nm_iput)))kallsyms_lookup_name_by_suffix("iput");
  kfunc(nm_d_splice_alias) = (typeof(kfunc(nm_d_splice_alias)))kallsyms_lookup_name_by_suffix("d_splice_alias");
  kfunc(nm_truncate_inode_pages_final) =
      (typeof(kfunc(nm_truncate_inode_pages_final)))kallsyms_lookup_name_by_suffix("truncate_inode_pages_final");
  kfunc(nm_clear_inode) = (typeof(kfunc(nm_clear_inode)))kallsyms_lookup_name_by_suffix("clear_inode");
  kfunc(nm_vfs_getattr_nosec) =
      (typeof(kfunc(nm_vfs_getattr_nosec)))kallsyms_lookup_name_by_suffix("vfs_getattr_nosec");
  nm_vfs_getattr_pair = struct_offset.getattr_function_args == 2 ? (void*)kfunc(nm_vfs_getattr_nosec) : NULL;
  return kfunc(nm_new_inode) && kfunc(nm_iput) && kfunc(nm_d_splice_alias) && kfunc(nm_truncate_inode_pages_final)
                 && kfunc(nm_clear_inode) && kfunc(nm_vfs_getattr_nosec)
             ? nm_prepare_security_functions()
             : -ENOENT;
}

static bool nm_is_file_inode(struct inode* inode) {
  return nm_inode_engine.inode_ops && nm_inode_ops(inode) == nm_inode_engine.inode_ops;
}
static bool nm_is_directory_inode(struct inode* inode) {
  return nm_inode_engine.directory_ops && nm_inode_ops(inode) == nm_inode_engine.directory_ops;
}
static bool nm_is_symlink_inode(struct inode* inode) {
  return nm_inode_engine.symlink_ops && nm_inode_ops(inode) == nm_inode_engine.symlink_ops;
}
static bool nm_is_virtual_inode(struct inode* inode) {
  return nm_is_file_inode(inode) || nm_is_directory_inode(inode) || nm_is_symlink_inode(inode);
}

#include "nm_setattr.c"

static bool nm_link_callback_matches(uintptr_t value, uintptr_t target) {
  uintptr_t start = nm_link_code_start, end = nm_link_code_end;
  if (!target)
    return false;
  if (value == target)
    return true;
  if (!start || end <= start || end - start < 4 || value < start || value > end - 4 || value % 4)
    return false;
  uint32_t inst = *(const uint32_t*)value;
  if (inst_is_bti_c(inst)) {
    if (end - value < 8)
      return false;
    value += 4;
    inst = *(const uint32_t*)value;
  }
  return inst_is_b(inst) && value + inst_get_b_label(inst) == target;
}

static int nm_follow_pair_index(struct inode* inode) {
  if (!inode || nm_link_put_slot < 0)
    return -1;
  const struct nm_inode_follow_prefix* ops = nm_inode_ops(inode);
  if (!ops)
    return -1;
  uintptr_t follow = (uintptr_t)ops->follow_link;
  uintptr_t put = (uintptr_t)nm_operation_callback(ops, nm_link_put_slot);
  for (unsigned int i = 0; i < sizeof(nm_follow_pairs) / sizeof(nm_follow_pairs[0]); i++)
    if (nm_follow_pairs[i].follow && follow == nm_follow_pairs[i].follow && put == nm_follow_pairs[i].put)
      return i;
  return -1;
}

// 只接受已核对的字符串回调及旧清理配对，在调用前拒绝 magic-link。
static bool nm_plain_symlink_source(struct inode* inode) {
  if (!inode || (nm_inode_mode(inode) & 0170000) != 0120000)
    return false;
  if (nm_link_source_read_slot < 0)
    return false;
  uintptr_t read = (uintptr_t)nm_operation_callback(nm_inode_ops(inode), nm_link_source_read_slot);
  if (read ? !nm_link_callback_matches(read, (uintptr_t)kfunc(nm_generic_readlink)) : !nm_link_default_readlink)
    return false;
  if (nm_legacy_links)
    return nm_follow_pair_index(inode) >= 0;
  uintptr_t callback =
      (uintptr_t)nm_operation_callback(nm_inode_ops(inode), offsetof(struct nm_inode_link_ops, get_link));
  for (unsigned int i = 0; i < sizeof(nm_plain_link_callbacks) / sizeof(nm_plain_link_callbacks[0]); i++)
    if (callback && nm_link_callback_matches(callback, nm_plain_link_callbacks[i]))
      return true;
  return false;
}

static const char* nm_symlink_follow_link(struct dentry* dentry, void** cookie) {
  if (!dentry)
    return ERR_PTR(-ECHILD);
  if (!cookie)
    return ERR_PTR(-EIO);
  *cookie = NULL;
  struct inode* inode = nm_dentry_inode(dentry);
  struct nm_inode_info* info = inode && nm_is_symlink_inode(inode) ? nm_inode_private(inode) : NULL;
  if (!info || !info->r_path.dentry || !kfunc(nm_security_inode_readlink))
    return ERR_PTR(-EIO);
  struct inode* backing = nm_dentry_inode(info->r_path.dentry);
  int pair = nm_follow_pair_index(backing);
  if (!nm_legacy_links || pair < 0 || !nm_plain_symlink_source(backing)
      || (uintptr_t)info->link_put != nm_follow_pairs[pair].put)
    return ERR_PTR(-EOPNOTSUPP);
  int rc = kfunc(nm_security_inode_readlink)(info->r_path.dentry);
  if (rc)
    return ERR_PTR(rc);
  const struct nm_inode_follow_prefix* ops = nm_inode_ops(backing);
  const char* link = ops->follow_link(info->r_path.dentry, cookie);
  // 原生错误路径自行回收；不让调用者对错误时残留的cookie再清理一次。
  if (IS_ERR(link))
    *cookie = NULL;
  return link;
}

static void nm_symlink_put_link(struct inode* inode, void* cookie) {
  if (!cookie)
    return;
  struct nm_inode_info* info = nm_inode_private(inode);
  // 原生VFS先put_link再path_put，info及其独立源path在清理期间仍有效。
  if (info && info->link_put)
    info->link_put(nm_dentry_inode(info->r_path.dentry), cookie);
}

static int nm_symlink_readlink(struct dentry* dentry, char* buffer, int length) {
  struct inode* inode = dentry ? nm_dentry_inode(dentry) : NULL;
  if (!inode || !nm_is_symlink_inode(inode) || !kfunc(nm_generic_readlink))
    return -EIO;
  // 始终用外层空i_link进入本模块follow/get回调；不调源readlink的未知回调。
  return kfunc(nm_generic_readlink)(dentry, buffer, length);
}

static const char* nm_symlink_get_link(struct dentry* dentry, struct inode* inode, struct delayed_call* done) {
  // RCU walk 不解引用私有绑定，也不进入可能睡眠的源安全钩子。
  if (!dentry)
    return ERR_PTR(-ECHILD);
  if (!inode || nm_dentry_inode(dentry) != inode || !nm_is_symlink_inode(inode) || !done)
    return ERR_PTR(-EIO);
  struct nm_inode_info* info = nm_inode_private(inode);
  if (!info || !info->r_path.dentry || !kfunc(nm_vfs_get_link))
    return ERR_PTR(-EIO);
  if (!nm_plain_symlink_source(nm_dentry_inode(info->r_path.dentry)))
    return ERR_PTR(-EOPNOTSUPP);
  // VFS 在释放外层路径之前执行 done；info 的独立源 path 覆盖返回字符串的使用期。
  // 保留当前凭据，原生 helper 核对源 security_inode_readlink；不改写返回的相对路径。
  return kfunc(nm_vfs_get_link)(info->r_path.dentry, done);
}

static int nm_getattr_from_backing(struct inode* inode, const struct nm_path* backing, struct kstat* stat, u32 mask,
                                   unsigned int flags) {
  int rc = nm_vfs_getattr_pair ? nm_vfs_getattr_pair(backing, stat)
                               : kfunc(nm_vfs_getattr_nosec)(backing, stat, mask, flags);
  if (!rc)
    nm_set_stat_identity(stat, nm_inode_number(inode), ((struct nm_super_head*)nm_inode_superblock(inode))->s_dev);
  return rc;
}

static int nm_file_getattr(const struct nm_path* path, struct kstat* stat, u32 mask, unsigned int flags) {
  struct inode* inode = nm_dentry_inode(path->dentry);
  struct nm_inode_info* info =
      inode && (nm_is_file_inode(inode) || nm_is_symlink_inode(inode)) ? nm_inode_private(inode) : NULL;
  return info && info->r_path.dentry ? nm_getattr_from_backing(inode, &info->r_path, stat, mask, flags) : -EIO;
}

static int nm_file_getattr_mount(struct vfsmount* mount, struct dentry* dentry, struct kstat* stat) {
  const struct nm_path path = {mount, dentry};
  return nm_file_getattr(&path, stat, 0, 0);
}

static int nm_file_getattr_userns(struct user_namespace* userns, const struct nm_path* path, struct kstat* stat,
                                  u32 mask, unsigned int flags) {
  return nm_file_getattr(path, stat, mask, flags);
}
static int nm_file_getattr_idmap(struct mnt_idmap* idmap, const struct nm_path* path, struct kstat* stat, u32 mask,
                                 unsigned int flags) {
  return nm_file_getattr(path, stat, mask, flags);
}
static void* nm_file_getattr_callback(void) {
  if (struct_offset.getattr_context_kind == 1)
    return nm_file_getattr_userns;
  if (struct_offset.getattr_context_kind == 2)
    return nm_file_getattr_idmap;
  return struct_offset.getattr_callback_args == 3 ? (void*)nm_file_getattr_mount : (void*)nm_file_getattr;
}

// 联合核对已取得的ABI与getattr锚点；静态模式不扫描操作表取偏移。
static int nm_prepare_link_prefix(bool legacy) {
  if (legacy) {
    if (struct_offset.permission_abi != 0
        || struct_offset.iop_getattr != offsetof(struct nm_inode_follow_prefix, getattr))
      return -EOPNOTSUPP;
    nm_link_source_read_slot = offsetof(struct nm_inode_follow_prefix, readlink);
    nm_link_put_slot = offsetof(struct nm_inode_follow_prefix, put_link);
  } else if (struct_offset.permission_abi == 0) {
    if (struct_offset.iop_getattr != offsetof(struct nm_inode_android_link_prefix, getattr))
      return -EOPNOTSUPP;
    nm_link_source_read_slot = offsetof(struct nm_inode_android_link_prefix, readlink);
  } else if (struct_offset.permission_abi >= 1 && struct_offset.permission_abi <= 3) {
    if (struct_offset.iop_getattr != offsetof(struct nm_inode_plain_link_prefix, getattr))
      return -EOPNOTSUPP;
    nm_link_source_read_slot = offsetof(struct nm_inode_plain_link_prefix, readlink);
  } else {
    return -EOPNOTSUPP;
  }
  return 0;
}

// 新能力的缺失不改变原普通文件／目录入口；readlink槽仅用于generic_readlink接口。
static int nm_new_symlink_operations(void** result) {
  *result = NULL;
  kfunc(nm_vfs_get_link) = (typeof(kfunc(nm_vfs_get_link)))kallsyms_lookup_name_by_suffix("vfs_get_link");
  memset(nm_plain_link_callbacks, 0, sizeof(nm_plain_link_callbacks));
  memset(nm_follow_pairs, 0, sizeof(nm_follow_pairs));
  nm_legacy_links = !kfunc(nm_vfs_get_link);
  nm_link_read_slot = nm_link_put_slot = nm_link_source_read_slot = -1;
  kfunc(nm_generic_readlink) = (typeof(kfunc(nm_generic_readlink)))kallsyms_lookup_name_by_suffix("generic_readlink");
  bool generic = !kallsyms_lookup_name_by_suffix("vfs_readlink");
  nm_link_default_readlink = !generic && !nm_legacy_links;
  if ((generic || nm_legacy_links) && !kfunc(nm_generic_readlink))
    return 0;
#ifndef CONFIG_KPM_BASELINES
  bool unavailable = false;
  int rc = generic || nm_legacy_links ? calculate_btf_link_compat(nm_legacy_links, &unavailable)
                                      : calculate_btf_symlink(&unavailable);
  if (rc && !(rc == -ENODATA && unavailable))
    return rc;
#endif
  const char* names[] = {"simple_get_link",         "simple_get_link.cfi_jt",
                         "page_get_link",           "page_get_link.cfi_jt",
                         "f2fs_get_link",           "f2fs_get_link.cfi_jt",
                         "ext4_encrypted_get_link", "ext4_encrypted_get_link.cfi_jt",
                         "f2fs_encrypted_get_link", "f2fs_encrypted_get_link.cfi_jt"};
  bool found = false;
  for (unsigned int i = 0; !nm_legacy_links && i < sizeof(names) / sizeof(names[0]); i++) {
    nm_plain_link_callbacks[i] = kallsyms_lookup_name_by_suffix(names[i]);
    found |= nm_plain_link_callbacks[i] != 0;
  }
  if (nm_legacy_links) {
    kfunc(nm_security_inode_readlink) =
        (typeof(kfunc(nm_security_inode_readlink)))kallsyms_lookup_name_by_suffix("security_inode_readlink");
    if (!kfunc(nm_security_inode_readlink))
      return 0;
    const char* follow[] = {"simple_follow_link", "page_follow_link_light", "ext4_encrypted_follow_link"};
    const char* put[] = {NULL, "page_put_link", "kfree_put_link"};
    for (unsigned int i = 0; i < 3; i++) {
      nm_follow_pairs[i].follow = kallsyms_lookup_name_by_suffix(follow[i]);
      nm_follow_pairs[i].put = put[i] ? kallsyms_lookup_name_by_suffix(put[i]) : 0;
      if (put[i] && !nm_follow_pairs[i].put)
        nm_follow_pairs[i].follow = 0;
      found |= nm_follow_pairs[i].follow != 0;
    }
  }
  if (!found)
    return 0;
  int size = nm_owned_operation_size(NM_INODE_OPS);
  if (size < 0 || size < sizeof(struct nm_inode_link_ops) || struct_offset.iop_getattr < 0
      || struct_offset.iop_getattr < sizeof(struct nm_inode_link_ops) || struct_offset.iop_getattr + 8 > size)
    return -EINVAL;
  int prefix = nm_prepare_link_prefix(nm_legacy_links);
  if (prefix)
    return prefix;
#ifndef CONFIG_KPM_BASELINES
  unavailable = false;
  prefix = calculate_btf_source_readlink(nm_link_source_read_slot, &unavailable);
  if (prefix && !(prefix == -ENODATA && unavailable))
    return prefix;
#endif
  if (generic || nm_legacy_links)
    nm_link_read_slot = nm_link_source_read_slot;
  nm_link_code_start = kallsyms_lookup_name_by_suffix("_stext");
  nm_link_code_end = kallsyms_lookup_name_by_suffix("_etext");
  uintptr_t end = kallsyms_lookup_name_by_suffix("_end");
  if (!end)
    end = kallsyms_lookup_name_by_suffix("__end_rodata");
  if (!nm_link_code_start || nm_link_code_end <= nm_link_code_start || nm_link_code_end > end)
    nm_link_code_end = kallsyms_lookup_name_by_suffix("__start_rodata");
  if (!nm_link_code_start || nm_link_code_end <= nm_link_code_start || nm_link_code_end > end)
    nm_link_code_start = nm_link_code_end = 0;  // 仍可精确匹配具名入口，禁止读未知跳板。
  void* table = nm_new_operations(NM_INODE_OPS, NULL);
  if (IS_ERR(table))
    return PTR_ERR(table);
  if (nm_legacy_links) {
    nm_set_operation_callback(table, offsetof(struct nm_inode_follow_prefix, follow_link), nm_symlink_follow_link);
    nm_set_operation_callback(table, nm_link_put_slot, nm_symlink_put_link);
  } else {
    nm_set_operation_callback(table, offsetof(struct nm_inode_link_ops, get_link), nm_symlink_get_link);
  }
  if (nm_link_read_slot >= 0)
    nm_set_operation_callback(table, nm_link_read_slot, nm_symlink_readlink);
  nm_set_operation_callback(table, struct_offset.iop_getattr, nm_file_getattr_callback());
  int setter = nm_install_setattr(table);
  if (setter) {
    nm_discard_operations(table);
    return setter;
  }
  *result = table;
  return 0;
}

static int nm_proxy_drop_inode(struct inode* inode);
static void nm_proxy_evict_inode(struct inode* inode);

static const struct nm_super_proxy* nm_super_proxy(const void* table) {
  // 只有这两处模块回调同时匹配，才按模块私有头部解释；普通原生表不向前读取。
  if (nm_operation_callback(table, struct_offset.sop_drop_inode) != nm_proxy_drop_inode
      || nm_operation_callback(table, struct_offset.sop_evict_inode) != nm_proxy_evict_inode)
    return NULL;
  return (const void*)((uintptr_t)table - offsetof(struct nm_super_proxy, table));
}

static int nm_proxy_drop_inode(struct inode* inode) {
  if (nm_is_virtual_inode(inode))
    return 1;
  const struct nm_super_proxy* proxy = nm_super_proxy(nm_super_ops(nm_inode_superblock(inode)));
  int (*original)(struct inode*) = proxy ? nm_operation_callback(proxy->original, struct_offset.sop_drop_inode) : NULL;
  return original ? original(inode) : !nm_inode_nlink(inode) || nm_inode_unhashed(inode);
}

static void nm_inode_info_rcu_free(struct rcu_head* head) {
  struct nm_inode_info* info = (void*)((uintptr_t)head - offsetof(struct nm_inode_info, rcu));
  nm_free_rcu(info);
}

static void nm_proxy_evict_inode(struct inode* inode) {
  bool virtual = nm_is_virtual_inode(inode);
  const struct nm_super_proxy* proxy = nm_super_proxy(nm_super_ops(nm_inode_superblock(inode)));
  void (*original)(struct inode*) =
      proxy ? nm_operation_callback(proxy->original, struct_offset.sop_evict_inode) : NULL;
  if (!virtual && nm_inode_engine.release_directory)
    nm_inode_engine.release_directory(inode);
  if (!virtual && original) {
    original(inode);
    return;
  }
  struct nm_inode_info* info = virtual ? nm_inode_private(inode) : NULL;
  if (virtual) {
    nm_set_inode_private(inode, NULL);
    // 回收开始时结束借用关系；后续原生销毁阶段不再依赖 backing 的生命周期。
    nm_reset_inode_mapping(inode);
  }
  // i_mapping 指向 backing；只清理本 inode 的嵌入映射。原生 VFS 负责 I_FREEING 和后续 destroy/free。
  kfunc(nm_truncate_inode_pages_final)(nm_inode_data(inode));
  kfunc(nm_clear_inode)(inode);
  if (info) {
    // evict 是进程上下文；路径释放不能搬进 RCU 回调。
    nm_put_inode_binding(info);
    nm_rcu_call(&info->rcu, nm_inode_info_rcu_free);
  }
}

// 调用者持有管理锁与 sb 的路径引用。复制全部原生回调，只替换 drop/evict。
static int nm_install_super_proxy(struct super_block* sb) {
  struct struct_offset offsets = struct_offset;
  int rc = nm_validate_inode_offsets(&offsets);
  if (rc || !nm_inode_engine.inode_ops)
    return rc ? rc : -ENODEV;
  const void* original = nm_super_ops(sb);
  if (!original)
    return -EINVAL;
  if (nm_super_proxy(original))
    return 0;
  struct nm_super_proxy* proxy = nm_zalloc(offsetof(struct nm_super_proxy, table) + offsets.super_ops_size);
  if (!proxy)
    return -ENOMEM;
  proxy->original = original;
  memcpy(proxy->table, original, offsets.super_ops_size);
  nm_set_operation_callback(proxy->table, offsets.sop_drop_inode, nm_proxy_drop_inode);
  nm_set_operation_callback(proxy->table, offsets.sop_evict_inode, nm_proxy_evict_inode);
  if (!nm_publish_super_ops(sb, &original, proxy->table)) {
    nm_free(proxy);  // CAS 失败：该表从未发布。
    return -EAGAIN;
  }
  return 0;
}

// 调用者持有规则引用，inode另取path引用；原生d_splice_alias消耗inode引用。
// 普通文件与普通链接共用路径、LSM及失败回收；链接保留自身映射与原生初始化的空 i_link。
static struct dentry* nm_materialize_backed_inode(struct inode* parent, struct dentry* dentry,
                                                  struct nomount_rule* rule, u64 number, bool symlink) {
  if (!rule || !rule->r_path.dentry || rule->flags & (NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT))
    return ERR_PTR(-EOPNOTSUPP);
  struct inode* backing = nm_dentry_inode(rule->r_path.dentry);
  if (!backing
      || (symlink ? !nm_inode_engine.symlink_ops || !nm_plain_symlink_source(backing)
                  : (nm_inode_mode(backing) & 0170000) != 0100000))
    return ERR_PTR(-EOPNOTSUPP);
  void (*link_put)(struct inode*, void*) = NULL;
  if (symlink && nm_legacy_links) {
    int pair = nm_follow_pair_index(backing);
    if (pair < 0)
      return ERR_PTR(-EOPNOTSUPP);
    link_put = (void*)nm_follow_pairs[pair].put;
  }
  struct super_block* sb = nm_inode_superblock(parent);
  if (!nm_inode_engine.file_ops || !nm_inode_engine.inode_ops || !nm_super_proxy(nm_super_ops(sb)))
    return ERR_PTR(-ENODEV);
  struct nm_security_context context;
  int rc = nm_get_security_context(backing, &context);
  if (rc)
    return ERR_PTR(rc);
  struct nm_inode_info* info = nm_zalloc(sizeof(*info));
  if (!info) {
    nm_release_security_context(&context);
    return ERR_PTR(-ENOMEM);
  }
  struct inode* inode = kfunc(nm_new_inode)(sb);
  if (!inode) {
    nm_free(info);
    nm_release_security_context(&context);
    return ERR_PTR(-ENOMEM);
  }
  nm_bind_inode_path(info, rule);
  info->link_put = link_put;
  info->secid = context.secid;
  if (symlink) {
    nm_copy_backing_inode_attributes(inode, backing, number);
    ((struct nm_inode_owner_prefix*)inode)->i_opflags &= ~0x0004U;  // IOP_NOFOLLOW 不适用于链接。
    nm_publish_inode_ops(inode, nm_inode_engine.symlink_ops, NULL);
    nm_set_inode_private(inode, info);
  } else {
    nm_initialize_file_inode(inode, backing, number, info, nm_inode_engine.inode_ops, nm_inode_engine.file_ops);
  }
  rc = nm_initialize_inode_security(inode, &context);
  nm_release_security_context(&context);
  if (rc) {
    kfunc(nm_iput)(inode);  // 原生evict释放独立path/info与LSM分配。
    return ERR_PTR(rc);
  }
  __atomic_store_n(&info->initialized, true, __ATOMIC_RELEASE);
  return kfunc(nm_d_splice_alias)(inode, dentry);
}

static struct dentry* nm_materialize_file(struct inode* parent, struct dentry* dentry, struct nomount_rule* rule,
                                          u64 number) {
  return nm_materialize_backed_inode(parent, dentry, rule, number, false);
}

static struct dentry* nm_materialize_symlink(struct inode* parent, struct dentry* dentry, struct nomount_rule* rule,
                                             u64 number) {
  return nm_materialize_backed_inode(parent, dentry, rule, number, true);
}

static int nm_prepare_inode_engine(void) {
  if (nm_inode_engine.inode_ops)
    return -EALREADY;
  int rc = nm_prepare_inode_layout();
  if (!rc)
    rc = nm_prepare_inode_functions();
  if (!rc)
    rc = nm_prepare_setattr();
  if (rc)
    return rc;
  void* file_ops = nm_new_file_operations();
  if (IS_ERR(file_ops))
    return PTR_ERR(file_ops);
  void* inode_ops = nm_new_operations(NM_INODE_OPS, NULL);
  if (IS_ERR(inode_ops)) {
    nm_discard_operations(file_ops);
    return PTR_ERR(inode_ops);
  }
  nm_set_operation_callback(inode_ops, struct_offset.iop_getattr, nm_file_getattr_callback());
  rc = nm_install_setattr(inode_ops);
  if (rc) {
    nm_discard_operations(inode_ops);
    nm_discard_operations(file_ops);
    return rc;
  }
  void* symlink_ops;
  rc = nm_new_symlink_operations(&symlink_ops);
  if (rc) {
    nm_discard_operations(inode_ops);
    nm_discard_operations(file_ops);
    return rc;
  }
  nm_inode_engine.file_ops = file_ops;
  nm_inode_engine.inode_ops = inode_ops;
  nm_inode_engine.symlink_ops = symlink_ops;
  return 0;
}
