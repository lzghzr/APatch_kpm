/* SPDX-License-Identifier: GPL-2.0-only */
/* Materialization and eviction adapted from the pinned NoMount implementation. */
struct kstat;
struct dentry;

struct nm_inode_engine {
  void* file_ops;
  void* inode_ops;
  void (*release_directory)(struct inode*);
  const void* directory_ops;
  void (*put_directory_node)(void*);
  struct dentry* (*materialize_directory)(struct inode*, struct dentry*, struct nomount_rule*, void*, u64);
  struct dentry* (*lookup_backing)(struct inode*, struct dentry*, unsigned int);
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
static bool nm_is_virtual_inode(struct inode* inode) { return nm_is_file_inode(inode) || nm_is_directory_inode(inode); }

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
  struct nm_inode_info* info = inode && nm_is_file_inode(inode) ? nm_inode_private(inode) : NULL;
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
// 目录、whiteout 和重验证由后续 lookup 层接入，本入口只物化有 backing 的普通文件。
static struct dentry* nm_materialize_file(struct inode* parent, struct dentry* dentry, struct nomount_rule* rule,
                                          u64 number) {
  if (!rule || !rule->r_path.dentry || rule->flags & (NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT))
    return ERR_PTR(-EOPNOTSUPP);
  struct inode* backing = nm_dentry_inode(rule->r_path.dentry);
  if (!backing || (nm_inode_mode(backing) & 0170000) != 0100000)
    return ERR_PTR(-EOPNOTSUPP);
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
  info->secid = context.secid;
  nm_initialize_file_inode(inode, backing, number, info, nm_inode_engine.inode_ops, nm_inode_engine.file_ops);
  rc = nm_initialize_inode_security(inode, &context);
  nm_release_security_context(&context);
  if (rc) {
    kfunc(nm_iput)(inode);  // 原生evict释放独立path/info与LSM分配。
    return ERR_PTR(rc);
  }
  __atomic_store_n(&info->initialized, true, __ATOMIC_RELEASE);
  return kfunc(nm_d_splice_alias)(inode, dentry);
}

static int nm_prepare_inode_engine(void) {
  if (nm_inode_engine.inode_ops)
    return -EALREADY;
  int rc = nm_prepare_inode_layout();
  if (!rc)
    rc = nm_prepare_inode_functions();
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
  nm_inode_engine.file_ops = file_ops;
  nm_inode_engine.inode_ops = inode_ops;
  return 0;
}
