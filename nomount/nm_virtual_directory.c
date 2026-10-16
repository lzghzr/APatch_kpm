/* SPDX-License-Identifier: GPL-2.0-only */
/* Virtual directory identity and callbacks adapted from the pinned NoMount source. */
static void* nm_virtual_directory_fops;
static struct inode* kfunc_def(nm_iget5_locked)(struct super_block*, unsigned long, int (*)(struct inode*, void*),
                                                int (*)(struct inode*, void*), void*);
static void kfunc_def(nm_unlock_new_inode)(struct inode*);
static void kfunc_def(nm_generic_fillattr)(struct inode*, struct kstat*);
static void (*nm_fillattr_userns)(struct user_namespace*, struct inode*, struct kstat*);
static void (*nm_fillattr_idmap)(struct mnt_idmap*, u32, struct inode*, struct kstat*);
static void kfunc_def(nm_set_nlink)(struct inode*, unsigned int);
static int64_t kfunc_def(nm_generic_file_llseek)(struct file*, int64_t, int);

static int nm_prepare_virtual_directory_functions(void) {
  int abi = struct_offset.fillattr_abi;
  if (abi < 0)
    return -ENOENT;
  if (abi < 2 || abi > 4 || abi - 2 != struct_offset.getattr_context_kind)
    return -EOPNOTSUPP;
  kfunc(nm_iget5_locked) = (typeof(kfunc(nm_iget5_locked)))kallsyms_lookup_name_by_suffix("iget5_locked");
  kfunc(nm_unlock_new_inode) = (typeof(kfunc(nm_unlock_new_inode)))kallsyms_lookup_name_by_suffix("unlock_new_inode");
  kfunc(nm_generic_fillattr) = (typeof(kfunc(nm_generic_fillattr)))kallsyms_lookup_name_by_suffix("generic_fillattr");
  nm_fillattr_userns = abi == 3 ? (void*)kfunc(nm_generic_fillattr) : NULL;
  nm_fillattr_idmap = abi == 4 ? (void*)kfunc(nm_generic_fillattr) : NULL;
  kfunc(nm_set_nlink) = (typeof(kfunc(nm_set_nlink)))kallsyms_lookup_name_by_suffix("set_nlink");
  kfunc(nm_generic_file_llseek) =
      (typeof(kfunc(nm_generic_file_llseek)))kallsyms_lookup_name_by_suffix("generic_file_llseek");
  return kfunc(nm_iget5_locked) && kfunc(nm_unlock_new_inode) && kfunc(nm_generic_fillattr) && kfunc(nm_set_nlink)
                 && kfunc(nm_generic_file_llseek)
             ? 0
             : -ENOENT;
}

// 原生 inode_hash_lock 不保护模块 info；test 可能先于 I_FREEING 检查，必须另持原生 RCU。
static int nm_cached_directory_test(struct inode* inode, void* data) {
  const struct nm_inode_info* candidate = data;
  nm_rcu_read_lock();
  bool match =
      nm_is_directory_inode(inode)
      && nm_inode_matches_binding(inode, &candidate->r_path, candidate->dir_node, candidate->flags, candidate->secid);
  nm_rcu_read_unlock();
  return match;
}
static int nm_cached_directory_set(struct inode* inode, void* data) {
  nm_set_inode_private(inode, data);
  // 此时 inode 带 I_NEW；原生 iget 等待 unlock_new_inode 后才能供其他调用者使用。
  nm_publish_inode_ops(inode, nm_inode_engine.directory_ops, nm_virtual_directory_fops);
  return 0;
}
static void nm_put_virtual_directory_node(void* node) { nm_directory_node_put(node); }

// 候选先取得独立path/node引用；新inode接收，命中或失败则在进程上下文释放。
static struct dentry* nm_materialize_virtual_directory(struct inode* parent, struct dentry* dentry,
                                                       struct nomount_rule* rule, void* node, u64 number) {
  bool backed = rule && rule->flags == NM_FLAG_IS_DIR && rule->r_path.dentry;
  bool pure = rule && rule->flags == (NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR) && !rule->r_path.dentry;
  if (!node || (!pure && !backed) || (backed && !nm_inode_engine.lookup_backing))
    return ERR_PTR(-EOPNOTSUPP);
  if (pure && rule->inherit_backing && nm_inode_engine.inherit_directory) {
    struct nomount_rule* inherited = nm_inode_engine.inherit_directory(parent, dentry);
    if (IS_ERR(inherited))
      return (void*)inherited;
    if (inherited) {
      struct dentry* result = nm_materialize_virtual_directory(parent, dentry, inherited, node, number);
      nm_rule_put(inherited);
      return result;
    }
  }
  struct inode* backing = backed ? nm_dentry_inode(rule->r_path.dentry) : NULL;
  if (backed) {
    if (!backing || (nm_inode_mode(backing) & 0170000) != 0040000)
      return ERR_PTR(-ENOTDIR);
    const struct nm_inode_lookup_ops* operations = nm_inode_ops(backing);
    if (backing == parent || nm_is_virtual_inode(backing) || (operations && operations->lookup == nm_directory_lookup))
      return ERR_PTR(-ELOOP);
  }
  struct super_block* sb = nm_inode_superblock(parent);
  if (!nm_inode_engine.directory_ops || !nm_virtual_directory_fops || !nm_super_proxy(nm_super_ops(sb)))
    return ERR_PTR(-ENODEV);
  int rc = nm_wrap_dentry(dentry, true);
  if (rc)
    return ERR_PTR(rc);
  struct nm_security_context context;
  rc = nm_get_security_context(backed ? backing : parent, &context);
  if (rc)
    return ERR_PTR(rc);
  struct nm_inode_info* info = nm_zalloc(sizeof(*info));
  if (!info) {
    nm_release_security_context(&context);
    return ERR_PTR(-ENOMEM);
  }
  nm_bind_inode_path(info, rule);
  info->secid = context.secid;
  info->dir_node = node;
  nm_directory_node_get(node);
  struct inode* inode =
      kfunc(nm_iget5_locked)(sb, (unsigned long)node, nm_cached_directory_test, nm_cached_directory_set, info);
  if (IS_ERR_OR_NULL(inode)) {
    nm_put_inode_binding(info);
    nm_free(info);
    nm_release_security_context(&context);
    return inode ? (void*)inode : ERR_PTR(-ENOMEM);
  }
  if (nm_inode_private(inode) == info) {
    // set 仅被成功插入的新 inode 调用；命中旧 inode 的原生 iget 会先等待其初始化。
    if (backed)
      nm_initialize_backing_directory_inode(inode, backing, number, nm_inode_engine.directory_ops,
                                            nm_virtual_directory_fops);
    else
      nm_initialize_directory_inode(inode, parent, number, nm_inode_engine.directory_ops, nm_virtual_directory_fops);
    kfunc(nm_set_nlink)(inode, backed ? nm_inode_nlink(backing) : 2);
    info->init_error = nm_initialize_inode_security(inode, &context);
    __atomic_store_n(&info->initialized, true, __ATOMIC_RELEASE);
    kfunc(nm_unlock_new_inode)(inode);
  } else {
    nm_put_inode_binding(info);
    nm_free(info);
  }
  nm_release_security_context(&context);
  // 已在test中命中的等待者可能等到初始化失败；唤醒后同样检查错误，绝不发布alias。
  const struct nm_inode_info* existing = nm_inode_private(inode);
  rc = existing->init_error;
  if (rc) {
    kfunc(nm_iput)(inode);
    return ERR_PTR(rc);
  }
  struct dentry* result = kfunc(nm_d_splice_alias)(inode, dentry);
  if (!IS_ERR_OR_NULL(result) && nm_dentry_ops(result) != nm_owned_dentry_ops) {
    // 已有虚拟 alias 应保有模块表；不能接管其他原生 alias 的私有生命周期。
    kfunc(nm_d_drop)(result);
    kfunc(nm_dput)(result);
    return ERR_PTR(-EOPNOTSUPP);
  }
  return result;
}

static int nm_virtual_directory_getattr_context(void* context, const struct nm_path* path, struct kstat* stat, u32 mask,
                                                unsigned int flags) {
  struct inode* inode = nm_dentry_inode(path->dentry);
  if (!inode || !nm_is_directory_inode(inode))
    return -ENODEV;
  struct nm_inode_info* info = nm_inode_private(inode);
  if (info && info->r_path.dentry)
    return nm_getattr_from_backing(inode, &info->r_path, stat, mask, flags);
  if (struct_offset.fillattr_abi != 2 && !context)
    return -EINVAL;
  if (struct_offset.fillattr_abi == 3)
    nm_fillattr_userns(context, inode, stat);
  else if (struct_offset.fillattr_abi == 4)
    nm_fillattr_idmap(context, mask, inode, stat);
  else
    kfunc(nm_generic_fillattr)(inode, stat);
  return 0;
}
static int nm_virtual_directory_getattr(const struct nm_path* path, struct kstat* stat, u32 mask, unsigned int flags) {
  return nm_virtual_directory_getattr_context(NULL, path, stat, mask, flags);
}
static int nm_virtual_directory_getattr_userns(struct user_namespace* userns, const struct nm_path* path,
                                               struct kstat* stat, u32 mask, unsigned int flags) {
  return nm_virtual_directory_getattr_context(userns, path, stat, mask, flags);
}
static int nm_virtual_directory_getattr_idmap(struct mnt_idmap* idmap, const struct nm_path* path, struct kstat* stat,
                                              u32 mask, unsigned int flags) {
  return nm_virtual_directory_getattr_context(idmap, path, stat, mask, flags);
}
static int nm_virtual_directory_getattr_mount(struct vfsmount* mount, struct dentry* dentry, struct kstat* stat) {
  const struct nm_path path = {mount, dentry};
  return nm_virtual_directory_getattr(&path, stat, 0, 0);
}
static long nm_virtual_directory_read(struct file* file, char* buffer, unsigned long size, int64_t* position) {
  return -EISDIR;
}
static int64_t nm_virtual_directory_llseek(struct file* file, int64_t offset, int whence) {
  struct inode* inode = nm_file_inode(file);
  struct nm_inode_info* info = inode && nm_is_directory_inode(inode) ? nm_inode_private(inode) : NULL;
  if (info && !(info->flags & NM_FLAG_VIRTUAL_DIR))
    return nm_inode_engine.seek_backing ? nm_inode_engine.seek_backing(file, offset, whence) : -EOPNOTSUPP;
  bool compat = nm_current_compat();
  if (whence == 0 && nm_virtual_position(offset, compat))
    return kfunc(nm_vfs_setpos)(file, offset, 0x7fffffffffffffffLL);
  if (whence == 1 && !offset && nm_virtual_position(*nm_file_position(file), compat))
    return *nm_file_position(file);
  return kfunc(nm_generic_file_llseek)(file, offset, whence);
}
static int nm_virtual_directory_iterate(struct file* file, struct nm_dir_context* context) {
  struct inode* inode = nm_file_inode(file);
  struct nm_inode_info* info = nm_is_directory_inode(inode) ? nm_inode_private(inode) : NULL;
  if (!info || !info->dir_node)
    return -ENODEV;
  if (!(info->flags & NM_FLAG_VIRTUAL_DIR))
    return nm_inode_engine.iterate_backing ? nm_inode_engine.iterate_backing(file, context, info->dir_node)
                                           : -EOPNOTSUPP;
  if (context->pos < 0)
    return -EINVAL;
  if (context->pos == 0) {
    if (nm_dir_emit(context, ".", 1, 0, nm_inode_number(inode), 4))
      return 0;
    context->pos = 1;
  }
  if (context->pos == 1) {
    struct dentry* parent = kfunc(nm_dget_parent)(nm_file_path(file)->dentry);
    struct inode* parent_inode = nm_dentry_inode(parent);
    u64 number = parent_inode ? nm_inode_number(parent_inode) : nm_inode_number(inode);
    int rc = nm_dir_emit(context, "..", 2, 1, number, 4);
    kfunc(nm_dput)(parent);
    if (rc)
      return 0;
    context->pos = 2;
  }
  u32 uid = nm_current_fsuid();
  return nomount_is_uid_blocked(uid) ? 0 : nm_emit_children(info->dir_node, context, uid, nm_current_compat());
}

static int nm_prepare_virtual_directory_engine(void) {
  if (!nm_owned_dentry_ops || !nm_inode_engine.inode_ops)
    return -ENODEV;
  if (nm_inode_engine.directory_ops)
    return -EALREADY;
  if (struct_offset.file_inode_ops < sizeof(struct nm_path))
    return -EINVAL;
#ifndef CONFIG_KPM_BASELINES
  int rc = nm_prepare_virtual_directory_abi();
  if (rc)
    return rc;
#endif
  int status = nm_prepare_virtual_directory_functions();
  if (status)
    return status;
  void* iops = nm_new_operations(NM_INODE_OPS, NULL);
  if (IS_ERR(iops))
    return PTR_ERR(iops);
  void* fops = nm_new_operations(NM_FILE_OPS, NULL);
  if (IS_ERR(fops)) {
    nm_discard_operations(iops);
    return PTR_ERR(fops);
  }
  ((struct nm_inode_lookup_ops*)iops)->lookup = nm_directory_lookup;
  void* getattr = struct_offset.getattr_context_kind == 1    ? (void*)nm_virtual_directory_getattr_userns
                  : struct_offset.getattr_context_kind == 2  ? (void*)nm_virtual_directory_getattr_idmap
                  : struct_offset.getattr_callback_args == 3 ? (void*)nm_virtual_directory_getattr_mount
                                                             : (void*)nm_virtual_directory_getattr;
  nm_set_operation_callback(iops, struct_offset.iop_getattr, getattr);
  ((struct nm_file_io_ops*)fops)->read = nm_virtual_directory_read;
  ((struct nm_file_io_ops*)fops)->llseek = nm_virtual_directory_llseek;
  nm_set_operation_callback(fops, struct_offset.fop_open, nm_open);
  nm_set_operation_callback(fops, struct_offset.fop_release, nm_release);
  int iterate = struct_offset.fop_iterate_shared >= 0 ? struct_offset.fop_iterate_shared : struct_offset.fop_iterate;
  nm_set_operation_callback(fops, iterate, nm_virtual_directory_iterate);
  nm_virtual_directory_fops = fops;
  nm_inode_engine.directory_ops = iops;
  nm_inode_engine.put_directory_node = nm_put_virtual_directory_node;
  nm_inode_engine.materialize_directory = nm_materialize_virtual_directory;
  return 0;
}
