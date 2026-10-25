/* SPDX-License-Identifier: GPL-2.0-only */
/* vfs_setxattr/do_set_acl入口前选择源；锁、权限、LSM与handler均留给原生。 */
static bool nm_xattr_writes_ready;
static bool nm_xattr_set_installed, nm_xattr_set_acl_installed;
static void* nm_xattr_set_target;
static void* nm_xattr_set_acl_target;
static int nm_xattr_set_context;
static int nm_xattr_write_status = -EOPNOTSUPP;
static bool (*nm_xattr_write_readonly)(struct vfsmount*);

static int nm_xattr_mutate_path(uint64_t* args, unsigned int at, bool setting) {
  struct dentry* dentry = (void*)args[at];
  struct inode* inode = dentry ? nm_dentry_inode(dentry) : NULL;
  if (!inode || !nm_is_virtual_inode(inode))
    return 0;
  if (!__atomic_load_n(&nm_xattr_writes_ready, __ATOMIC_ACQUIRE))
    return -EOPNOTSUPP;
  if (nm_xattr_write_status)
    return nm_xattr_write_status;
  int rc = nm_validate_inode_offsets((const void*)&struct_offset);
  if (rc)
    return rc;
  struct nm_inode_info* info = nm_inode_private(inode);
  if (!info || !__atomic_load_n(&info->initialized, __ATOMIC_ACQUIRE))
    return -EIO;
  if (!info->r_path.dentry)  // 纯虚拟目录没有可修改的源。
    return -EOPNOTSUPP;
  if (!info->r_path.mnt)
    return -EIO;
  struct inode* source = nm_dentry_inode(info->r_path.dentry);
  if (!source)
    return -EIO;
  if (source == inode || nm_is_virtual_inode(source))
    return -ELOOP;
  if (nm_xattr_set_context) {
    const struct nm_mount_context_head* mount = info->r_path.mnt;
    void* context = nm_xattr_set_context == 1 ? (void*)mount->context.userns : (void*)mount->context.idmap;
    if (!context)
      return -EINVAL;
    if (context != (void*)args[0])
      return -EXDEV;
  }
  const char* name = (void*)args[at + 1];  // VFS入口收到内核名称，不是用户指针。
  if (!name)
    return -EINVAL;
  // 部分调用者已按外层inode转换nscap；未证转换层前不把该载荷转交源。
  if (setting && !strcmp(name, "security.capability"))
    return -EOPNOTSUPP;
  if (!nm_xattr_write_readonly)
    return -ENOENT;
  if (nm_xattr_write_readonly(info->r_path.mnt))
    return -EROFS;
  // A档：回调不取得源mnt_want_write/drop_write，只依赖VFS调用者已持有的外层写引用；
  // 同sb重取会与freezer互等。没有源侧writer/freeze屏障，也不隔离随后remount-ro竞态。
  // 当前不持外层inode锁；完整原生VFS随后取得源锁并执行权限/LSM和delegation重试。
  args[at] = (uintptr_t)info->r_path.dentry;
  return 0;
}

static int nm_xattr_write_path(uint64_t* args, unsigned int at) { return nm_xattr_mutate_path(args, at, true); }

static void nm_xattr_set5(hook_fargs5_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_write_path(args->args, 0);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}

static void nm_xattr_set_mapped(hook_fargs6_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_write_path(args->args, 1);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}

// 沿读取族的驻留/首次ADD契约；ready发布前不允许managed修改，部分hook保留供重试。
static int nm_activate_xattr_writes_locked(void) {
  if (!__atomic_load_n(&nm_xattr_resident, __ATOMIC_ACQUIRE))
    return -ENODEV;
  if (__atomic_load_n(&nm_xattr_writes_ready, __ATOMIC_ACQUIRE))
    return 0;
  if (!nm_xattr_set_target) {
    int context = struct_offset.getattr_context_kind;
    if (context < 0 || context > 2 || (context && struct_offset.permission_abi != context + 1)
        || (!context && struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
      return -EOPNOTSUPP;
    void* set = (void*)kallsyms_lookup_name_by_suffix("vfs_setxattr");
    void* acl = (void*)kallsyms_lookup_name_by_suffix("do_set_acl");
    if (!set)
      return -ENOENT;
    if (set == acl || set == nm_xattr_get_target || set == nm_xattr_list_target || set == nm_xattr_acl_target
        || (acl && (acl == nm_xattr_get_target || acl == nm_xattr_list_target || acl == nm_xattr_acl_target)))
      return -EINVAL;
    nm_xattr_write_status = -EOPNOTSUPP;
#ifndef CONFIG_KPM_BASELINES
    bool unavailable = false;
    int shape = calculate_btf_xattr_write(context, &unavailable);
    if (shape < 0 && !(shape == -ENODATA && unavailable))
      return shape;
    if (shape >= 0 && !!acl != !!shape)
      return -EOPNOTSUPP;
    if (shape < 0 && (context == 2 || acl))
      return -EOPNOTSUPP;
    if (shape < 0 && !context && !acl && !nm_setattr_status) {
      // 仅BTF不可用时尝试已验证的plain5；证据不足保留既有拒绝hook。
      int plain = calculate_function_xattr_write(context, &nm_setattr_layout);
      if (!plain)
        shape = 0;
      else
        nm_log_info("layout: setxattr plain5 unavailable (%d); writes remain closed\n", plain);
    }
    if (shape >= 0) {
      nm_xattr_write_readonly = (void*)kallsyms_lookup_name_by_suffix("__mnt_is_readonly");
      nm_xattr_write_status = nm_xattr_write_readonly ? 0 : -ENOENT;
    }
#else
    // 已登记plain/userns共同入口只用于拒绝；静态表未提供新写入ABI证据。
    if (context == 2 || acl)
      return -EOPNOTSUPP;
#endif
    nm_xattr_set_context = context;
    nm_xattr_set_acl_target = acl;
    nm_xattr_set_target = set;
  }
  if (!nm_xattr_set_installed) {
    hook_err_t rc = hook_wrap(nm_xattr_set_target, nm_xattr_set_context ? 6 : 5,
                              nm_xattr_set_context ? (void*)nm_xattr_set_mapped : (void*)nm_xattr_set5, NULL, NULL);
    if (rc)
      return -EOPNOTSUPP;
    nm_xattr_set_installed = true;
  }
  if (nm_xattr_set_acl_target && !nm_xattr_set_acl_installed) {
    hook_err_t rc = hook_wrap(nm_xattr_set_acl_target, 5, nm_xattr_set_mapped, NULL, NULL);
    if (rc)
      return -EOPNOTSUPP;
    nm_xattr_set_acl_installed = true;
  }
  __atomic_store_n(&nm_xattr_writes_ready, true, __ATOMIC_RELEASE);
  return 0;
}
