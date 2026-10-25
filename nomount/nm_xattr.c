/* SPDX-License-Identifier: GPL-2.0-only */
/* Native VFS xattr reads for managed inodes, including descriptor callers. */
static bool nm_xattr_resident;
static bool nm_xattr_reads_ready;
static bool nm_xattr_get_installed, nm_xattr_list_installed;
static bool nm_xattr_acl_installed;
static void* nm_xattr_acl_target;
static void* nm_xattr_get_target;
static void* nm_xattr_list_target;
static int nm_xattr_get_args, nm_xattr_context;

// 调用者持有外层dentry/inode，info的独立源path覆盖整个原生调用。
// 这里只换已确认的VFS实参，不自行解释/调用文件系统私有回调。
static int nm_xattr_read_path(uint64_t* args, unsigned int at, bool mapped) {
  if (!__atomic_load_n(&nm_xattr_reads_ready, __ATOMIC_ACQUIRE))
    return 0;
  struct dentry* dentry = (void*)args[at];
  struct inode* inode = dentry ? nm_dentry_inode(dentry) : NULL;
  if (!inode || !nm_is_virtual_inode(inode))
    return 0;
  struct nm_inode_info* info = nm_inode_private(inode);
  if (!info)
    return -EIO;
  if (!info->r_path.dentry)  // 纯虚拟目录保持原生LSM/文件系统语义。
    return 0;
  struct inode* source = nm_dentry_inode(info->r_path.dentry);
  if (!source)
    return -EIO;
  if (source == inode || nm_is_virtual_inode(source))
    return -ELOOP;
  if (!info->r_path.mnt)
    return -EIO;
  if (mapped) {
    const struct nm_mount_context_head* mount = (void*)info->r_path.mnt;
    void* context = nm_xattr_context == 1 ? (void*)mount->context.userns : (void*)mount->context.idmap;
    if (!context)
      return -EINVAL;
    args[0] = (uintptr_t)context;
  }
  args[at] = (uintptr_t)info->r_path.dentry;
  return 0;
}

static void nm_xattr_get4(hook_fargs4_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_read_path(args->args, 0, false);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}
static void nm_xattr_get_mapped(hook_fargs5_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_read_path(args->args, 1, true);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}
static void nm_xattr_list3(hook_fargs3_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_read_path(args->args, 0, false);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}

// 管理锁串行化；只在控制key已注册、模块已驻留后由ADD调用。
// 现有SDK撤钩不等待在途回调，故保留成功接入；未齐全时不发布规则、回调直通。
static int nm_activate_xattr_reads_locked(void) {
  if (!__atomic_load_n(&nm_xattr_resident, __ATOMIC_ACQUIRE))
    return -ENODEV;
  if (__atomic_load_n(&nm_xattr_reads_ready, __ATOMIC_ACQUIRE))
    return 0;
  if (!nm_xattr_get_target) {
    int context = struct_offset.getattr_context_kind;
    if (context < 0 || context > 2 || (context && struct_offset.permission_abi != context + 1)
        || (!context && struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
      return -EOPNOTSUPP;
    int count = context ? 5 : 4;
#ifndef CONFIG_KPM_BASELINES
    bool unavailable = false;
    count = calculate_btf_xattr_read(context, &unavailable);
    if (count < 0 && !(count == -ENODATA && unavailable))
      return count;
    if (count < 0)
      count = context ? 5 : 4;
#endif
    // 静态共同契约限已登记的plain/userns目标；idmap先要求目标BTF。
#ifdef CONFIG_KPM_BASELINES
    if (context == 2)
      return -EOPNOTSUPP;
#else
    if (unavailable && context == 2)
      return -EOPNOTSUPP;
#endif
    void* get = (void*)kallsyms_lookup_name_by_suffix("vfs_getxattr");
    void* list = (void*)kallsyms_lookup_name_by_suffix("vfs_listxattr");
    if (!get || !list)
      return -ENOENT;
    if (get == list)
      return -EINVAL;
    void* acl = (void*)kallsyms_lookup_name_by_suffix("do_get_acl");
    if (acl && (acl == get || acl == list))
      return -EINVAL;
#ifndef CONFIG_KPM_BASELINES
    bool acl_unavailable = false;
    int acl_shape = calculate_btf_xattr_acl(context, &acl_unavailable);
    if (acl_shape < 0 && !(acl_shape == -ENODATA && acl_unavailable && !acl))
      return acl_shape;
    if (acl_shape == 1 && !acl)
      return -ENOENT;
    if (!acl_shape && acl)
      return -EOPNOTSUPP;
#else
    if (acl)  // 独立ACL入口尚无静态签名契约，不用旧目标的接口推测它。
      return -EOPNOTSUPP;
#endif
    nm_xattr_acl_target = acl;
    nm_xattr_context = context;
    nm_xattr_get_args = count;
    nm_xattr_get_target = get;
    nm_xattr_list_target = list;
  }
  if (!nm_xattr_get_installed) {
    hook_err_t rc = nm_xattr_get_args == 4
                        ? hook_wrap4(nm_xattr_get_target, nm_xattr_get4, NULL, NULL)
                        : hook_wrap(nm_xattr_get_target, nm_xattr_get_args, nm_xattr_get_mapped, NULL, NULL);
    if (rc) {
      nm_log_error("xattr: get wrap failed (%d)\n", rc);
      return -EOPNOTSUPP;
    }
    nm_xattr_get_installed = true;
  }
  if (!nm_xattr_list_installed) {
    hook_err_t rc = hook_wrap3(nm_xattr_list_target, nm_xattr_list3, NULL, NULL);
    if (rc) {
      nm_log_error("xattr: list wrap failed (%d)\n", rc);
      return -EOPNOTSUPP;
    }
    nm_xattr_list_installed = true;
  }
  if (nm_xattr_acl_target && !nm_xattr_acl_installed) {
    hook_err_t rc = hook_wrap(nm_xattr_acl_target, 5, nm_xattr_get_mapped, NULL, NULL);
    if (rc) {
      nm_log_error("xattr: ACL wrap failed (%d)\n", rc);
      return -EOPNOTSUPP;
    }
    nm_xattr_acl_installed = true;
  }
  __atomic_store_n(&nm_xattr_reads_ready, true, __ATOMIC_RELEASE);
  return 0;
}
