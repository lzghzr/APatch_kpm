/* SPDX-License-Identifier: GPL-2.0-only */
/* 动态版：补齐删除入口与syscall内联list路径。管理锁串行准备，驻留到重启。 */
#ifndef CONFIG_KPM_BASELINES
static bool nm_xattr_extra_ready, nm_xattr_remove_installed, nm_xattr_internal_list_installed;
static void *nm_xattr_remove_target, *nm_xattr_internal_list_target;
static int nm_xattr_remove_context;
static bool nm_xattr_remove_acl_installed;
static void* nm_xattr_remove_acl_target;

static int nm_xattr_extra_path(uint64_t* args, unsigned int at, bool removing) {
  struct inode* inode = args[at] ? nm_dentry_inode((void*)args[at]) : NULL;
  if (!inode || !nm_is_virtual_inode(inode))
    return 0;
  if (!__atomic_load_n(&nm_xattr_extra_ready, __ATOMIC_ACQUIRE))
    return -EOPNOTSUPP;
  return removing ? nm_xattr_mutate_path(args, at, false) : nm_xattr_read_path(args, at, false);
}

static void nm_xattr_remove2(hook_fargs2_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_extra_path(args->args, 0, true);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}
static void nm_xattr_remove_mapped(hook_fargs3_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_extra_path(args->args, 1, true);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}
static void nm_xattr_internal_list3(hook_fargs3_t* args, void* unused) {
  if (args->skip_origin)
    return;
  int rc = nm_xattr_extra_path(args->args, 0, false);
  if (rc) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)rc;
  }
}

static int nm_activate_xattr_extra_locked(void) {
  if (!__atomic_load_n(&nm_xattr_resident, __ATOMIC_ACQUIRE))
    return -ENODEV;
  if (__atomic_load_n(&nm_xattr_extra_ready, __ATOMIC_ACQUIRE))
    return 0;
  if (!nm_xattr_remove_target) {
    int context = nm_xattr_set_context;
    void* remove = (void*)kallsyms_lookup_name_by_suffix("vfs_removexattr");
    void* list = (void*)kallsyms_lookup_name_by_suffix("listxattr");
    void* acl = (void*)kallsyms_lookup_name_by_suffix("vfs_remove_acl");
    if (!remove || !list)
      return -ENOENT;
    if (remove == list || remove == nm_xattr_set_target || remove == nm_xattr_get_target
        || remove == nm_xattr_list_target || list == nm_xattr_set_target || list == nm_xattr_get_target
        || remove == nm_xattr_set_acl_target || list == nm_xattr_set_acl_target || remove == nm_xattr_acl_target
        || list == nm_xattr_acl_target)
      return -EINVAL;
    if (acl
        && (acl == remove || acl == list || acl == nm_xattr_set_target || acl == nm_xattr_get_target
            || acl == nm_xattr_list_target || acl == nm_xattr_set_acl_target || acl == nm_xattr_acl_target))
      return -EINVAL;
    bool unavailable = false;
    int rc = calculate_btf_xattr_remove(context, &unavailable);
    if (rc == -ENODATA && unavailable) {
      // 旧follow接口的removexattr在空i_op槽直接拒绝；此时可关闭extra而保留只读规则。
      // handler型删除不能用空槽证明拒绝；独立ACL入口也仍须核验，不能一律降级。
      if (nm_setattr_status == -EOPNOTSUPP && !acl && !context && !struct_offset.permission_abi
          && struct_offset.iop_getattr == offsetof(struct nm_inode_follow_prefix, getattr)) {
        if (nm_setattr_derivation_status != -EOPNOTSUPP && nm_setattr_derivation_status != -ENOENT)
          return nm_setattr_derivation_status ? nm_setattr_derivation_status : -EINVAL;
        nm_log_info("xattr: extra entries unavailable without source lock evidence; writes remain closed\n");
        return 0;
      }
      if (nm_setattr_status)
        return nm_setattr_status;
      rc = calculate_function_xattr_remove(context, &nm_setattr_layout);
    }
    if (rc)
      return rc;
    unavailable = false;
    rc = calculate_btf_xattr_internal_list(&unavailable);
    if (rc == -ENODATA && unavailable)
      rc = calculate_function_xattr_internal_list(context);
    if (rc)
      return rc;
    unavailable = false;
    int acl_shape = calculate_btf_xattr_remove_acl(context, &unavailable);
    if (acl_shape < 0) {
      if (!(acl_shape == -ENODATA && unavailable && !acl))
        return acl_shape;
    } else if (!!acl != !!acl_shape) {
      return acl_shape ? -ENOENT : -EOPNOTSUPP;
    }
    nm_xattr_remove_acl_target = acl;
    nm_xattr_remove_context = context;
    nm_xattr_remove_target = remove;
    nm_xattr_internal_list_target = list;
  }
  if (!nm_xattr_internal_list_installed) {
    if (nm_xattr_internal_list_target != nm_xattr_list_target) {
      hook_err_t rc = hook_wrap3(nm_xattr_internal_list_target, nm_xattr_internal_list3, NULL, NULL);
      if (rc)
        return -EOPNOTSUPP;
    }
    nm_xattr_internal_list_installed = true;
  }
  if (!nm_xattr_remove_installed) {
    hook_err_t rc =
        hook_wrap(nm_xattr_remove_target, nm_xattr_remove_context ? 3 : 2,
                  nm_xattr_remove_context ? (void*)nm_xattr_remove_mapped : (void*)nm_xattr_remove2, NULL, NULL);
    if (rc)
      return -EOPNOTSUPP;
    nm_xattr_remove_installed = true;
  }
  if (nm_xattr_remove_acl_target && !nm_xattr_remove_acl_installed) {
    hook_err_t rc = hook_wrap3(nm_xattr_remove_acl_target, nm_xattr_remove_mapped, NULL, NULL);
    if (rc)
      return -EOPNOTSUPP;
    nm_xattr_remove_acl_installed = true;
  }
  __atomic_store_n(&nm_xattr_extra_ready, true, __ATOMIC_RELEASE);
  nm_log_info("xattr: remove and syscall-list entries ready\n");
  return 0;
}
#endif
