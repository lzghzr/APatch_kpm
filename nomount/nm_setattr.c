/* SPDX-License-Identifier: GPL-2.0-only */
/* A档：外层VFS事务中的源属性回调；不取得第二份mount写引用。 */
static struct nm_setattr_layout nm_setattr_layout;
static int nm_setattr_status = -EOPNOTSUPP;
#ifndef CONFIG_KPM_BASELINES
// 保留可选能力的具体推导结果，不能将冲突/损坏误作“目标不支持”。
static int nm_setattr_derivation_status = -ENODATA;
#endif
static int (*nm_setattr_lock)(void*);
static void (*nm_setattr_unlock)(void*);
static bool (*nm_setattr_readonly)(struct vfsmount*);
static int (*nm_notify_plain)(struct dentry*, void*, struct inode**);
static int (*nm_notify_context)(void*, struct dentry*, void*, struct inode**);

// 已核对声明前部与getattr锚点共同约束setattr槽；不按版本分派。
static int nm_setattr_slots(int* second) {
  *second = -1;
  if (struct_offset.getattr_context_kind < 0 || struct_offset.getattr_context_kind > 2 || struct_offset.iop_getattr < 0
      || struct_offset.inode_ops_size < 0)
    return -EINVAL;
  int slot;
  if (struct_offset.permission_abi == 0 && !struct_offset.getattr_context_kind) {
    if (struct_offset.iop_getattr == offsetof(struct nm_inode_follow_prefix, getattr)) {
      slot = offsetof(struct nm_inode_follow_prefix, setattr);
      *second = offsetof(struct nm_inode_follow_prefix, setattr2);
    } else if (struct_offset.iop_getattr == offsetof(struct nm_inode_android_link_prefix, getattr)) {
      slot = offsetof(struct nm_inode_android_link_prefix, setattr);
      *second = offsetof(struct nm_inode_android_link_prefix, setattr2);
    } else
      return -EOPNOTSUPP;
  } else if (struct_offset.permission_abi == struct_offset.getattr_context_kind + 1
             && struct_offset.iop_getattr == offsetof(struct nm_inode_plain_link_prefix, getattr)) {
    slot = offsetof(struct nm_inode_plain_link_prefix, setattr);
  } else
    return -EOPNOTSUPP;
  if (slot < 0 || slot % 8 || slot + 8 > struct_offset.inode_ops_size
      || (*second >= 0 && (*second % 8 || *second + 8 > struct_offset.inode_ops_size)))
    return -EINVAL;
  return slot;
}

static int nm_prepare_setattr(void) {
  nm_setattr_status = -EOPNOTSUPP;
#ifndef CONFIG_KPM_BASELINES
  nm_setattr_derivation_status = -ENODATA;
#endif
  // 槽位依赖permission ABI：在本入口显式准备，不依赖稍后的backing引擎或调用者预填。
  int rc = nm_prepare_permission_abi();
  if (rc)
    return rc;
  int second, slot = nm_setattr_slots(&second);
  if (slot < 0)
    return slot;
#ifndef CONFIG_KPM_BASELINES
  bool unavailable = false;
  struct nm_setattr_layout layout;
  rc = calculate_btf_setattr(&layout, &unavailable);
  if (rc == -ENODATA && unavailable) {
    rc = calculate_function_setattr(&layout, slot);
    nm_setattr_derivation_status = rc;
    if (rc) {
      nm_log_info("layout: source inode lock unavailable (%d); write callbacks remain closed\n", rc);
      return 0;  // 可选写能力缺证据，既有读取入口保持可用。
    }
  }
  if (rc)
    return rc;
  if (layout.slot != slot)
    return -EINVAL;
  nm_setattr_layout = layout;
  nm_setattr_lock =
      (void*)kallsyms_lookup_name_by_suffix(layout.lock_kind == 1 ? "down_write_killable" : "mutex_lock_interruptible");
  nm_setattr_unlock = (void*)kallsyms_lookup_name_by_suffix(layout.lock_kind == 1 ? "up_write" : "mutex_unlock");
  nm_setattr_readonly = (void*)kallsyms_lookup_name_by_suffix("__mnt_is_readonly");
  void* notify =
      (void*)kallsyms_lookup_name_by_suffix(struct_offset.permission_abi == 0 ? "notify_change2" : "notify_change");
  nm_notify_plain = !layout.context && struct_offset.permission_abi != 0 ? notify : NULL;
  nm_notify_context = layout.context || struct_offset.permission_abi == 0 ? notify : NULL;
  if (!nm_setattr_lock || !nm_setattr_unlock || !nm_setattr_readonly || !notify) {
    nm_setattr_status = -ENOENT;
    return 0;
  }
  nm_setattr_status = 0;
#endif
  // 静态46项表尚无源锁的类型/位置证据；保持明确拒绝，不运行时猜偏移。
  return 0;
}

static int nm_setattr_context(void* outer_context, struct dentry* dentry, void* attr) {
  if (nm_setattr_status)
    return nm_setattr_status;
  int valid = nm_validate_inode_offsets((const void*)&struct_offset);
  if (valid)
    return valid;
  int second, slot = nm_setattr_slots(&second);
  if (slot < 0 || slot != nm_setattr_layout.slot || nm_setattr_layout.lock_offset < 0
      || nm_setattr_layout.lock_offset % 8 || nm_setattr_layout.lock_offset > 0x7fff
      || (nm_setattr_layout.lock_kind != 1 && nm_setattr_layout.lock_kind != 2)
      || nm_setattr_layout.context != struct_offset.getattr_context_kind)
    return -EINVAL;
  if (!attr || !dentry)
    return -EINVAL;
  unsigned int requested = ((struct nm_iattr_head*)attr)->ia_valid;
  // SIZE只与原生FD/时间等辅助位同行；MODE/UID/GID复合在源锁前整体拒绝。
  // 包括外层notify内生的MODE，不能把MODE|KILL再次交给源notify。
  if ((requested & 8U) && (requested & 7U))
    return -EOPNOTSUPP;
  struct inode* inode = nm_dentry_inode(dentry);
  if (!inode || !nm_is_virtual_inode(inode))
    return -EIO;
  const struct nm_inode_info* info = nm_inode_private(inode);
  if (!info || !__atomic_load_n(&info->initialized, __ATOMIC_ACQUIRE) || !info->r_path.dentry || !info->r_path.mnt)
    return -EOPNOTSUPP;  // 纯虚拟目录没有可修改的源。
  struct inode* source = nm_dentry_inode(info->r_path.dentry);
  if (!source || source == inode || nm_is_virtual_inode(source))
    return -ELOOP;
  void* context = info->r_path.mnt;
  if (nm_setattr_layout.context) {
    const struct nm_mount_context_head* mount = info->r_path.mnt;
    context = nm_setattr_layout.context == 1 ? (void*)mount->context.userns : (void*)mount->context.idmap;
    if (!context)
      return -EINVAL;
    if (context != outer_context)
      return -EXDEV;  // iattr已按外层idmap转换；本轮不重解释跨映射的UID/GID。
  }
  if (!nm_setattr_lock || !nm_setattr_unlock || !nm_setattr_readonly
      || (nm_setattr_layout.context || struct_offset.permission_abi == 0 ? !nm_notify_context : !nm_notify_plain))
    return -ENOENT;
  void* lock = (void*)((uintptr_t)source + nm_setattr_layout.lock_offset);
  // VFS调用者持外层inode锁与外层写引用；顺序为outer→source。
  // A档不在回调重取mount写引用：同sb递归freeze读锁会与freezer互等。
  // 跨mount没有源writer/freeze屏障；下面只拒绝当前只读状态，不隔离remount竞态。
  int rc = nm_setattr_lock(lock);
  if (rc)
    return rc;
  if (nm_setattr_readonly(info->r_path.mnt))
    rc = -EROFS;
  else
    rc = nm_setattr_layout.context || struct_offset.permission_abi == 0
             ? nm_notify_context(context, info->r_path.dentry, attr, NULL)
             : nm_notify_plain(info->r_path.dentry, attr, NULL);
  if (!rc) {
    struct nm_inode_owner_prefix* owner = (void*)inode;
    const struct nm_inode_owner_prefix* real = (void*)source;
    owner->i_mode = real->i_mode;
    owner->i_uid = real->i_uid;
    owner->i_gid = real->i_gid;
    *(struct nm_inode_size_times*)((uintptr_t)inode + struct_offset.inode_size) =
        *(const struct nm_inode_size_times*)((uintptr_t)source + struct_offset.inode_size);
  }
  nm_setattr_unlock(lock);
  return rc;
}

static int nm_setattr(struct dentry* dentry, void* attr) { return nm_setattr_context(NULL, dentry, attr); }

static int nm_setattr_mapped(void* context, struct dentry* dentry, void* attr) {
  return nm_setattr_context(context, dentry, attr);
}

static int nm_install_setattr(void* table) {
  int second, slot = nm_setattr_slots(&second);
  if (slot < 0)
    return slot;
  nm_set_operation_callback(table, slot,
                            struct_offset.getattr_context_kind ? (void*)nm_setattr_mapped : (void*)nm_setattr);
  if (second >= 0)
    nm_set_operation_callback(table, second, nm_setattr_mapped);
  return 0;
}
