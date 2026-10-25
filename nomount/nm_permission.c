/* SPDX-License-Identifier: GPL-2.0-only */
/* DAC使用inode保留的源；外层security_inode_permission保留原生门控。 */
#ifndef CONFIG_KPM_BASELINES
#include "nm_permission_shape.c"

static int (*nm_generic_permission_plain)(struct inode*, int);
static int (*nm_generic_permission_context)(void*, struct inode*, int);
static uintptr_t nm_permission_generic, nm_permission_code_start, nm_permission_code_end;
static int nm_permission_slot = -1, nm_permission_second = -1;

static int nm_generic_dac(void* context, struct inode* inode, int mask) {
  if (struct_offset.permission_abi < 2)
    return nm_generic_permission_plain(inode, mask);
  return context ? nm_generic_permission_context(context, inode, mask) : -EINVAL;
}

static int nm_owned_permission(void* context, struct inode* inode, int mask) {
  // RCU-walk不读绑定、不取ACL、不调用可睡眠的原生入口。
  if (mask & 0x80)  // MAY_NOT_BLOCK
    return -ECHILD;
  if (!inode || !nm_is_virtual_inode(inode))
    return -EINVAL;
  const struct nm_inode_info* info = nm_inode_private(inode);
  if (!info || !__atomic_load_n(&info->initialized, __ATOMIC_ACQUIRE) || info->init_error)
    return -EIO;
  if (!info->r_path.dentry) {
    if (!(info->flags & NM_FLAG_VIRTUAL_DIR) || info->r_path.mnt)
      return -EIO;
    return nm_generic_dac(context, inode, mask);
  }
  struct inode* source = nm_dentry_inode(info->r_path.dentry);
  if (!source || !info->r_path.mnt)
    return -EIO;
  if (source == inode || nm_is_virtual_inode(source))
    return -ELOOP;
  const void* ops = nm_inode_ops(source);
  if (!ops || nm_permission_slot < 0)
    return -EIO;
  // generic_permission不能替代文件系统的自定义授权。未知槽在调用前拒绝。
  // 不改源IOP_FASTPERM；NULL与原生generic入口是唯一可接受的DAC分派。
  uintptr_t callback = (uintptr_t)nm_operation_callback(ops, nm_permission_slot);
  if ((callback && !nm_code_matches(callback, nm_permission_generic, nm_permission_code_start, nm_permission_code_end))
      || (nm_permission_second >= 0 && nm_operation_callback(ops, nm_permission_second)))
    return -EOPNOTSUPP;
  if (struct_offset.permission_abi >= 2) {
    const struct nm_mount_context_head* mount = info->r_path.mnt;
    context = struct_offset.permission_abi == 2 ? (void*)mount->context.userns : (void*)mount->context.idmap;
  }
  // path引用由inode持有。此处不取管理锁/外层或源inode锁，不触碰S_PRIVATE。
  return nm_generic_dac(context, source, mask);
}

static int nm_permission_plain(struct inode* inode, int mask) { return nm_owned_permission(NULL, inode, mask); }
static int nm_permission_mount(struct vfsmount* mount, struct inode* inode, int mask) {
  return nm_owned_permission(NULL, inode, mask);
}
static int nm_permission_userns(struct user_namespace* ns, struct inode* inode, int mask) {
  return nm_owned_permission(ns, inode, mask);
}
static int nm_permission_idmap(struct mnt_idmap* idmap, struct inode* inode, int mask) {
  return nm_owned_permission(idmap, inode, mask);
}

static int nm_install_owned_permissions(void) {
  int slot = -1, second = -1;
  bool unavailable = false;
  int rc = calculate_btf_owned_permission(&unavailable, &slot, &second);
  if (rc == -ENODATA && unavailable) {
    rc = nm_common_owned_permission(&slot, &second);
    if (!rc)
      rc = nm_confirm_generic_dac_abi();
  }
  if (rc)
    return rc;
  void* generic = (void*)kallsyms_lookup_name_by_suffix("generic_permission");
  if (!generic)
    return -ENOENT;
  int size = nm_owned_operation_size(NM_INODE_OPS);
  if (slot < 0 || slot % 8 || slot > size - 8 || (second >= 0 && (second % 8 || second > size - 8)))
    return -EINVAL;
  nm_generic_permission_plain = struct_offset.permission_abi < 2 ? generic : NULL;
  nm_generic_permission_context = struct_offset.permission_abi >= 2 ? generic : NULL;
  nm_permission_generic = (uintptr_t)generic;
  nm_permission_code_start = kallsyms_lookup_name("_stext");
  nm_permission_code_end = kallsyms_lookup_name("_etext");
  nm_permission_slot = slot;
  nm_permission_second = second;
  void* callback = struct_offset.permission_abi == 2   ? (void*)nm_permission_userns
                   : struct_offset.permission_abi == 3 ? (void*)nm_permission_idmap
                                                       : (void*)nm_permission_plain;
  // 完整引擎在控制注册和inode发布前准备；不热改已有IOP_FASTPERM的inode。
  void* tables[] = {nm_inode_engine.inode_ops, (void*)nm_inode_engine.directory_ops};
  for (unsigned int i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
    if (!tables[i])
      continue;
    nm_set_operation_callback(tables[i], slot, callback);
    if (second >= 0)
      nm_set_operation_callback(tables[i], second, nm_permission_mount);
  }
  return 0;
}
#endif
