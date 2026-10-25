/* SPDX-License-Identifier: GPL-2.0-only */
/* Backing directories share the virtual-directory inode cache and operation tables. */
static int kfunc_def(nm_inode_permission2)(struct vfsmount*, struct inode*, int);

// 编号表示原生签名：0=Android mount，1=inode，2=user namespace，3=idmap。
static int (*nm_inode_permission_plain)(struct inode*, int);
static int (*nm_inode_permission_userns)(struct user_namespace*, struct inode*, int);
static int (*nm_inode_permission_idmap)(struct mnt_idmap*, struct inode*, int);

static bool nm_permission_ready(void) {
  return kfunc(nm_inode_permission2) || nm_inode_permission_plain || nm_inode_permission_userns
         || nm_inode_permission_idmap;
}

static int nm_prepare_backing_inode_functions(void) {
#ifndef CONFIG_KPM_BASELINES
  int rc = nm_prepare_permission_abi();
  if (rc)
    return rc;
#endif
  int abi = struct_offset.permission_abi;
  if (abi < 0)
    return -ENOENT;
  if (abi > 3 || (abi >= 2 && struct_offset.getattr_context_kind != abi - 1))
    return -EOPNOTSUPP;
  void* function = (void*)kallsyms_lookup_name_by_suffix(abi == 0 ? "inode_permission2" : "inode_permission");
  if (!function)
    return -ENOENT;
  kfunc(nm_inode_permission2) = abi == 0 ? function : NULL;
  nm_inode_permission_plain = abi == 1 ? function : NULL;
  nm_inode_permission_userns = abi == 2 ? function : NULL;
  nm_inode_permission_idmap = abi == 3 ? function : NULL;
  return 0;
}

static int nm_backing_permission(const struct nm_path* path, int mask) {
  struct inode* inode = path && path->dentry ? nm_dentry_inode(path->dentry) : NULL;
  if (!inode || !path->mnt)
    return -ENOENT;
  if (struct_offset.permission_abi == 0)
    return kfunc(nm_inode_permission2)(path->mnt, inode, mask);
  if (struct_offset.permission_abi == 1)
    return nm_inode_permission_plain(inode, mask);
  const struct nm_mount_context_head* mount = path->mnt;
  if (struct_offset.permission_abi == 2)
    return mount->context.userns ? nm_inode_permission_userns(mount->context.userns, inode, mask) : -EINVAL;
  if (struct_offset.permission_abi == 3)
    return mount->context.idmap ? nm_inode_permission_idmap(mount->context.idmap, inode, mask) : -EINVAL;
  return -EOPNOTSUPP;
}

#include "nm_permission.c"

static int nm_backing_read_permission(const struct nm_path* path) {
  // dentry_open 本身不做 DAC，保留源 mount 对应的原生权限语义。
  return nm_backing_permission(path, 0x20 | 0x04);  // MAY_OPEN | MAY_READ。
}

static int nm_backing_write_permission(const struct nm_path* path, int flags) {
  // dentry_open保留原生file_open/写句柄检查，但不替代源DAC检查。
  int mask = 0x20 | 0x02;  // MAY_OPEN | MAY_WRITE。
  if ((flags & 03U) != 01U)
    mask |= 0x04;  // RDWR（及原生特殊access mode）仍需MAY_READ。
  return nm_backing_permission(path, mask);
}

// 临时规则接收path引用；物化另取独立引用后释放，published阻止进入管理树。
static struct nomount_rule* nm_take_backing_child_rule(struct nm_path* path, u32 uid) {
  struct inode* inode = path->dentry ? nm_dentry_inode(path->dentry) : NULL;
  unsigned int mode = inode ? nm_inode_mode(inode) & 0170000 : 0;
  if (mode != 0100000 && mode != 0040000
      && (mode != 0120000 || !nm_inode_engine.symlink_ops || !nm_plain_symlink_source(inode)))
    return ERR_PTR(-EOPNOTSUPP);
  struct nomount_rule* rule = nm_zalloc(sizeof(*rule));
  if (!rule)
    return ERR_PTR(-ENOMEM);
  rule->r_path = *path;
  *path = (struct nm_path){0};
  rule->refs = 1;
  rule->target_uid = uid;
  rule->uid_end = uid;
  rule->flags = mode == 0040000 ? NM_FLAG_IS_DIR : 0;
  rule->published = true;
  return rule;
}

static struct dentry* nm_lookup_backing_directory(struct inode* parent, struct dentry* dentry, unsigned int flags) {
  struct nm_inode_info* info = nm_is_directory_inode(parent) ? nm_inode_private(parent) : NULL;
  if (!info || !info->r_path.dentry)
    return ERR_PTR(-ENODEV);
  if (info->flags & NM_FLAG_OPAQUE)
    return kfunc(nm_d_splice_alias)(NULL, dentry);
  int rc = nm_wrap_dentry(dentry, true);
  if (rc)
    return ERR_PTR(rc);
  u32 uid = nm_current_fsuid();
  if (nomount_is_uid_blocked(uid))
    return kfunc(nm_d_splice_alias)(NULL, dentry);
  const struct nm_qstr* name = &((struct nm_dentry_head*)dentry)->d_name;
  struct nm_path path;
  rc = nm_lookup_backing_child(parent, &info->r_path, name, &path);
  if (rc == -ENOENT)
    return kfunc(nm_d_splice_alias)(NULL, dentry);
  if (rc)
    return ERR_PTR(rc);
  struct nomount_rule* rule = nm_take_backing_child_rule(&path, uid);
  if (IS_ERR(rule)) {
    kfunc(nm_path_put)(&path);
    return (void*)rule;
  }
  rule->inherited_child = true;
  u64 number = nm_name_hash((const void*)(uintptr_t)nm_inode_number(parent), name->name, name->len);
  struct nm_directory_node* node = NULL;
  struct dentry* result;
  if (rule->flags & NM_FLAG_IS_DIR) {
    node = nm_new_directory_node();
    result = node ? nm_materialize_virtual_directory(parent, dentry, rule, node, number) : ERR_PTR(-ENOMEM);
  } else if ((nm_inode_mode(nm_dentry_inode(rule->r_path.dentry)) & 0170000) == 0120000) {
    result = nm_materialize_symlink(parent, dentry, rule, number);
  } else {
    result = nm_materialize_file(parent, dentry, rule, number);
  }
  nm_directory_node_put(node);
  nm_rule_put(rule);
  // revalidate 每次回源；仅绑定和状态未变的普通文件/目录可以保留原对象。
  return result;
}

static int nm_revalidate_backing_child(struct inode* parent, struct inode* inode, const struct nm_qstr* name) {
  const struct nm_inode_info* parent_info = nm_inode_private(parent);
  const struct nm_inode_info* info = nm_inode_private(inode);
  bool directory = nm_is_directory_inode(inode);
  if (!parent_info || !info || !info->r_path.mnt || !info->r_path.dentry || (!directory && !nm_is_file_inode(inode)))
    return 0;  // 本里程碑不复用链接或负项。
  struct nm_path path;
  int rc = nm_lookup_backing_child(parent, &parent_info->r_path, name, &path);
  if (rc)
    return rc == -ENOENT ? 0 : rc;
  struct inode* source = nm_dentry_inode(path.dentry);
  u16 expected = directory ? NM_FLAG_IS_DIR : 0;
  if (path.mnt != info->r_path.mnt || path.dentry != info->r_path.dentry || !source
      || (nm_inode_mode(source) & 0170000) != (directory ? 0040000 : 0100000)
      || (directory ? !info->dir_node : nm_inode_mapping(inode) != nm_inode_mapping(source))) {
    kfunc(nm_path_put)(&path);
    return 0;
  }
  struct nm_security_context context;
  rc = nm_get_security_context(source, &context);
  if (!rc) {
    // 不刷新存活 inode 的权限/标签/大小快照；变化时由 VFS 失效后重新物化。
    const struct nm_inode_size_times* cached = (void*)((uintptr_t)inode + struct_offset.inode_size);
    const struct nm_inode_size_times* real = (void*)((uintptr_t)source + struct_offset.inode_size);
    rc = nm_inode_matches_binding(inode, &path, directory ? info->dir_node : NULL, expected, context.secid)
         && !memcmp(cached, real, sizeof(*cached))
         && *(const u64*)((uintptr_t)inode + struct_offset.inode_blocks)
                == *(const u64*)((uintptr_t)source + struct_offset.inode_blocks)
         && (!directory || nm_inode_nlink(inode) == nm_inode_nlink(source));
    nm_release_security_context(&context);
  }
  kfunc(nm_path_put)(&path);
  return rc;
}

static int nm_iterate_backing_view(struct file* file, struct nm_dir_context* context, void* node) {
  return nm_backing_directory_iterate(file, context, node);
}

// 初始化阶段调用，尚未安装任何目录视图；依赖全齐后才开放拓扑中的 backing 目录规则。
static int nm_prepare_backing_inode_engine(void) {
  if (!nm_inode_engine.file_ops || !nm_inode_engine.directory_ops || !nm_virtual_directory_fops || !nm_owned_dentry_ops)
    return -ENODEV;
  if (nm_inode_engine.lookup_backing)
    return -EALREADY;
  int rc = nm_prepare_backing_directory_functions();
  if (!rc)
    rc = nm_prepare_backing_inode_functions();
#ifndef CONFIG_KPM_BASELINES
  if (!rc) {
    bool unavailable = false;
    rc = calculate_btf_file_write(&unavailable);
    if (rc == -ENODATA && unavailable)
      rc = 0;  // 与已核对共同read_iter/write_iter声明共用；有效BTF冲突不能回退。
  }
#endif
  if (rc)
    return rc;
#ifndef CONFIG_KPM_BASELINES
  rc = nm_install_owned_permissions();
  if (rc)
    nm_log_info("permission: source DAC delegation unavailable (%d); retaining existing core capability\n", rc);
#endif
  // 此时尚未发布规则/inode，完整源权限可用后才开放普通文件写回调。
  ((struct nm_file_io_ops*)nm_inode_engine.file_ops)->write_iter = nm_write_iter;
  nm_backing_write_open_permission = nm_backing_write_permission;
  nm_backing_open_permission = nm_backing_read_permission;
  nm_inode_engine.iterate_backing = nm_iterate_backing_view;
  nm_inode_engine.seek_backing = nm_backing_directory_llseek;
  nm_inode_engine.lookup_backing = nm_lookup_backing_directory;
  nm_inode_engine.revalidate_backing = nm_revalidate_backing_child;
  return 0;
}
