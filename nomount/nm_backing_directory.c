/* SPDX-License-Identifier: GPL-2.0-only */
/* Native backing-path lookup and merged directory enumeration. */
struct vfsmount;
static int kfunc_def(nm_vfs_path_lookup)(struct dentry*, struct vfsmount*, const char*, unsigned int, struct nm_path*);

static int nm_prepare_backing_directory_functions(void) {
#ifndef CONFIG_KPM_BASELINES
  int rc = nm_prepare_backing_directory_abi();
  if (rc)
    return rc;
#endif
  kfunc(nm_vfs_path_lookup) = (typeof(kfunc(nm_vfs_path_lookup)))kallsyms_lookup_name_by_suffix("vfs_path_lookup");
  return kfunc(nm_vfs_path_lookup) ? 0 : -ENOENT;
}

// 不将 outer dentry 交给 backing 的 lookup。调用者持 base path，成功接收一份完整 path 引用。
// 进程上下文、无模块 RCU/管理锁；flags=0 保留最终 symlink，交给后续物化层决定支持的类型。
static int nm_lookup_backing_child(struct inode* outer, const struct nm_path* base, const struct nm_qstr* name,
                                   struct nm_path* result) {
  if (!result || result == base)
    return -EINVAL;
  *result = (struct nm_path){0};
  if (!outer || !base || !base->mnt || !base->dentry || !name || !name->name || !name->len || name->len > 255)
    return -EINVAL;
  if ((name->len == 1 && name->name[0] == '.') || (name->len == 2 && name->name[0] == '.' && name->name[1] == '.'))
    return -EINVAL;
  char component[256];
  for (unsigned int i = 0; i < name->len; i++) {
    if (!name->name[i] || name->name[i] == '/')
      return -EINVAL;
    component[i] = name->name[i];
  }
  component[name->len] = 0;
  struct inode* backing = nm_dentry_inode(base->dentry);
  if (!backing || (nm_inode_mode(backing) & 0170000) != 0040000)
    return -ENOTDIR;
  const struct nm_inode_lookup_ops* operations = nm_inode_ops(backing);
  if (backing == outer || nm_is_virtual_inode(backing) || (operations && operations->lookup == nm_directory_lookup))
    return -ELOOP;
  struct nm_path child = {0};
  int rc = kfunc(nm_vfs_path_lookup)(base->dentry, base->mnt, component, 0, &child);
  if (rc)
    return rc;
  struct inode* inode = child.dentry ? nm_dentry_inode(child.dentry) : NULL;
  if (!inode) {
    rc = -ENOENT;
  } else {
    operations = nm_inode_ops(inode);
    if (inode == outer || nm_is_virtual_inode(inode) || (operations && operations->lookup == nm_directory_lookup))
      rc = -ELOOP;
  }
  if (rc) {
    kfunc(nm_path_put)(&child);
    return rc;
  }
  *result = child;
  return 0;
}

struct nm_backing_directory_actor {
  struct nm_directory_actor filter;
  u64 self_number;
  u64 parent_number;
};

static int nm_backing_directory_filter(struct nm_dir_context* context, const char* name, int length, int64_t offset,
                                       u64 number, unsigned int type) {
  struct nm_backing_directory_actor* actor = (void*)context;
  if (length == 1 && name[0] == '.')
    number = actor->self_number;
  else if (length == 2 && name[0] == '.' && name[1] == '.')
    number = actor->parent_number;
  return nm_directory_filter(context, name, length, offset, number, type);
}
static bool nm_backing_directory_filter_bool(struct nm_dir_context* context, const char* name, int length,
                                             int64_t offset, u64 number, unsigned int type) {
  return nm_backing_directory_filter(context, name, length, offset, number, type) == 0;
}

static int nm_backing_directory_file_status(struct file* file, struct file* backing) {
  if (!file || !backing)
    return -EINVAL;
  struct inode* inode = nm_file_inode(file);
  struct inode* backing_inode = nm_file_inode(backing);
  if (!inode || !backing_inode || (nm_inode_mode(backing_inode) & 0170000) != 0040000)
    return -ENOTDIR;
  const struct nm_inode_lookup_ops* operations = nm_inode_ops(backing_inode);
  // open 可在 i_fop 已发布而 i_op 尚未发布时保存模块表，故同时核对 file 自己持有的表。
  const void* file_ops = nm_file_ops(backing);
  return inode == backing_inode || nm_is_virtual_inode(backing_inode)
                 || (operations && operations->lookup == nm_directory_lookup)
                 || (nm_virtual_directory_fops && file_ops == nm_virtual_directory_fops)
                 || nm_directory_file_proxy(file_ops)
             ? -ELOOP
             : 0;
}

// 调用者持 node 引用及已打开的 outer file；private_data 中的 backing file 由 open/release 持有。
static int nm_backing_directory_iterate(struct file* file, struct nm_dir_context* context,
                                        struct nm_directory_node* node) {
  struct file* backing = file ? nm_file_private(file) : NULL;
  if (!backing || !context || !node)
    return -EINVAL;
  if (context->pos < 0)
    return -EINVAL;
  int status = nm_backing_directory_file_status(file, backing);
  if (status)
    return status;
  struct inode* inode = nm_file_inode(file);
  u32 uid = nm_current_fsuid();
  bool compat = nm_current_compat(), blocked = nomount_is_uid_blocked(uid);
  if (nm_virtual_position(context->pos, compat))
    return blocked ? 0 : nm_emit_children(node, context, uid, compat);
  struct dentry* parent = kfunc(nm_dget_parent)(nm_file_path(file)->dentry);
  struct inode* parent_inode = nm_dentry_inode(parent);
  struct nm_backing_directory_actor actor = {
      .filter = {.context = {.actor = nm_backing_directory_filter, .pos = context->pos},
                 .outer = context,
                 .node = blocked ? NULL : node,
                 .uid = uid},
      .self_number = nm_inode_number(inode),
      .parent_number = parent_inode ? nm_inode_number(parent_inode) : nm_inode_number(inode)};
  if (struct_offset.dir_actor_abi == 1)
    actor.filter.context.actor_bool = nm_backing_directory_filter_bool;
  kfunc(nm_dput)(parent);
  int rc = nm_iterate_backing(file, backing, &actor.filter.context);
  context->pos = actor.filter.context.pos;
  if (rc >= 0 && !actor.filter.emitted && !blocked)
    rc = nm_emit_children(node, context, uid, compat);
  return rc;
}

static int64_t nm_backing_directory_llseek(struct file* file, int64_t offset, int whence) {
  struct file* backing = file ? nm_file_private(file) : NULL;
  int status = nm_backing_directory_file_status(file, backing);
  if (status)
    return status;
  bool compat = nm_current_compat();
  if (whence == 0 && nm_virtual_position(offset, compat))
    return kfunc(nm_vfs_setpos)(file, offset, 0x7fffffffffffffffLL);
  if (whence == 1 && !offset && nm_virtual_position(*nm_file_position(file), compat))
    return *nm_file_position(file);
  return nm_llseek(file, offset, whence);
}
