/* SPDX-License-Identifier: GPL-2.0-only */
/* Managed automatic directories inherit the selected parent view at lookup time. */
static struct nomount_rule* nm_inherit_backing_directory(struct inode* parent, struct dentry* dentry) {
  struct nm_inode_info* info = nm_is_directory_inode(parent) ? nm_inode_private(parent) : NULL;
  if (!info || !info->r_path.dentry)
    return NULL;
  const struct nm_qstr* name = &((struct nm_dentry_head*)dentry)->d_name;
  struct nm_path path;
  int rc = nm_lookup_backing_child(parent, &info->r_path, name, &path);
  if (rc == -ENOENT)
    return NULL;
  if (rc)
    return ERR_PTR(rc);
  struct inode* inode = nm_dentry_inode(path.dentry);
  if (!inode || (nm_inode_mode(inode) & 0170000) != 0040000) {
    kfunc(nm_path_put)(&path);
    return ERR_PTR(-ENOTDIR);
  }
  struct nomount_rule* rule = nm_take_backing_child_rule(&path, nm_current_fsuid());
  if (IS_ERR(rule))
    kfunc(nm_path_put)(&path);
  return rule;
}

static int nm_check_backing_directory_search(struct inode* parent) {
  struct nm_inode_info* info = nm_inode_private(parent);
  if (!info)
    return -ENODEV;
  const struct nm_path* path = &info->r_path;
  if (!path->dentry)
    return 0;
  struct inode* inode = nm_dentry_inode(path->dentry);
  if (!inode || !path->mnt)
    return -ENOENT;
  return nm_backing_permission(path, 1);  // MAY_EXEC，目标 fs.h。
}

// 完整入口在安装视图／注册控制前必须接入此层；前面的对象准备可分别用于分段开发。
static int nm_prepare_backing_subtrees(void) {
  if (!nm_inode_engine.lookup_backing || !nm_permission_ready())
    return -ENODEV;
  if (nm_inode_engine.inherit_directory || nm_inode_engine.check_directory_search)
    return -EALREADY;
  nm_inode_engine.inherit_directory = nm_inherit_backing_directory;
  nm_inode_engine.check_directory_search = nm_check_backing_directory_search;
  return 0;
}
