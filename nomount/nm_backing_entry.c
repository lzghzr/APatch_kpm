/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nm_topology_entry.c"

// backing 封装使用上面的布局、规则和目录实现，保持编译顺序。
#include "nm_backing_directory.c"

// 目录物化与 backing 回调在上述共同实现之后准备。
#include "nm_backing_inode.c"

// 自动父目录和源搜索权限在完整 backing 引擎之后接入。
#include "nm_backing_subtree.c"

int nm_prepare_backing_queries(void) {
  if (nm_inode_engine.inode_ops)
    return -EALREADY;
  int rc = nm_prepare_path_rules();
  if (!rc)
    rc = nm_prepare_backing_inode_engine();
  if (!rc)
    rc = nm_prepare_backing_subtrees();
  if (rc) {
    nm_topology_ready = false;
    nm_backing_open_permission = NULL;
    nm_discard_directory_view();
  }
  return rc;
}

// 对象阶段入口；控制层尚未注册。
int nm_query_backing_child(struct inode* outer, const struct nm_path* base, const struct nm_qstr* name,
                           struct nm_path* result) {
  return nm_lookup_backing_child(outer, base, name, result);
}
int nm_enumerate_backing_directory(struct file* file, struct nm_dir_context* context, struct nm_directory_node* node) {
  return nm_backing_directory_iterate(file, context, node);
}
int64_t nm_seek_backing_directory(struct file* file, int64_t offset, int whence) {
  return nm_backing_directory_llseek(file, offset, whence);
}
