/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nm_inode_entry.c"

// 已初始化的 KP current/cred 布局。
#include "nm_current.c"

// 私有子项视图。
#include "nm_directory_nodes.c"

// 原生父目录回调。
#include "nm_directory.c"

// 纯虚拟目录 inode 与回调。
#include "nm_virtual_directory.c"

// 仅用于初始化失败：操作表尚未安装到原生对象，不能用于已发布视图的撤销。
static void nm_discard_directory_view(void) {
  nm_discard_operations(nm_inode_engine.inode_ops);
  nm_discard_operations(nm_inode_engine.file_ops);
  nm_discard_operations((void*)nm_inode_engine.directory_ops);
  nm_discard_operations(nm_virtual_directory_fops);
  nm_discard_operations(nm_owned_dentry_ops);
  nm_virtual_directory_fops = NULL;
  nm_owned_dentry_ops = NULL;
  nm_inode_engine = (struct nm_inode_engine){0};
}

int nm_prepare_directory_view(void) {
  int rc = nm_prepare_materialization();
  if (rc)
    return rc;
  rc = nm_prepare_directory_engine();
  if (!rc)
    rc = nm_prepare_virtual_directory_engine();
  if (rc) {
    // 此处尚未发布 inode/目录回调，释放本次准备的私有表。
    nm_discard_directory_view();
  }
  return rc;
}
struct nm_directory_node* nm_create_directory_view(void) { return nm_new_directory_node(); }
int nm_attach_directory_view(struct inode* parent, struct nm_directory_node* node) {
  return nm_install_directory(parent, node);
}
void nm_drop_directory_view(struct nm_directory_node* node) { nm_directory_node_put(node); }
