/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nm_backing_entry.c"

// 管理锁先于命令分派，保持编译顺序。
#include "nm_control_lock.c"

// 命令使用上述管理锁和完整backing引擎。
#include "nm_control.c"

// keyring引用命令分派，最后发布。
#include "nm_control_key.c"

int nm_prepare_control_engine(void) {
  if (nm_registered_key_type || nm_inode_engine.inode_ops)
    return -EALREADY;
  int rc = nm_prepare_backing_queries();
  if (!rc)
    rc = nm_prepare_control_layout();
  if (!rc)
    rc = nm_prepare_management_mutex();
  if (!rc)
    rc = nm_register_control();
  if (rc) {
    if (nm_management_mutex)
      nm_discard_management_mutex();
    nm_topology_ready = false;
    nm_backing_open_permission = NULL;
    nm_discard_directory_view();
  }
  return rc;
}
