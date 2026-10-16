/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "nm_directory_entry.c"
#include "nm_topology.c"

int nm_prepare_path_rules(void) {
  int rc = nm_prepare_directory_view();
  return rc ? rc : nm_prepare_topology_functions();
}

// 临时编译入口。调用者持管理锁，解锁后统一完成 updates；控制层随后接入。
int nm_add_path_rule_locked(const char* path, u16 length, struct nomount_rule* rule,
                            struct nm_topology_updates* updates) {
  return nm_topology_add_locked(path, length, rule, updates);
}
int nm_delete_path_rule_locked(const char* path, u16 length, u32 uid, struct nm_topology_updates* updates) {
  return nm_topology_remove_locked(path, length, uid, updates);
}
void nm_finish_path_rule_updates(struct nm_topology_updates* updates) { nm_finish_topology_updates(updates); }
int nm_clear_path_rules_locked(struct nm_topology_updates* updates) { return nm_topology_clear_locked(updates); }
