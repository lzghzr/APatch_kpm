/* SPDX-License-Identifier: GPL-2.0-only */
/* Base port: maxsteeel/nomount 1ded61dc908c511072162fa0bee44e6ccdb7b4c7.
 * Child lookup and UID prefilter: 7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3. */
#ifndef __NM_RULES_H
#define __NM_RULES_H

#include "nm_structs.h"

#define NM_FLAG_IS_DIR (1U << 0)
#define NM_FLAG_VIRTUAL_DIR (1U << 1)
#define NM_FLAG_WHITEOUT (1U << 2)

struct nm_directory_node;

struct nomount_rule {
  struct nm_path r_path;
  u32 refs;
  u32 target_uid;
  u16 r_len;
  u16 flags;
  bool published;
  bool inherit_backing;  // 仅自动父目录／保留目录使用，不来自控制协议。
  struct nomount_rule* next;
  char paths[];
};

struct nm_inode_info {
  struct nm_path r_path;
  void* dir_node;
  u16 flags;
  u32 secid;
  int init_error;
  bool initialized;
  struct rcu_head rcu;
};

struct nm_rule_updates {
  struct nomount_rule* rules;
};

struct nm_rule_array {
  struct rcu_head rcu;
  u32 count;
  struct nomount_rule* rules[];
};

struct nomount_leaf {
  struct nm_rule_array* rules;
  struct nm_directory_node* this_dir;
  u64 v_ino;
  u16 v_len;
  u16 child_len;
  char paths[];
};

struct nm_child {
  u32 hash;
  u32 bloom_hash;
  struct nomount_leaf* leaf;
};

struct nomount_child_array {
  struct rcu_head rcu;
  u32 count;
  u32 bloom_words;
  u64 bloom[];
};

struct nm_uid_array {
  struct rcu_head rcu;
  u32 count;
  u64 bloom_mask[4];
  u32 uids[];
};

// 修改者持有规则管理锁，且在进程上下文调用；读者持有原生 RCU 读锁。
// 容器指针采用 acquire/release 发布。叶节点由后续拓扑层管理生命周期。
#define nm_rules_load(pointer) __atomic_load_n(&(pointer), __ATOMIC_ACQUIRE)
#define nm_rules_publish(pointer, value) __atomic_store_n(&(pointer), (value), __ATOMIC_RELEASE)

#endif
