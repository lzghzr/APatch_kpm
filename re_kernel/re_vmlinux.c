#include "vmlinux.h"

extern int printf(const char *, ...);
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)

int main() {
  printf(
      "struct struct_offset struct_offset = {\n\
    .binder_alloc_buffer_size = 0x%lx,\n\
    .binder_alloc_buffer = 0x%lx,\n\
    .binder_alloc_free_async_space = 0x%lx,\n\
    .binder_alloc_pid = 0x%lx,\n\
    .binder_node_async_todo = 0x%lx,\n\
    .binder_node_cookie = 0x%lx,\n\
    .binder_node_has_async_transaction = 0x%lx,\n\
    .binder_node_lock = 0x%lx,\n\
    .binder_node_ptr = 0x%lx,\n\
    .binder_proc_alloc = 0x%lx,\n\
    .binder_proc_context = 0x%lx,\n\
    .binder_proc_inner_lock = 0x%lx,\n\
    .binder_proc_is_frozen = 0x%lx,\n\
    .binder_proc_outer_lock = 0x%lx,\n\
    .binder_proc_outstanding_txns = 0x%lx,\n\
    .binder_stats_deleted_transaction = 0x%lx,\n\
    .binder_transaction_buffer = 0x%lx,\n\
    .binder_transaction_code = 0x%lx,\n\
    .binder_transaction_flags = 0x%lx,\n\
    .binder_transaction_from = 0x%lx,\n\
    .binder_transaction_to_proc = 0x%lx,\n\
    .task_struct_group_leader = 0x%lx,\n\
    .task_struct_jobctl = 0x%lx,\n\
    .task_struct_pid = 0x%lx,\n\
    .task_struct_tgid = 0x%lx,\n\
};\n",
      offsetof(struct binder_alloc, buffer_size), offsetof(struct binder_alloc, buffer),
      offsetof(struct binder_alloc, free_async_space), offsetof(struct binder_alloc, pid),
      offsetof(struct binder_node, async_todo), offsetof(struct binder_node, cookie),
      offsetof(struct binder_node, has_async_transaction), offsetof(struct binder_node, lock),
      offsetof(struct binder_node, ptr), offsetof(struct binder_proc, alloc), offsetof(struct binder_proc, context),
      offsetof(struct binder_proc, inner_lock), offsetof(struct binder_proc, is_frozen),
      offsetof(struct binder_proc, outer_lock), offsetof(struct binder_proc, outstanding_txns),
      offsetof(struct binder_stats, obj_deleted[BINDER_STAT_TRANSACTION]), offsetof(struct binder_transaction, buffer),
      offsetof(struct binder_transaction, code), offsetof(struct binder_transaction, flags),
      offsetof(struct binder_transaction, from), offsetof(struct binder_transaction, to_proc),
      offsetof(struct task_struct, group_leader), offsetof(struct task_struct, jobctl),
      offsetof(struct task_struct, pid), offsetof(struct task_struct, tgid));

  return 0;
}
