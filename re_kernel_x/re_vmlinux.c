#include "vmlinux.h"

extern int printf(const char*, ...);
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE*)0)->MEMBER)

// 复用 sk_buff 与 Netlink 凭据的共同前缀，目标头文件不符合时停止生成。
_Static_assert(offsetof(struct sk_buff, sk) == 0x18 && offsetof(struct sk_buff, cb) == 0x28,
               "sk_buff common prefix changed");
_Static_assert(sizeof(((struct sk_buff*)0)->cb) == 48
                   && sizeof(struct netlink_skb_parms) <= sizeof(((struct sk_buff*)0)->cb),
               "netlink control buffer size changed");
_Static_assert(offsetof(struct netlink_skb_parms, creds) == 0 && offsetof(struct scm_creds, uid) == 4
                   && sizeof(((struct scm_creds*)0)->uid) == sizeof(unsigned int),
               "netlink sender credentials layout changed");

// 共同配置段由目标头文件核对；布局不符合时生成器直接报错。
_Static_assert(sizeof(struct genl_family) <= 0x400, "genl_family storage too small");
_Static_assert(sizeof(struct genl_multicast_group) <= 0x40, "genl_multicast_group storage too small");
_Static_assert(offsetof(struct genl_family, name) == offsetof(struct genl_family, hdrsize) + sizeof(unsigned int),
               "genl_family config name layout changed");
_Static_assert(sizeof(((struct genl_family*)0)->name) == 16, "genl_family name size changed");
_Static_assert(offsetof(struct genl_family, version)
                   == offsetof(struct genl_family, name) + sizeof(((struct genl_family*)0)->name),
               "genl_family config version layout changed");
_Static_assert(offsetof(struct genl_family, maxattr) == offsetof(struct genl_family, version) + sizeof(unsigned int),
               "genl_family config maxattr layout changed");
_Static_assert(sizeof(((struct genl_family*)0)->hdrsize) == sizeof(unsigned int)
                   && sizeof(((struct genl_family*)0)->version) == sizeof(unsigned int)
                   && sizeof(((struct genl_family*)0)->maxattr) == sizeof(unsigned int),
               "genl_family config field width changed");
_Static_assert(offsetof(struct genl_multicast_group, name) == 0
                   && sizeof(((struct genl_multicast_group*)0)->name) == 16,
               "genl_multicast_group name layout changed");
_Static_assert(sizeof(((struct genl_family*)0)->n_mcgrps) == 1 || sizeof(((struct genl_family*)0)->n_mcgrps) == 2
                   || sizeof(((struct genl_family*)0)->n_mcgrps) == sizeof(unsigned int),
               "genl_family n_mcgrps width unsupported");

// 仅有目标头文件确认 data 为内核映射指针时启用；user_data 不能直接解引用。
#ifdef REKERNEL_BINDER_KERNEL_DATA
#define BINDER_BUFFER_DATA_OFFSET offsetof(struct binder_buffer, data)
#else
#define BINDER_BUFFER_DATA_OFFSET (-1L)
#endif

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
    .sk_buff_len = 0x%lx,\n\
    .sk_buff_transport_header = 0x%lx,\n\
    .sk_buff_network_header = 0x%lx,\n\
    .sk_buff_tail = 0x%lx,\n\
    .sk_buff_head = 0x%lx,\n\
    .sk_buff_data = 0x%lx,\n\
    .net_genl_sock = 0x%lx,\n\
    .genl_family_id = 0x%lx,\n\
    .genl_family_config = 0x%lx,\n\
    .genl_family_mcgrps = 0x%lx,\n\
    .genl_family_n_mcgrps = 0x%lx,\n\
    .genl_family_n_mcgrps_size = 0x%lx,\n\
    .genl_family_mcgrp_offset = 0x%lx,\n\
    .task_struct_cred = 0x%lx,\n\
    .cred_uid = 0x%lx,\n\
    .task_struct_comm = 0x%lx,\n\
    .sock_sk_net = 0x%lx,\n\
    .binder_proc_is_dead = 0x%lx,\n\
    .binder_buffer_data = %ld,\n\
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
      offsetof(struct task_struct, pid), offsetof(struct task_struct, tgid), offsetof(struct sk_buff, len),
      offsetof(struct sk_buff, transport_header), offsetof(struct sk_buff, network_header),
      offsetof(struct sk_buff, tail), offsetof(struct sk_buff, head), offsetof(struct sk_buff, data),
      offsetof(struct net, genl_sock), offsetof(struct genl_family, id), offsetof(struct genl_family, hdrsize),
      offsetof(struct genl_family, mcgrps), offsetof(struct genl_family, n_mcgrps),
      sizeof(((struct genl_family*)0)->n_mcgrps), offsetof(struct genl_family, mcgrp_offset),
      offsetof(struct task_struct, cred), offsetof(struct cred, uid), offsetof(struct task_struct, comm),
      offsetof(struct sock, __sk_common.skc_net.net), offsetof(struct binder_proc, is_dead), BINDER_BUFFER_DATA_OFFSET);

  return 0;
}
