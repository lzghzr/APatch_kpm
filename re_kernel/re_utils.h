/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <uapi/asm-generic/errno.h>

#define logkm(fmt, ...) printk("re_kernel: " fmt, ##__VA_ARGS__)

struct struct_offset {
  int16_t binder_alloc_buffer_size;
  int16_t binder_alloc_buffer;
  int16_t binder_alloc_free_async_space;
  int16_t binder_alloc_pid;
  int16_t binder_node_async_todo;
  int16_t binder_node_cookie;
  int16_t binder_node_has_async_transaction;
  int16_t binder_node_lock;
  int16_t binder_node_ptr;
  int16_t binder_proc_alloc;
  int16_t binder_proc_context;
  int16_t binder_proc_inner_lock;
  int16_t binder_proc_is_frozen;
  int16_t binder_proc_outer_lock;
  int16_t binder_proc_outstanding_txns;
  int16_t binder_stats_deleted_transaction;
  int16_t binder_transaction_buffer;
  int16_t binder_transaction_code;
  int16_t binder_transaction_flags;
  int16_t binder_transaction_from;
  int16_t binder_transaction_to_proc;
  int16_t task_struct_group_leader;
  int16_t task_struct_jobctl;
  int16_t task_struct_pid;
  int16_t task_struct_tgid;
};

extern struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
static inline struct sk_buff* alloc_skb(unsigned int size, gfp_t priority) {
  kfunc_call(__alloc_skb, size, priority, 0, NUMA_NO_NODE);
  kfunc_not_found();
  return NULL;
}

static inline int nlmsg_msg_size(int payload) { return NLMSG_HDRLEN + payload; }

static inline int nlmsg_total_size(int payload) { return NLMSG_ALIGN(nlmsg_msg_size(payload)); }

static inline void* nlmsg_data(const struct nlmsghdr* nlh) { return (unsigned char*)nlh + NLMSG_HDRLEN; }

static inline struct sk_buff* nlmsg_new(size_t payload, gfp_t flags) {
  return alloc_skb(nlmsg_total_size(payload), flags);
}

extern struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
static inline struct nlmsghdr* nlmsg_put(struct sk_buff* skb, u32 portid, u32 seq, int type, int payload, int flags) {
  kfunc_call(__nlmsg_put, skb, portid, seq, type, payload, flags);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(kfree_skb)(struct sk_buff* skb);
static inline void nlmsg_free(struct sk_buff* skb) { kfunc_call_void(kfree_skb, skb); }

extern int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
static inline int netlink_unicast(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock) {
  kfunc_call(netlink_unicast, ssk, skb, portid, nonblock);
  kfunc_not_found();
  return -EFAULT;
}

extern int kfunc_def(netlink_rcv_skb)(struct sk_buff* skb,
                                      int (*cb)(struct sk_buff*, struct nlmsghdr*, struct netlink_ext_ack*));
static inline int netlink_rcv_skb(struct sk_buff* skb,
                                  int (*cb)(struct sk_buff*, struct nlmsghdr*, struct netlink_ext_ack*)) {
  kfunc_call(netlink_rcv_skb, skb, cb);
  kfunc_not_found();
  return -EFAULT;
}

extern struct sock* kfunc_def(__netlink_kernel_create)(struct net* net, int unit, struct module* module,
                                                       struct netlink_kernel_cfg* cfg);
static inline struct sock* netlink_kernel_create(struct net* net, int unit, struct netlink_kernel_cfg* cfg) {
  kfunc_call(__netlink_kernel_create, net, unit, THIS_MODULE, cfg);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(netlink_kernel_release)(struct sock* sk);
static inline void netlink_kernel_release(struct sock* sk) { kfunc_call_void(netlink_kernel_release, sk); }

extern struct proc_dir_entry* kfunc_def(proc_mkdir)(const char* name, struct proc_dir_entry* parent);
static inline struct proc_dir_entry* proc_mkdir(const char* name, struct proc_dir_entry* parent) {
  kfunc_call(proc_mkdir, name, parent);
  kfunc_not_found();
  return NULL;
}

extern struct proc_dir_entry* kfunc_def(proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent,
                                                          const struct file_operations* proc_fops, void* data);
static inline struct proc_dir_entry* proc_create(const char* name, umode_t mode, struct proc_dir_entry* parent,
                                                 const struct file_operations* proc_fops) {
  kfunc_call(proc_create_data, name, mode, parent, proc_fops, NULL);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(proc_remove)(struct proc_dir_entry* de);
static inline void proc_remove(struct proc_dir_entry* de) { kfunc_call_void(proc_remove, de); }

extern kuid_t kfunc_def(sock_i_uid)(struct sock* sk);
static inline kuid_t sock_i_uid(struct sock* sk) {
  kfunc_call(sock_i_uid, sk);
  kfunc_not_found();
  return (kuid_t){0};
}

extern int kfunc_def(get_cmdline)(struct task_struct* task, char* buffer, int buflen);
static inline int get_cmdline(struct task_struct* task, char* buffer, int buflen) {
  kfunc_call(get_cmdline, task, buffer, buflen);
  kfunc_not_found();
  return -EFAULT;
}

extern int kfunc_def(tracepoint_probe_register)(struct tracepoint* tp, void* probe, void* data);
static inline int tracepoint_probe_register(struct tracepoint* tp, void* probe, void* data) {
  kfunc_call(tracepoint_probe_register, tp, probe, data);
  kfunc_not_found();
  return -EFAULT;
}

extern int kfunc_def(tracepoint_probe_unregister)(struct tracepoint* tp, void* probe, void* data);
static inline int tracepoint_probe_unregister(struct tracepoint* tp, void* probe, void* data) {
  kfunc_call(tracepoint_probe_unregister, tp, probe, data);
  kfunc_not_found();
  return -EFAULT;
}

#endif /* __RE_UTILS_H */
