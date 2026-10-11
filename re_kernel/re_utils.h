/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <uapi/asm-generic/errno.h>

#define logkm(fmt, ...) printk("re_kernel: " fmt, ##__VA_ARGS__)

// 模块自己的 0/1 锁，不传给内核；持锁区只操作上下文链表、UID 或清理规则数组。
static inline unsigned long rekernel_context_lock(unsigned int* lock) {
  unsigned long flags;
  asm volatile("mrs %0, daif\n\tmsr daifset, #2" : "=r"(flags) : : "memory");
  while (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE)) asm volatile("yield" : : : "memory");
  return flags;
}
static inline void rekernel_context_unlock(unsigned int* lock, unsigned long flags) {
  __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
  asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

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

extern void kfunc_def(kfree_skb)(struct sk_buff* skb);
static inline void nlmsg_free(struct sk_buff* skb) { kfunc_call_void(kfree_skb, skb); }

extern int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
static inline int netlink_unicast(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock) {
  kfunc_call(netlink_unicast, ssk, skb, portid, nonblock);
  kfunc_not_found();
  return -EFAULT;
}

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
