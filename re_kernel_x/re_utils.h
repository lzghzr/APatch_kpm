/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <uapi/asm-generic/errno.h>

#define logkm(fmt, ...) printk("[ReKernel-X] " fmt, ##__VA_ARGS__)

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
static inline unsigned char* skb_tail_pointer(const struct sk_buff* skb) {
  return sk_buff_head(skb) + sk_buff_tail(skb);
}
static inline unsigned char* skb_transport_header(const struct sk_buff* skb) {
  return sk_buff_head(skb) + sk_buff_transport_header(skb);
}
static inline int skb_transport_offset(const struct sk_buff* skb) {
  return skb_transport_header(skb) - sk_buff_data(skb);
}

static inline int nlmsg_msg_size(int payload) { return NLMSG_HDRLEN + payload; }
static inline int nlmsg_total_size(int payload) { return NLMSG_ALIGN(nlmsg_msg_size(payload)); }
static inline int nlmsg_padlen(int payload) { return nlmsg_total_size(payload) - nlmsg_msg_size(payload); }
static inline void* nlmsg_data(const struct nlmsghdr* nlh) { return (unsigned char*)nlh + NLMSG_HDRLEN; }
static inline int nlmsg_len(const struct nlmsghdr* nlh) { return nlh->nlmsg_len - NLMSG_HDRLEN; }

static inline struct sk_buff* nlmsg_new(size_t payload, gfp_t flags) {
  return alloc_skb(nlmsg_total_size(payload), flags);
}

extern struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
static inline struct nlmsghdr* nlmsg_put(struct sk_buff* skb, u32 portid, u32 seq, int type, int payload, int flags) {
  kfunc_call(__nlmsg_put, skb, portid, seq, type, payload, flags);
  kfunc_not_found();
  return NULL;
}

static inline void* nla_data(const struct nlattr* nla) { return (char*)nla + NLA_HDRLEN; }
static inline int nla_len(const struct nlattr* nla) { return nla->nla_len - NLA_HDRLEN; }
static inline int nla_total_size(int payload) { return NLA_ALIGN(NLA_HDRLEN + payload); }
extern int kfunc_def(nla_put)(struct sk_buff* skb, int attrtype, int attrlen, const void* data);
static inline int nla_put_s32(struct sk_buff* skb, int attrtype, s32 value) {
  kfunc_call(nla_put, skb, attrtype, sizeof(value), &value);
  kfunc_not_found();
  return -EFAULT;
}
static inline int nla_put_string(struct sk_buff* skb, int attrtype, const char* value) {
  kfunc_call(nla_put, skb, attrtype, strlen(value) + 1, value);
  kfunc_not_found();
  return -EFAULT;
}
static inline struct nlattr* nla_nest_start(struct sk_buff* skb, int attrtype) {
  struct nlattr* start = (struct nlattr*)skb_tail_pointer(skb);
  if (kf_nla_put && !kf_nla_put(skb, attrtype | NLA_F_NESTED, 0, NULL))
    return start;
  return NULL;
}
static inline void nla_nest_end(struct sk_buff* skb, struct nlattr* start) {
  start->nla_len = skb_tail_pointer(skb) - (unsigned char*)start;
}

static inline void nlmsg_end(struct sk_buff* skb, struct nlmsghdr* nlh) {
  nlh->nlmsg_len = skb_tail_pointer(skb) - (unsigned char*)nlh;
}
extern void kfunc_def(skb_trim)(struct sk_buff* skb, unsigned int len);
static inline void nlmsg_trim(struct sk_buff* skb, const void* mark) {
  if (mark && (unsigned char*)mark >= sk_buff_data(skb)) {
    kfunc_call_void(skb_trim, skb, (unsigned char*)mark - sk_buff_data(skb));
  }
}
static inline void nlmsg_cancel(struct sk_buff* skb, struct nlmsghdr* nlh) { nlmsg_trim(skb, nlh); }

extern void kfunc_def(kfree_skb)(struct sk_buff* skb);
static inline void nlmsg_free(struct sk_buff* skb) { kfunc_call_void(kfree_skb, skb); }

static inline int genlmsg_msg_size(int payload) { return GENL_HDRLEN + payload; }
static inline int genlmsg_total_size(int payload) { return NLMSG_ALIGN(genlmsg_msg_size(payload)); }

static inline struct sk_buff* genlmsg_new(size_t payload, gfp_t flags) {
  return nlmsg_new(genlmsg_total_size(payload), flags);
}
static inline void genlmsg_end(struct sk_buff* skb, void* hdr) { nlmsg_end(skb, hdr - GENL_HDRLEN - NLMSG_HDRLEN); }
static inline void genlmsg_cancel(struct sk_buff* skb, void* hdr) {
  if (hdr)
    nlmsg_cancel(skb, hdr - GENL_HDRLEN - NLMSG_HDRLEN);
}
extern int kfunc_def(netlink_broadcast)(struct sock* ssk, struct sk_buff* skb, u32 portid, u32 group, gfp_t allocation);
static inline int nlmsg_multicast(struct sock* sk, struct sk_buff* skb, u32 portid, unsigned int group, gfp_t flags) {
  kfunc_call(netlink_broadcast, sk, skb, portid, group, flags);
  kfunc_not_found();
  nlmsg_free(skb);
  return -EFAULT;
}
static inline int genlmsg_multicast_netns(const struct genl_family* family, struct net* net, struct sk_buff* skb,
                                          u32 portid, unsigned int group, gfp_t flags) {
  if (group >= genl_family_n_mcgrps(family)) {
    nlmsg_free(skb);
    return -EINVAL;
  }
  group = genl_family_mcgrp_offset(family) + group;
  return nlmsg_multicast(net_genl_sock(net), skb, portid, group, flags);
}
static struct net kvar_def(init_net);
static inline int genlmsg_multicast(const struct genl_family* family, struct sk_buff* skb, u32 portid,
                                    unsigned int group, gfp_t flags) {
  return genlmsg_multicast_netns(family, kvar(init_net), skb, portid, group, flags);
}

extern int kfunc_def(genl_register_family)(struct genl_family* family);
extern int kfunc_def(__genl_register_family)(struct genl_family* family);
static inline int genl_register_family(struct genl_family* family) {
  kfunc_call(genl_register_family, family);
  kfunc_call(__genl_register_family, family);
  kfunc_not_found();
  return -EFAULT;
}
extern int kfunc_def(genl_unregister_family)(const struct genl_family* family);
static inline int genl_unregister_family(const struct genl_family* family) {
  kfunc_call(genl_unregister_family, family);
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
