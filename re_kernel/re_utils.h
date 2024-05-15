/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <hook.h>
#include <ksyms.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/asm-generic/errno.h>

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
  (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_ADD_64 0x91000000u
#define INST_ADD_64_Rn_X0 0x91000000u
#define INST_ADD_64_Rn_X19_Rd_X0 0x91000260u
#define INST_ADD_64_Rd_X0 0x91000000u
#define INST_ADD_64_Rd_X1 0x91000001u
#define INST_LDR_32_ 0xB9400000u
#define INST_LDR_32_X0 0xB9400000u
#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_X0 0xF9400000u
#define INST_LDR_64_SP 0xF94003E0u
#define INST_LDRB 0x39400000u
#define INST_LDRB_X0 0x39400000u
#define INST_LDRH 0x79400000u
#define INST_STR_32_x0 0xB9000000u
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000u
#define INST_TBNZ 0x37000000u
#define INST_TBNZ_5 0x37280000u

#define MASK_ADD_64 0xFF800000u
#define MASK_ADD_64_Rn_X0 0xFF8003E0u
#define MASK_ADD_64_Rn_X19_Rd_X0 0xFF8003FFu
#define MASK_ADD_64_Rd_X0 0xFF80001Fu
#define MASK_ADD_64_Rd_X1 0xFF80001Fu
#define MASK_LDR_32_ 0xFFC00000u
#define MASK_LDR_32_X0 0xFFC003E0u
#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_X0 0xFFC003E0u
#define MASK_LDR_64_SP 0xFFC003E0u
#define MASK_LDRB 0xFFC00000u
#define MASK_LDRB_X0 0xFFC003E0u
#define MASK_LDRH 0xFFC00000u
#define MASK_STR_32_x0 0xFFC003E0u
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_TBNZ_5 0xFFF80000u

#define ARM64_RET 0xD65F03C0

#define lookup_name(func)                                  \
  func = 0;                                                \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
  {                                                        \
    return -21;                                            \
  }

#define hook_func(func, argv, before, after, udata)                         \
  if (!func)                                                                \
  {                                                                         \
    return -22;                                                             \
  }                                                                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func)                                                      \
  {                                                                         \
    func = 0;                                                               \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  }                                                                         \
  else                                                                      \
  {                                                                         \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)            \
  if (func && !is_bad_address(func)) \
  {                                  \
    unhook(func);                    \
    func = 0;                        \
  }


#define __task_cred(task)	rcu_dereference((task)->real_cred)

#define task_uid(task) task_real_uid(task)
  // ({                                                                                               \
  //   struct cred __rcu *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
  //   kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                         \
  //   ___val;                                                                                        \
  // })

#define task_real_uid(task)                                                                             \
  ({                                                                                                    \
    struct cred __rcu *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                              \
    ___val;                                                                                             \
  })

extern bool kfunc_def(freezing_slow_path)(struct task_struct* p);
static inline bool freezing_slow_path(struct task_struct* p)
{
  kfunc_call(freezing_slow_path, p);
  kfunc_not_found();
  return false;
}

extern bool kfunc_def(cgroup_freezing)(struct task_struct* task);
static inline bool cgroup_freezing(struct task_struct* task)
{
  kfunc_call(cgroup_freezing, task);
  kfunc_not_found();
  return false;
}

extern struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
static inline struct sk_buff* alloc_skb(unsigned int size, gfp_t priority)
{
  kfunc_call(__alloc_skb, size, priority, 0, NUMA_NO_NODE);
  kfunc_not_found();
  return NULL;
}

static inline int nlmsg_msg_size(int payload)
{
  return NLMSG_HDRLEN + payload;
}

static inline int nlmsg_total_size(int payload)
{
  return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

static inline void* nlmsg_data(const struct nlmsghdr* nlh)
{
  return (unsigned char*)nlh + NLMSG_HDRLEN;
}

static inline struct sk_buff* nlmsg_new(size_t payload, gfp_t flags)
{
  return alloc_skb(nlmsg_total_size(payload), flags);
}

extern struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
static inline struct nlmsghdr* nlmsg_put(struct sk_buff* skb, u32 portid, u32 seq, int type, int payload, int flags)
{
  kfunc_call(__nlmsg_put, skb, portid, seq, type, payload, flags);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(kfree_skb)(struct sk_buff* skb);
static inline void nlmsg_free(struct sk_buff* skb)
{
  kfunc_call(kfree_skb, skb);
  kfunc_not_found();
}

extern int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
static inline int netlink_unicast(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock)
{
  kfunc_call(netlink_unicast, ssk, skb, portid, nonblock);
  kfunc_not_found();
  return -ESRCH;
}

extern struct sock* kfunc_def(__netlink_kernel_create)(struct net* net, int unit, struct module* module, struct netlink_kernel_cfg* cfg);
static inline struct sock* netlink_kernel_create(struct net* net, int unit, struct netlink_kernel_cfg* cfg)
{
  kfunc_call(__netlink_kernel_create, net, unit, THIS_MODULE, cfg);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(netlink_kernel_release)(struct sock* sk);
static inline void netlink_kernel_release(struct sock* sk)
{
  kfunc_call(netlink_kernel_release, sk);
  kfunc_not_found();
}

extern struct proc_dir_entry* kfunc_def(proc_mkdir)(const char* name, struct proc_dir_entry* parent);
static inline struct proc_dir_entry* proc_mkdir(const char* name, struct proc_dir_entry* parent)
{
  kfunc_call(proc_mkdir, name, parent);
  kfunc_not_found();
  return NULL;
}

extern struct proc_dir_entry* kfunc_def(proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops, void* data);
static inline struct proc_dir_entry* proc_create(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops)
{
  kfunc_call(proc_create_data, name, mode, parent, proc_fops, NULL);
  kfunc_not_found();
  return NULL;
}

extern void kfunc_def(proc_remove)(struct proc_dir_entry* de);
static inline void proc_remove(struct proc_dir_entry* de)
{
  kfunc_call(proc_remove, de);
  kfunc_not_found();
}

extern void kfunc_def(seq_printf)(struct seq_file* m, const char* f, ...);
static inline void seq_printf(struct seq_file* m, const char* f, ...) {
  va_list args;
  va_start(args, f);
  kfunc(seq_printf)(m, f, args);
  va_end(args);
}

extern int kfunc_def(single_open)(struct file* file, int (*show)(struct seq_file*, void*), void* data);
static inline int single_open(struct file* file, int (*show)(struct seq_file*, void*), void* data) {
  kfunc_call(single_open, file, show, data);
  kfunc_not_found();
  return -ESRCH;
}

extern int kfunc_def(get_cmdline)(struct task_struct* task, char* buffer, int buflen);
static inline int get_cmdline(struct task_struct* task, char* buffer, int buflen) {
  kfunc_call(get_cmdline, task, buffer, buflen);
  kfunc_not_found();
  return -ESRCH;
}


#endif /* __RE_UTILS_H */
