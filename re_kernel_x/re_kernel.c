/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

/*   SPDX-License-Identifier: GPL-3.0-only   */
/*
 * Copyright (C) 2024 Nep-Timeline. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include "re_kernel.h"

#include <asm/atomic.h>
#include <asm/current.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../kpm_utils.h"
#include "re_offsets.c"
#include "re_utils.h"

KPM_NAME("re_kernel_x");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Nep-Timeline, lzghzr, myflavor");
KPM_DESCRIPTION("ReKernel-X, every bit belongs to you.");

static const unsigned int rekernel_binder_abi __attribute__((section(".rodata.re_abi"), used)) = REKERNEL_BINDER_ABI;

// cgroup_freezing, cgroupv1_freeze
static bool (*cgroup_freezing)(struct task_struct* task);
// send_netlink_message
struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
void* kfunc_def(genlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, const struct genl_family* family, int flags,
                             u8 cmd);
int kfunc_def(nla_put)(struct sk_buff* skb, int attrtype, int attrlen, const void* data);
void kfunc_def(skb_trim)(struct sk_buff* skb, unsigned int len);
void kfunc_def(kfree_skb)(struct sk_buff* skb);
int kfunc_def(netlink_broadcast)(struct sock* ssk, struct sk_buff* skb, u32 portid, u32 group, gfp_t allocation);
// start_rekernel_genl_server
int kfunc_def(genl_register_family)(struct genl_family* family);
int kfunc_def(__genl_register_family)(struct genl_family* family);
int kfunc_def(genl_unregister_family)(const struct genl_family* family);
// genl_rcv_msg 的前两个参数在旧、新内核上相同；extack 由内核接收流程处理。
static int (*genl_rcv_msg)(struct sk_buff* skb, struct nlmsghdr* nlh);
// hook binder_proc_transaction
static int (*binder_proc_transaction)(struct binder_transaction* t, struct binder_proc* proc,
                                      struct binder_thread* thread);
// free the outdated transaction and buffer
static void (*binder_transaction_buffer_release)(struct binder_proc* proc
#if REKERNEL_BINDER_ABI >= 5
                                                 ,
                                                 struct binder_thread* thread
#endif
                                                 ,
                                                 struct binder_buffer* buffer

#if REKERNEL_BINDER_ABI == 5
                                                 ,
                                                 binder_size_t off_end_offset
#endif
#if REKERNEL_BINDER_ABI == 4 || REKERNEL_BINDER_ABI == 6
                                                 ,
                                                 binder_size_t failed_at
#endif
#if REKERNEL_BINDER_ABI == 3
                                                 ,
                                                 binder_size_t* failed_at
#endif
#if REKERNEL_BINDER_ABI >= 4
                                                 ,
                                                 bool is_failure
#endif
);
static void (*binder_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
void kfunc_def(kfree)(const void* objp);
void* kfunc_def(kmalloc)(size_t size, gfp_t flags);
void* kfunc_def(__kmalloc)(size_t size, gfp_t flags);
struct binder_stats kvar_def(binder_stats);
int kfunc_def(binder_alloc_copy_from_buffer)(struct binder_alloc* alloc, void* dest, struct binder_buffer* buffer,
                                             binder_size_t offset, size_t bytes);
// 调用方持有当前事务或队列锁；旧 Binder 的 data 是已映射的内核地址。
static int binder_buffer_read(struct binder_alloc* alloc, void* dest, struct binder_buffer* buffer,
                              binder_size_t offset, size_t bytes) {
  if (kf_binder_alloc_copy_from_buffer)
    return kf_binder_alloc_copy_from_buffer(alloc, dest, buffer, offset, bytes);
  if (struct_offset.binder_buffer_data < 0)
    return -EOPNOTSUPP;
  if (buffer->free || offset % sizeof(u32) || offset > buffer->data_size || bytes > buffer->data_size - offset)
    return -EINVAL;
  const unsigned char* data = *(const unsigned char**)((uintptr_t)buffer + struct_offset.binder_buffer_data);
  if (!data)
    return -EFAULT;
  memcpy(dest, data + offset, bytes);
  return 0;
}
// 新内核延迟安装 FD；旧内核没有此函数，无对象事务也没有 fixup。
static void (*binder_free_txn_fixups)(struct binder_transaction* t);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);
// hook binder_transaction
static void (*binder_transaction)(struct binder_proc* proc, struct binder_thread* thread,
                                  struct binder_transaction_data* tr, int reply, binder_size_t extra_buffers_size);
// copy_from_user
void* kfunc_def(memdup_user)(const void __user* src, size_t len);
void kfunc_def(kvfree)(const void* addr);

// netfilter
kuid_t kfunc_def(sock_i_uid)(struct sock* sk);
// hook tcp_rcv
static int (*tcp_v4_do_rcv)(struct sock* sk, struct sk_buff* skb);
static int (*tcp_v6_do_rcv)(struct sock* sk, struct sk_buff* skb);
static int ipv4_version = 4, ipv6_version = 6;

// _raw_spin_lock && _raw_spin_unlock
void kfunc_def(_raw_spin_lock)(raw_spinlock_t* lock);
void kfunc_def(_raw_spin_unlock)(raw_spinlock_t* lock);
// trace
int kfunc_def(tracepoint_probe_register)(struct tracepoint* tp, void* probe, void* data);
int kfunc_def(tracepoint_probe_unregister)(struct tracepoint* tp, void* probe, void* data);
// trace_binder_transaction
struct tracepoint kvar_def(__tracepoint_binder_transaction);
#ifdef CONFIG_DEBUG_CMDLINE
int kfunc_def(get_cmdline)(struct task_struct* task, char* buffer, int buflen);
#endif /* CONFIG_DEBUG_CMDLINE */

// 最好初始化一个大于 0xFFFFFFFF 的值, 否则编译器优化后, 全局变量可能出错
// 实际上会被编译器优化为 bool
static unsigned long trace = UZERO;
static struct rekernel_binder_context* binder_contexts;
static unsigned int binder_context_guard, binder_context_unavailable;

// binder_node_lock
static inline void binder_node_lock(struct binder_node* node) {
  spinlock_t* node_lock = binder_node_lock_ptr(node);
  spin_lock(node_lock);
}
// binder_node_unlock
static inline void binder_node_unlock(struct binder_node* node) {
  spinlock_t* node_lock = binder_node_lock_ptr(node);
  spin_unlock(node_lock);
}
// binder_inner_proc_lock
static inline void binder_inner_proc_lock(struct binder_proc* proc) {
  spinlock_t* inner_lock = binder_proc_inner_lock(proc);
  spin_lock(inner_lock);
}
// binder_inner_proc_unlock
static inline void binder_inner_proc_unlock(struct binder_proc* proc) {
  spinlock_t* inner_lock = binder_proc_inner_lock(proc);
  spin_unlock(inner_lock);
}

// binder_is_frozen
static inline bool binder_is_frozen(struct binder_proc* proc) {
  bool is_frozen = false;
  if (struct_offset.binder_proc_is_frozen > 0) {
    is_frozen = binder_proc_is_frozen(proc);
  }
  return is_frozen;
}

// cgroupv2_freeze
static inline bool jobctl_frozen(struct task_struct* task) {
  unsigned long jobctl = task_jobctl(task);
  return ((jobctl & JOBCTL_TRAP_FREEZE) != 0);
}
// 判断线程是否进入 frozen 状态
static inline bool frozen_task_group(struct task_struct* task) {
  return (jobctl_frozen(task) || cgroup_freezing(task));
}

// UID 数组保留固定容量；满时返回错误，不扩大监控范围。
static uid_t rekernel_net_uids[REKERNEL_NET_UID_MAX];
static unsigned int rekernel_net_uid_count, rekernel_net_uid_guard;
static bool net_uid_monitored(uid_t uid) {
  bool found = false;
  unsigned long flags = rekernel_context_lock(&rekernel_net_uid_guard);
  for (unsigned int i = 0; i < rekernel_net_uid_count; i++) {
    if (rekernel_net_uids[i] == uid) {
      found = true;
      break;
    }
  }
  rekernel_context_unlock(&rekernel_net_uid_guard, flags);
  return found;
}
static int net_uid_update(uid_t uid, bool add) {
  int rc = 0;
  unsigned long flags = rekernel_context_lock(&rekernel_net_uid_guard);
  unsigned int i = 0;
  while (i < rekernel_net_uid_count && rekernel_net_uids[i] != uid) i++;
  if (add && i == rekernel_net_uid_count) {
    if (rekernel_net_uid_count == REKERNEL_NET_UID_MAX)
      rc = -ENOSPC;
    else
      rekernel_net_uids[rekernel_net_uid_count++] = uid;
  } else if (!add && i < rekernel_net_uid_count) {
    while (i + 1 < rekernel_net_uid_count) {
      rekernel_net_uids[i] = rekernel_net_uids[i + 1];
      i++;
    }
    rekernel_net_uids[--rekernel_net_uid_count] = 0;
  }
  rekernel_context_unlock(&rekernel_net_uid_guard, flags);
  return rc;
}

// 与 UID 一样使用固定数组；规则读写只在模块短临界区内完成。
static struct rekernel_free_async_rule rekernel_free_async_rules[REKERNEL_FREE_ASYNC_MAX];
static unsigned int rekernel_free_async_count, rekernel_free_async_guard;
static int free_async_update(const char* rpc_name, int code, unsigned char strategy, bool add) {
  if (!rpc_name)
    return -EINVAL;
  size_t len = strnlen(rpc_name, REKERNEL_RPC_NAME_SIZE);
  if (!len || len == REKERNEL_RPC_NAME_SIZE || code < -1)
    return -EINVAL;
  if (add && !kf_binder_alloc_copy_from_buffer && struct_offset.binder_buffer_data < 0)
    return -EOPNOTSUPP;
  if (add && strategy != REKERNEL_FREE_ASYNC_SKIP && strategy != REKERNEL_FREE_ASYNC_BY_CODE
      && strategy != REKERNEL_FREE_ASYNC_BY_DATA)
    return -EINVAL;
  int rc = 0;
  unsigned long flags = rekernel_context_lock(&rekernel_free_async_guard);
  unsigned int i = 0;
  while (i < rekernel_free_async_count
         && (rekernel_free_async_rules[i].code != code || strcmp(rekernel_free_async_rules[i].rpc_name, rpc_name)))
    i++;
  if (add) {
    if (i == REKERNEL_FREE_ASYNC_MAX)
      rc = -ENOSPC;
    else {
      if (i == rekernel_free_async_count) {
        memcpy(rekernel_free_async_rules[i].rpc_name, rpc_name, len + 1);
        rekernel_free_async_rules[i].code = code;
        rekernel_free_async_count++;
      }
      rekernel_free_async_rules[i].strategy = strategy;
    }
  } else if (i < rekernel_free_async_count) {
    // 规则顺序不影响匹配，用尾项填补空位。
    memcpy(&rekernel_free_async_rules[i], &rekernel_free_async_rules[--rekernel_free_async_count],
           sizeof(rekernel_free_async_rules[0]));
    memset(&rekernel_free_async_rules[rekernel_free_async_count], 0, sizeof(rekernel_free_async_rules[0]));
  }
  rekernel_context_unlock(&rekernel_free_async_guard, flags);
  return rc;
}
static unsigned char free_async_lookup(const char* rpc_name, unsigned int code) {
  unsigned char strategy = REKERNEL_FREE_ASYNC_BY_CODE;
  unsigned long flags = rekernel_context_lock(&rekernel_free_async_guard);
  for (unsigned int i = 0; i < rekernel_free_async_count; i++) {
    struct rekernel_free_async_rule* rule = &rekernel_free_async_rules[i];
    if (strcmp(rule->rpc_name, rpc_name))
      continue;
    if (rule->code >= 0 && (unsigned int)rule->code == code) {
      strategy = rule->strategy;
      break;
    }
    if (rule->code == -1)
      strategy = rule->strategy;
  }
  rekernel_context_unlock(&rekernel_free_async_guard, flags);
  return strategy;
}
static bool free_async_has_rules(void) {
  unsigned long flags = rekernel_context_lock(&rekernel_free_async_guard);
  bool found = rekernel_free_async_count != 0;
  rekernel_context_unlock(&rekernel_free_async_guard, flags);
  return found;
}

static struct genl_family rekernel_genl_family;
static struct genl_multicast_group rekernel_genl_mcgrp;
static unsigned long rekernel_genl_registered = UZERO;
// 接收只处理本 family；返回值交给内核 netlink_rcv_skb 生成 ACK。
static int rekernel_genl_rcv_msg(struct sk_buff* skb, struct nlmsghdr* nlh) {
  if (!skb->sk || sock_net(skb->sk) != kvar(init_net))
    return -ENOENT;
  if (NETLINK_CB(skb).creds.uid.val != REKERNEL_GENL_UID)
    return -EPERM;
  if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN || nlh->nlmsg_len > sk_buff_len(skb))
    return -EINVAL;
  if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP)
    return -EOPNOTSUPP;
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  if (hdr->version != REKERNEL_GENL_VERSION)
    return -EINVAL;
  bool monitor = hdr->cmd == REKERNEL_C_ADD_MONITOR_NET || hdr->cmd == REKERNEL_C_DEL_MONITOR_NET;
  bool add_rule = hdr->cmd == REKERNEL_C_ADD_FREE_ASYNC;
  if (!monitor && !add_rule && hdr->cmd != REKERNEL_C_DEL_FREE_ASYNC)
    return -EOPNOTSUPP;

  uid_t uid = 0;
  int code = 0;
  unsigned char strategy = 0;
  const char* rpc_name = NULL;
  bool has_uid = false, has_code = false, has_strategy = false;
  unsigned int left = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
  struct nlattr* attr = (struct nlattr*)((char*)hdr + GENL_HDRLEN);
  while (left) {
    if (left < NLA_HDRLEN || attr->nla_len < NLA_HDRLEN || attr->nla_len > left)
      return -EINVAL;
    unsigned int len = NLA_ALIGN(attr->nla_len);
    if (len > left)
      return -EINVAL;
    unsigned int type = attr->nla_type & NLA_TYPE_MASK;
    if (type >= REKERNEL_A_UID && type <= REKERNEL_A_FREE_ASYNC_CODE) {
      if (attr->nla_type != type)
        return -EINVAL;
      switch (type) {
        case REKERNEL_A_UID:
          if (has_uid || nla_len(attr) != sizeof(uid))
            return -EINVAL;
          memcpy(&uid, nla_data(attr), sizeof(uid));
          has_uid = true;
          break;
        case REKERNEL_A_FREE_ASYNC_STRATEGY:
          if (has_strategy || nla_len(attr) != sizeof(strategy))
            return -EINVAL;
          memcpy(&strategy, nla_data(attr), sizeof(strategy));
          has_strategy = true;
          break;
        case REKERNEL_A_FREE_ASYNC_RPC_NAME: {
          int size = nla_len(attr);
          const char* name = nla_data(attr);
          if (rpc_name || size < 2 || size > REKERNEL_RPC_NAME_SIZE || name[size - 1]
              || strnlen(name, size) != size - 1)
            return -EINVAL;
          rpc_name = name;
          break;
        }
        case REKERNEL_A_FREE_ASYNC_CODE:
          if (has_code || nla_len(attr) != sizeof(code))
            return -EINVAL;
          memcpy(&code, nla_data(attr), sizeof(code));
          has_code = true;
          break;
      }
    }
    left -= len;
    attr = (struct nlattr*)((char*)attr + len);
  }
  if (monitor)
    return has_uid ? net_uid_update(uid, hdr->cmd == REKERNEL_C_ADD_MONITOR_NET) : -EINVAL;
  if (!rpc_name || !has_code || (add_rule && !has_strategy))
    return -EINVAL;
  return free_async_update(rpc_name, code, strategy, add_rule);
}
static void genl_rcv_msg_before(hook_fargs2_t* args, void* udata) {
  struct sk_buff* skb = (struct sk_buff*)args->arg0;
  struct nlmsghdr* nlh = (struct nlmsghdr*)args->arg1;
  if (__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE) != IZERO || !skb || !nlh
      || nlh->nlmsg_type != genl_family_id(&rekernel_genl_family))
    return;
  args->skip_origin = 1;
  args->ret = rekernel_genl_rcv_msg(skb, nlh);
}
// 静态内存块清零、填写配置，再交给内核注册。
static int start_rekernel_genl_server(void) {
  if (rekernel_genl_registered == IZERO)
    return 0;
  kfunc_lookup_name(genl_register_family);
  if (!kf_genl_register_family)
    kfunc_lookup_name(__genl_register_family);
  kfunc_lookup_name(genl_unregister_family);
  lookup_name(genl_rcv_msg);
  if ((!kf_genl_register_family && !kf___genl_register_family) || !kf_genl_unregister_family || !kf___alloc_skb
      || !kf___nlmsg_put || !kf_genlmsg_put || !kf_nla_put || !kf_skb_trim || !kf_kfree_skb || !kf_netlink_broadcast
      || !kvar(init_net))
    return -EOPNOTSUPP;

  struct genl_family* family = &rekernel_genl_family;
  struct genl_family_config* config = genl_family_config(family);
  unsigned int n_mcgrps = 1;
  memset(family, 0, sizeof(*family));
  memset(&rekernel_genl_mcgrp, 0, sizeof(rekernel_genl_mcgrp));
  memcpy(config->name, REKERNEL_GENL_FAMILY_NAME, sizeof(REKERNEL_GENL_FAMILY_NAME));
  config->version = REKERNEL_GENL_VERSION;
  config->maxattr = REKERNEL_GENL_MAXATTR;
  *(struct genl_multicast_group**)((uintptr_t)family + struct_offset.genl_family_mcgrps) = &rekernel_genl_mcgrp;
  memcpy((void*)((uintptr_t)family + struct_offset.genl_family_n_mcgrps), &n_mcgrps,
         struct_offset.genl_family_n_mcgrps_size);
  memcpy(rekernel_genl_mcgrp.name, REKERNEL_GENL_MCGRP_NAME, sizeof(REKERNEL_GENL_MCGRP_NAME));

  int rc = hook_wrap(genl_rcv_msg, 2, genl_rcv_msg_before, NULL, NULL);
  if (rc)
    return -EOPNOTSUPP;
  rc = genl_register_family(family);
  if (rc) {
    hook_unwrap(genl_rcv_msg, genl_rcv_msg_before, NULL);
    return rc;
  }
  __atomic_store_n(&rekernel_genl_registered, IZERO, __ATOMIC_RELEASE);
  logkm("Created Re:Kernel Generic Netlink family! ID: %d\n", genl_family_id(family));
  return 0;
}
static int stop_rekernel_genl_server(void) {
  if (rekernel_genl_registered != IZERO)
    return 0;
  int rc = genl_unregister_family(&rekernel_genl_family);
  if (rc)
    return rc;
  __atomic_store_n(&rekernel_genl_registered, UZERO, __ATOMIC_RELEASE);
  hook_unwrap(genl_rcv_msg, genl_rcv_msg_before, NULL);
  return 0;
}
// 内部事件转换为上游嵌套 attributes，发送到 events 组播组。
static int send_netlink_message(const struct rekernel_event* msg) {
  if (__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE) != IZERO)
    return -ENOTCONN;
  struct sk_buff* skb = genlmsg_new(nla_total_size(PACKET_SIZE), GFP_ATOMIC);
  if (!skb)
    return -ENOMEM;
  void* hdr = kf_genlmsg_put(skb, 0, 0, &rekernel_genl_family, 0, REKERNEL_C_EVENT);
  if (!hdr) {
    nlmsg_free(skb);
    return -EMSGSIZE;
  }
  struct nlattr* event = nla_nest_start(skb, REKERNEL_A_EVENT);
  struct nlattr* payload;
  if (!event)
    goto nla_fail;
  switch (msg->type) {
    case BINDER: {
      int type;
      switch (msg->binder.type) {
        case TRANSACTION:
          type = 1;
          break;
        case REPLY:
          type = 2;
          break;
        case OVERFLOW:
          type = 3;
          break;
        default:
          goto nla_fail;
      }
      if (strnlen(msg->binder.rpc_name, sizeof(msg->binder.rpc_name)) == sizeof(msg->binder.rpc_name))
        goto nla_fail;
      payload = nla_nest_start(skb, REKERNEL_A_BINDER);
      if (!payload || nla_put_s32(skb, REKERNEL_A_BINDER_TYPE, type)
          || nla_put_s32(skb, REKERNEL_A_BINDER_ONEWAY, msg->binder.oneway)
          || nla_put_s32(skb, REKERNEL_A_BINDER_FROM_PID, msg->binder.src_pid)
          || nla_put_s32(skb, REKERNEL_A_BINDER_FROM_UID, msg->binder.src_uid)
          || nla_put_s32(skb, REKERNEL_A_BINDER_TARGET_PID, msg->binder.dst_pid)
          || nla_put_s32(skb, REKERNEL_A_BINDER_TARGET_UID, msg->binder.dst_uid)
          || nla_put_s32(skb, REKERNEL_A_BINDER_CODE, msg->binder.code)
          || nla_put_string(skb, REKERNEL_A_BINDER_RPC_NAME, msg->binder.rpc_name))
        goto nla_fail;
      break;
    }
    case SIGNAL:
      payload = nla_nest_start(skb, REKERNEL_A_SIGNAL);
      if (!payload || nla_put_s32(skb, REKERNEL_A_SIGNAL_SIGNAL, msg->signal.signum)
          || nla_put_s32(skb, REKERNEL_A_SIGNAL_KILLER_PID, msg->signal.src_pid)
          || nla_put_s32(skb, REKERNEL_A_SIGNAL_KILLER_UID, msg->signal.src_uid)
          || nla_put_s32(skb, REKERNEL_A_SIGNAL_DST_PID, msg->signal.dst_pid)
          || nla_put_s32(skb, REKERNEL_A_SIGNAL_DST_UID, msg->signal.dst_uid))
        goto nla_fail;
      break;
    case NETWORK:
      payload = nla_nest_start(skb, REKERNEL_A_NETWORK);
      if (!payload || nla_put_s32(skb, REKERNEL_A_NETWORK_PROTO, msg->network.family)
          || nla_put_s32(skb, REKERNEL_A_NETWORK_TARGET_UID, msg->network.uid)
          || nla_put_s32(skb, REKERNEL_A_NETWORK_DATA_LEN, msg->network.data_len))
        goto nla_fail;
      break;
    default:
      goto nla_fail;
  }
  nla_nest_end(skb, payload);
  nla_nest_end(skb, event);
  genlmsg_end(skb, hdr);
  int rc = genlmsg_multicast(&rekernel_genl_family, skb, 0, 0, GFP_ATOMIC);
  return rc == -ESRCH ? 0 : rc;
nla_fail:
  genlmsg_cancel(skb, hdr);
  nlmsg_free(skb);
  return -EMSGSIZE;
}

// 查找当前任务最内层 Binder 调用，参数地址在 before/after 期间保持有效。
static struct binder_transaction_data* binder_current_transaction(void) {
  struct binder_transaction_data* tr = NULL;
  unsigned long flags = rekernel_context_lock(&binder_context_guard);
  if (!binder_context_unavailable) {
    for (struct rekernel_binder_context* context = binder_contexts; context; context = context->next) {
      if (context->task == current) {
        hook_fargs5_t* call = context->call;
        tr = (void*)call->arg2;
        break;
      }
    }
  }
  rekernel_context_unlock(&binder_context_guard, flags);
  return tr;
}

static void rekernel_report(int reporttype, int type, pid_t src_pid, struct task_struct* src, pid_t dst_pid,
                            struct task_struct* dst, bool oneway) {
  if (__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE) != IZERO)
    return;

  struct rekernel_event msg = {
      .version = REKERNEL_EVENT_VERSION,
      .type = reporttype,
  };
  if (reporttype == NETWORK) {
    msg.network.family = type;
    msg.network.uid = dst_pid;
    msg.network.data_len = src_pid;
#ifdef CONFIG_DEBUG
    logkm("network uid=%u,ipv%u,data_len=%u\n", msg.network.uid, msg.network.family, msg.network.data_len);
#endif /* CONFIG_DEBUG */
    send_netlink_message(&msg);
    return;
  }

  if (!frozen_task_group(dst))
    return;

  unsigned int src_uid = task_uid(src).val;
  unsigned int dst_uid = task_uid(dst).val;
  if (src_uid == dst_uid)
    return;

  switch (reporttype) {
    case BINDER:
      msg.binder.type = type;
      msg.binder.oneway = oneway;
      msg.binder.src_pid = src_pid;
      msg.binder.src_uid = src_uid;
      msg.binder.dst_pid = dst_pid;
      msg.binder.dst_uid = dst_uid;
      if (oneway && type == TRANSACTION) {
        struct binder_transaction_data* tr = binder_current_transaction();
        if (!tr)
          return;
        size_t buf_data_size = PARCEL_OFFSET + sizeof(msg.binder.rpc_name) * 2;
        if (buf_data_size > tr->data_size)
          buf_data_size = tr->data_size;
        char* buf_data = memdup_user((char*)tr->data.ptr.buffer, buf_data_size);
        if (IS_ERR(buf_data))
          return;
        int i = 0;
        size_t j = PARCEL_OFFSET;
        while (i < sizeof(msg.binder.rpc_name) - 1 && j + 1 < buf_data_size && buf_data[j] != '\0') {
          msg.binder.rpc_name[i++] = buf_data[j];
          j += 2;
        }
        kvfree(buf_data);
        msg.binder.code = tr->code;
      }
      break;
    case SIGNAL:
      msg.signal.signum = type;
      msg.signal.src_pid = src_pid;
      msg.signal.src_uid = src_uid;
      msg.signal.dst_pid = dst_pid;
      msg.signal.dst_uid = dst_uid;
      break;
    default:
      return;
  }
#ifdef CONFIG_DEBUG
  logkm("event type=%u,src_pid=%d,src_uid=%u,dst_pid=%d,dst_uid=%u\n", msg.type, src_pid, src_uid, dst_pid, dst_uid);
  logkm("src_comm=%s,dst_comm=%s\n", task_comm(src), task_comm(dst));
#endif /* CONFIG_DEBUG */
#ifdef CONFIG_DEBUG_CMDLINE
  char src_cmdline[PATH_MAX], dst_cmdline[PATH_MAX];
  memset(&src_cmdline, 0, PATH_MAX);
  memset(&dst_cmdline, 0, PATH_MAX);
  int res = 0;
  res = get_cmdline(src, src_cmdline, PATH_MAX - 1);
  src_cmdline[res] = '\0';
  res = get_cmdline(dst, dst_cmdline, PATH_MAX - 1);
  dst_cmdline[res] = '\0';
  logkm("src_cmdline=%s,dst_cmdline=%s\n", src_cmdline, dst_cmdline);
#endif /* CONFIG_DEBUG_CMDLINE */
  send_netlink_message(&msg);
}

static void binder_reply_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst,
                                 bool oneway) {
  if (unlikely(!dst))
    return;
  if (task_uid(dst).val > MAX_SYSTEM_UID || src_pid == dst_pid)
    return;

  // oneway=0
  rekernel_report(BINDER, REPLY, src_pid, src, dst_pid, dst, oneway);
}

static void binder_trans_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst,
                                 bool oneway) {
  if (unlikely(!dst))
    return;
  if ((task_uid(dst).val <= MIN_USERAPP_UID) || src_pid == dst_pid)
    return;

  rekernel_report(BINDER, TRANSACTION, src_pid, src, dst_pid, dst, oneway);
}

static void binder_overflow_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst,
                                    bool oneway) {
  if (unlikely(!dst))
    return;

  // oneway=1
  rekernel_report(BINDER, OVERFLOW, src_pid, src, dst_pid, dst, oneway);
}

static void rekernel_binder_transaction(void* data, bool reply, struct binder_transaction* t,
                                        struct binder_node* target_node) {
  struct binder_proc* to_proc = binder_transaction_to_proc(t);
  if (!to_proc)
    return;
  struct binder_thread* from = binder_transaction_from(t);

  if (reply) {
    binder_reply_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, false);
  } else if (from) {
    if (from->proc) {
      binder_trans_handler(from->proc->pid, from->proc->tsk, to_proc->pid, to_proc->tsk, false);
    }
  } else {  // oneway=1
    binder_trans_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, true);

    struct binder_alloc* target_alloc = binder_proc_alloc(to_proc);
    size_t free_async_space = binder_alloc_free_async_space(target_alloc);
    size_t buffer_size = binder_alloc_buffer_size(target_alloc);
    if (free_async_space < (buffer_size / 10 + 0x300)) {
      binder_overflow_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, true);
    }
  }
}

// 队列由 Binder 锁保护；固定小缓冲分块比较，预算不足保留事务。
static bool binder_buffer_data_equal(struct binder_proc* proc, struct binder_buffer* b1, struct binder_buffer* b2,
                                     size_t* budget) {
  if ((!kf_binder_alloc_copy_from_buffer && struct_offset.binder_buffer_data < 0) || b1->data_size != b2->data_size)
    return false;
  size_t size = b1->data_size;
  if (size > *budget / 2) {
    *budget = 0;
    return false;
  }
  *budget -= size * 2;
  unsigned char data1[64], data2[64];
  struct binder_alloc* alloc = binder_proc_alloc(proc);
  for (size_t pos = 0; pos < size;) {
    size_t bytes = size - pos;
    if (bytes > sizeof(data1))
      bytes = sizeof(data1);
    if (binder_buffer_read(alloc, data1, b1, pos, bytes) || binder_buffer_read(alloc, data2, b2, pos, bytes)) {
      *budget = 0;
      return false;
    }
    if (memcmp(data1, data2, bytes))
      return false;
    pos += bytes;
  }
  return true;
}

static bool binder_can_update_transaction(struct binder_transaction* t1, struct binder_transaction* t2,
                                          unsigned char strategy, size_t* budget) {
  struct binder_proc* t1_to_proc = binder_transaction_to_proc(t1);
  struct binder_buffer* t1_buffer = binder_transaction_buffer(t1);
  struct binder_proc* t2_to_proc = binder_transaction_to_proc(t2);
  struct binder_buffer* t2_buffer = binder_transaction_buffer(t2);
  // 带 Binder 对象、FD 或额外缓冲区的消息不能仅按 code 去重。
  if (!t1_buffer || !t2_buffer || !t1_buffer->target_node || !t2_buffer->target_node || t1_buffer->offsets_size
      || t2_buffer->offsets_size || t1_buffer->extra_buffers_size || t2_buffer->extra_buffers_size)
    return false;
  unsigned int t1_code = binder_transaction_code(t1);
  unsigned int t1_flags = binder_transaction_flags(t1);
  binder_uintptr_t t1_ptr = binder_node_ptr(t1_buffer->target_node);
  binder_uintptr_t t1_cookie = binder_node_cookie(t1_buffer->target_node);
  unsigned int t2_code = binder_transaction_code(t2);
  unsigned int t2_flags = binder_transaction_flags(t2);
  binder_uintptr_t t2_ptr = binder_node_ptr(t2_buffer->target_node);
  binder_uintptr_t t2_cookie = binder_node_cookie(t2_buffer->target_node);

  if ((t1_flags & t2_flags & TF_ONE_WAY) != TF_ONE_WAY || !t1_to_proc || !t2_to_proc)
    return false;
  if (t1_to_proc == t2_to_proc && t1_to_proc->tsk == t2_to_proc->tsk && t1_code == t2_code && t1_flags == t2_flags
      && (struct_offset.binder_proc_is_frozen > 0 ? t1_buffer->pid == t2_buffer->pid : true)  // 4.19 以下无此数据
      && t1_ptr == t2_ptr && t1_cookie == t2_cookie) {
    if (strategy == REKERNEL_FREE_ASYNC_BY_CODE)
      return true;
    if (strategy == REKERNEL_FREE_ASYNC_BY_DATA)
      return binder_buffer_data_equal(t1_to_proc, t1_buffer, t2_buffer, budget);
  }
  return false;
}

static struct binder_transaction* binder_find_outdated_transaction_ilocked(struct binder_transaction* t,
                                                                           struct list_head* target_list,
                                                                           unsigned char strategy) {
  struct binder_work* w;
  bool second = false;
  size_t budget = REKERNEL_FREE_ASYNC_DATA_BUDGET;

  list_for_each_entry(w, target_list, entry) {
    if (w->type != BINDER_WORK_TRANSACTION)
      continue;
    struct binder_transaction* t_queued = container_of(w, struct binder_transaction, work);
    if (binder_can_update_transaction(t_queued, t, strategy, &budget)) {
      if (second)
        return t_queued;
      else {
        second = true;
      }
    }
    if (strategy == REKERNEL_FREE_ASYNC_BY_DATA && !budget)
      break;
  }
  return NULL;
}

static inline void outstanding_txns_dec(struct binder_proc* proc) {
  if (struct_offset.binder_proc_outstanding_txns > 0) {
    int* outstanding_txns = binder_proc_outstanding_txns(proc);
    (*outstanding_txns)--;
  }
}

static inline void binder_release_entire_buffer(struct binder_proc* proc, struct binder_thread* thread,
                                                struct binder_buffer* buffer, bool is_failure) {
#if REKERNEL_BINDER_ABI == 5
  binder_size_t off_end_offset = ALIGN(buffer->data_size, sizeof(void*));
  off_end_offset += buffer->offsets_size;
#endif
  binder_transaction_buffer_release(proc
#if REKERNEL_BINDER_ABI >= 5
                                    ,
                                    thread
#endif
                                    ,
                                    buffer

#if REKERNEL_BINDER_ABI == 5
                                    ,
                                    off_end_offset
#endif
#if REKERNEL_BINDER_ABI == 4 || REKERNEL_BINDER_ABI == 6
                                    ,
                                    0
#endif
#if REKERNEL_BINDER_ABI == 3
                                    ,
                                    NULL
#endif
#if REKERNEL_BINDER_ABI >= 4
                                    ,
                                    is_failure
#endif
  );
}

static inline void binder_stats_deleted(enum binder_stat_types type) {
  atomic_t* binder_stats_deleted_addr =
      (atomic_t*)((uintptr_t)kvar(binder_stats) + struct_offset.binder_stats_deleted_transaction);
  atomic_inc(binder_stats_deleted_addr);
}

// 在 Binder 锁外读取已经复制好的缓冲；读取失败保留消息。
static unsigned char binder_free_async_strategy(struct binder_proc* proc, struct binder_buffer* buffer,
                                                unsigned int code) {
  if (!free_async_has_rules())
    return REKERNEL_FREE_ASYNC_BY_CODE;
  if ((!kf_binder_alloc_copy_from_buffer && struct_offset.binder_buffer_data < 0) || buffer->data_size <= PARCEL_OFFSET)
    return REKERNEL_FREE_ASYNC_SKIP;
  unsigned char data[PARCEL_OFFSET + REKERNEL_RPC_NAME_SIZE * 2];
  size_t size = sizeof(data);
  if (size > buffer->data_size)
    size = buffer->data_size;
  if (binder_buffer_read(binder_proc_alloc(proc), data, buffer, 0, size))
    return REKERNEL_FREE_ASYNC_SKIP;
  char rpc_name[REKERNEL_RPC_NAME_SIZE];
  for (unsigned int i = 0; i < sizeof(rpc_name) && PARCEL_OFFSET + i * 2 + 1 < size; i++) {
    unsigned int pos = PARCEL_OFFSET + i * 2;
    if (data[pos + 1] || data[pos] > 0x7f)
      break;
    rpc_name[i] = data[pos];
    if (!rpc_name[i])
      return i ? free_async_lookup(rpc_name, code) : REKERNEL_FREE_ASYNC_SKIP;
  }
  return REKERNEL_FREE_ASYNC_SKIP;
}

static void binder_proc_transaction_before(hook_fargs3_t* args, void* udata) {
  struct binder_transaction* t = (struct binder_transaction*)args->arg0;
  struct binder_proc* proc = (struct binder_proc*)args->arg1;
  if (trace == UZERO)
    rekernel_binder_transaction(NULL, false, t, NULL);
  struct binder_buffer* buffer = binder_transaction_buffer(t);
  if (!buffer || !buffer->target_node || !(binder_transaction_flags(t) & TF_ONE_WAY) || !frozen_task_group(proc->tsk))
    return;
  unsigned char strategy = binder_free_async_strategy(proc, buffer, binder_transaction_code(t));
  if (strategy == REKERNEL_FREE_ASYNC_SKIP)
    return;
  struct binder_node* node = buffer->target_node;
  struct binder_transaction* outdated = NULL;

  binder_node_lock(node);
  binder_inner_proc_lock(proc);
  // 保留第二条去重规则；Binder 冻结和退出时不清理。
  if (!binder_proc_is_dead(proc) && !binder_is_frozen(proc) && binder_node_has_async_transaction(node))
    outdated = binder_find_outdated_transaction_ilocked(t, binder_node_async_todo(node), strategy);
  if (outdated) {
    list_del_init(&outdated->work.entry);
    outstanding_txns_dec(proc);
  }
  binder_inner_proc_unlock(proc);
  binder_node_unlock(node);

  if (!outdated)
    return;
  // 调用方持有 target_proc 引用直到原函数返回；摘除后在锁外同步释放。
  buffer = binder_transaction_buffer(outdated);
  *(struct binder_buffer**)((uintptr_t)outdated + struct_offset.binder_transaction_buffer) = NULL;
  buffer->transaction = NULL;
  binder_release_entire_buffer(proc, NULL, buffer, true);
  binder_alloc_free_buf(binder_proc_alloc(proc), buffer);
  if (binder_free_txn_fixups)
    binder_free_txn_fixups(outdated);
  kfree(outdated);
  binder_stats_deleted(BINDER_STAT_TRANSACTION);
}

static void binder_transaction_before(hook_fargs5_t* args, void* udata) {
  struct rekernel_binder_context* context = kmalloc(sizeof(*context), GFP_ATOMIC);
  unsigned long flags = rekernel_context_lock(&binder_context_guard);
  if (context) {
    context->task = current;
    context->call = args;
    context->next = binder_contexts;
    binder_contexts = context;
  } else {
    // 暂停 RPC 读取，避免嵌套调用分配失败时误用外层参数。
    binder_context_unavailable++;
  }
  rekernel_context_unlock(&binder_context_guard, flags);
}
static void binder_transaction_after(hook_fargs5_t* args, void* udata) {
  unsigned long flags = rekernel_context_lock(&binder_context_guard);
  struct rekernel_binder_context** entry = &binder_contexts;
  while (*entry && (*entry)->call != args) entry = &(*entry)->next;
  struct rekernel_binder_context* context = *entry;
  if (context)
    *entry = context->next;
  else if (binder_context_unavailable)
    binder_context_unavailable--;
  rekernel_context_unlock(&binder_context_guard, flags);
  if (context)
    kfree(context);
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
  int sig = (int)args->arg0;
  struct task_struct* dst = (struct task_struct*)args->arg2;

  if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT) {
    rekernel_report(SIGNAL, sig, task_tgid_nr(current), current, task_tgid_nr(dst), dst, false);
  }
}

static void tcp_rcv_before(hook_fargs2_t* args, void* udata) {
  struct sock* sk = (struct sock*)args->arg0;
  struct sk_buff* skb = (struct sk_buff*)args->arg1;

  uid_t uid = sock_i_uid(sk).val;
  if (uid < MIN_USERAPP_UID)
    return;

  if (!net_uid_monitored(uid))
    return;

  int version = *(int*)udata;
  struct tcphdr* th = (struct tcphdr*)sk_buff_data(skb);
  int data_len = sk_buff_len(skb) - skb_transport_offset(skb) - (th->doff << 2);
  if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
    return;

  rekernel_report(NETWORK, version, data_len, NULL, uid, NULL, true);
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  lookup_name(cgroup_freezing);

  kfunc_lookup_name(__alloc_skb);
  kfunc_lookup_name(__nlmsg_put);
  kfunc_lookup_name(genlmsg_put);
  kfunc_lookup_name(nla_put);
  kfunc_lookup_name(skb_trim);
  kfunc_lookup_name(kfree_skb);
  kfunc_lookup_name(netlink_broadcast);

  kvar_lookup_name(init_net);
  kfunc_lookup_name(tracepoint_probe_register);
  kfunc_lookup_name(tracepoint_probe_unregister);

  kfunc_lookup_name(_raw_spin_lock);
  kfunc_lookup_name(_raw_spin_unlock);
  kvar_lookup_name(__tracepoint_binder_transaction);

  lookup_name(binder_transaction_buffer_release);
  lookup_name(binder_alloc_free_buf);
  binder_free_txn_fixups = (void*)kallsyms_lookup_name("binder_free_txn_fixups");
  kfunc_lookup_name(binder_alloc_copy_from_buffer);
  if (!kf_binder_alloc_copy_from_buffer) {
    if (struct_offset.binder_buffer_data >= 0)
      logkm("Free-async buffer reader: kernel-mapped data\n");
    else
      logkm("Free-async rules unavailable: buffer reader not configured\n");
  }
  kfunc_lookup_name(kfree);
  kfunc_lookup_name(kmalloc);
  kfunc_lookup_name(__kmalloc);
  if (!kf_kfree || (!kf_kmalloc && !kf___kmalloc))
    return -EOPNOTSUPP;
  kvar_lookup_name(binder_stats);
  kfunc_lookup_name(kvfree);
  kfunc_lookup_name(memdup_user);

  lookup_name(binder_proc_transaction);
  lookup_name(binder_transaction);
  lookup_name(do_send_sig_info);

  kfunc_lookup_name(sock_i_uid);

  lookup_name(tcp_v4_do_rcv);
  lookup_name(tcp_v6_do_rcv);
#ifdef CONFIG_DEBUG_CMDLINE
  kfunc_lookup_name(get_cmdline);
#endif /* CONFIG_DEBUG_CMDLINE */

  int rc = 0;
  rc = tracepoint_probe_register(kvar(__tracepoint_binder_transaction), rekernel_binder_transaction, NULL);
  if (rc == 0) {
    trace = IZERO;
  }

  hook_func(binder_proc_transaction, 3, binder_proc_transaction_before, NULL, NULL);
  hook_func(binder_transaction, 5, binder_transaction_before, binder_transaction_after, NULL);
  hook_func(do_send_sig_info, 4, do_send_sig_info_before, NULL, NULL);

  hook_func(tcp_v4_do_rcv, 2, tcp_rcv_before, NULL, &ipv4_version);
  hook_func(tcp_v6_do_rcv, 2, tcp_rcv_before, NULL, &ipv6_version);

  rc = start_rekernel_genl_server();
  if (rc) {
    if (trace == IZERO) {
      tracepoint_probe_unregister(kvar(__tracepoint_binder_transaction), rekernel_binder_transaction, NULL);
      trace = UZERO;
    }
    hook_unwrap(binder_proc_transaction, binder_proc_transaction_before, NULL);
    hook_unwrap(binder_transaction, binder_transaction_before, binder_transaction_after);
    hook_unwrap(do_send_sig_info, do_send_sig_info_before, NULL);
    hook_unwrap(tcp_v4_do_rcv, tcp_rcv_before, NULL);
    hook_unwrap(tcp_v6_do_rcv, tcp_rcv_before, NULL);
  }
  return rc;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  char msg[64];
  snprintf(msg, sizeof(msg), "_(._.)_");
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  int rc = stop_rekernel_genl_server();
  if (rc)
    logkm("Failed to unregister Generic Netlink family: %d\n", rc);
  tracepoint_probe_unregister(kvar(__tracepoint_binder_transaction), rekernel_binder_transaction, NULL);

  unhook_func(binder_proc_transaction);
  unhook_func(binder_transaction);
  unhook_func(do_send_sig_info);

  unhook_func(tcp_v4_do_rcv);
  unhook_func(tcp_v6_do_rcv);

  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
