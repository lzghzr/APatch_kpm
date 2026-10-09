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
#include "re_utils.h"

KPM_NAME("re_kernel");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel, support 4.4 ~ 6.6");

enum report_type {
  BINDER,
  SIGNAL,
  NETWORK,
};
enum binder_type {
  REPLY,
  TRANSACTION,
  OVERFLOW,
};
static const char* binder_type_names[] = {
    "reply",
    "transaction",
    "free_buffer_full",
};

// cgroup_freezing, cgroupv1_freeze
static bool (*cgroup_freezing)(struct task_struct* task);
// send_netlink_message
struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
void kfunc_def(kfree_skb)(struct sk_buff* skb);
int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
static struct net kvar_def(init_net);
// hook binder_proc_transaction
static int (*binder_proc_transaction)(struct binder_transaction* t, struct binder_proc* proc,
                                      struct binder_thread* thread);
// free the outdated transaction and buffer
static void (*binder_free_txn_fixups)(struct binder_transaction* t);
static void (*binder_transaction_buffer_release)(struct binder_proc* proc, struct binder_thread* thread,
                                                 struct binder_buffer* buffer, binder_size_t off_end_offset,
                                                 bool is_failure);
static void (*binder_transaction_buffer_release_v6)(struct binder_proc* proc, struct binder_thread* thread,
                                                    struct binder_buffer* buffer, binder_size_t failed_at,
                                                    bool is_failure);
static void (*binder_transaction_buffer_release_v4)(struct binder_proc* proc, struct binder_buffer* buffer,
                                                    binder_size_t failed_at, bool is_failure);
static void (*binder_transaction_buffer_release_v3)(struct binder_proc* proc, struct binder_buffer* buffer,
                                                    binder_size_t* failed_at);
static void (*binder_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
void kfunc_def(kfree)(const void* objp);
void* kfunc_def(kmalloc)(size_t size, gfp_t flags);
void* kfunc_def(__kmalloc)(size_t size, gfp_t flags);
struct binder_stats kvar_def(binder_stats);
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

static bool binder_transaction_buffer_release_ver6, binder_transaction_buffer_release_ver5,
    binder_transaction_buffer_release_ver4;

static bool trace;

struct struct_offset struct_offset = {};
// clang-format off
#include "re_offsets.c"
// clang-format on

// Generic Netlink
static void* kfunc_def(genlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, const struct genl_family* family,
                                    int flags, u8 cmd);
static int kfunc_def(nla_put)(struct sk_buff* skb, int type, int len, const void* data);
static int kfunc_def(netlink_broadcast)(struct sock* sk, struct sk_buff* skb, u32 portid, u32 group, gfp_t flags);
static int kfunc_def(genl_register_family)(struct genl_family* family);
static int kfunc_def(__genl_register_family)(struct genl_family* family);
static int kfunc_def(genl_unregister_family)(const struct genl_family* family);
static int (*genl_rcv_msg)(struct sk_buff* skb, struct nlmsghdr* nlh);
static struct genl_family* rekernel_genl_family;
static bool rekernel_genl_registered;
static bool rekernel_genl_hooked;

static unsigned int genl_family_id(void) {
  return *(unsigned int*)((char*)rekernel_genl_family + struct_offset.genl_family_id);
}
static struct sock* rekernel_genl_sock(void) {
  return *(struct sock**)((char*)kvar(init_net) + struct_offset.net_genl_sock);
}

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

// 每个 skb 只包含一条消息，从 skb->len 结束消息，不再增加 tail 偏移。
static struct sk_buff* rekernel_genl_message(const char* msg, unsigned int len, u8 cmd, u32 seq) {
  struct sk_buff* skb = nlmsg_new(GENL_HDRLEN + NLA_ALIGN(NLA_HDRLEN + len), GFP_ATOMIC);
  if (!skb)
    return NULL;
  void* hdr = kfunc(genlmsg_put)(skb, 0, seq, rekernel_genl_family, 0, cmd);
  if (!hdr || kfunc(nla_put)(skb, REKERNEL_A_MSG, len, msg)) {
    nlmsg_free(skb);
    return NULL;
  }
  struct nlmsghdr* nlh = (void*)((char*)hdr - GENL_HDRLEN - NLMSG_HDRLEN);
  nlh->nlmsg_len = sk_buff_len(skb);
  return skb;
}

static int send_netlink_message(char* msg) {
  if (!__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE))
    return -ENOTCONN;
  unsigned int len = strnlen(msg, PACKET_SIZE);
  if (len == PACKET_SIZE)
    return -EMSGSIZE;
  struct sk_buff* skb = rekernel_genl_message(msg, len, REKERNEL_C_EVENT, 0);
  if (!skb)
    return -ENOMEM;
  unsigned int group = *(unsigned int*)((char*)rekernel_genl_family + struct_offset.genl_family_mcgrp_offset);
  int rc = kfunc(netlink_broadcast)(rekernel_genl_sock(), skb, 0, group, GFP_ATOMIC);
  return rc == -ESRCH ? 0 : rc;
}

static int rekernel_genl_rcv_msg(struct sk_buff* skb, struct nlmsghdr* nlh) {
  // 内核收包 skb 的所属 socket 是目标 Genl socket，不使用用户填写的 nlmsg_pid。
  if (!skb->sk || skb->sk != rekernel_genl_sock())
    return -ENOENT;
  if (NETLINK_CB(skb).creds.uid.val != REKERNEL_GENL_UID)
    return -EPERM;
  if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
    return -EINVAL;
  if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP)
    return -EOPNOTSUPP;
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  if (hdr->version != REKERNEL_GENL_VERSION)
    return -EINVAL;
  if (hdr->cmd != REKERNEL_C_ADD_MONITOR_NET && hdr->cmd != REKERNEL_C_DEL_MONITOR_NET
      && hdr->cmd != REKERNEL_C_GET_VERSION)
    return -EOPNOTSUPP;
  bool has_uid = false;
  uid_t uid = 0;
  unsigned int left = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
  struct nlattr* attr = (void*)((char*)hdr + GENL_HDRLEN);
  while (left) {
    if (left < NLA_HDRLEN || attr->nla_len < NLA_HDRLEN || attr->nla_len > left)
      return -EINVAL;
    unsigned int len = NLA_ALIGN(attr->nla_len);
    if (len > left)
      return -EINVAL;
    if (attr->nla_type != REKERNEL_A_UID || has_uid || attr->nla_len != NLA_HDRLEN + sizeof(uid))
      return -EINVAL;
    memcpy(&uid, (char*)attr + NLA_HDRLEN, sizeof(uid));
    has_uid = true;
    left -= len;
    attr = (void*)((char*)attr + len);
  }
  if (hdr->cmd != REKERNEL_C_GET_VERSION)
    return has_uid ? net_uid_update(uid, hdr->cmd == REKERNEL_C_ADD_MONITOR_NET) : -EINVAL;
  if (has_uid || !NETLINK_CB(skb).portid)
    return -EINVAL;
  struct sk_buff* reply = rekernel_genl_message(MYKPM_VERSION, sizeof(MYKPM_VERSION), hdr->cmd, nlh->nlmsg_seq);
  if (!reply)
    return -ENOMEM;
  int rc = netlink_unicast(rekernel_genl_sock(), reply, NETLINK_CB(skb).portid, MSG_DONTWAIT);
  return rc < 0 ? rc : 0;
}

static void genl_rcv_msg_before(hook_fargs2_t* args, void* udata) {
  struct sk_buff* skb = (void*)args->arg0;
  struct nlmsghdr* nlh = (void*)args->arg1;
  if (!__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE) || nlh->nlmsg_type != genl_family_id())
    return;
  args->skip_origin = 1;
  args->ret = rekernel_genl_rcv_msg(skb, nlh);
}

static int prepare_rekernel_genl_server(void) {
  kfunc_lookup_name(genlmsg_put);
  kfunc_lookup_name(nla_put);
  kfunc_lookup_name(netlink_broadcast);
  kfunc_lookup_name(genl_register_family);
  if (!kfunc(genl_register_family))
    kfunc_lookup_name(__genl_register_family);
  kfunc_lookup_name(genl_unregister_family);
  genl_rcv_msg = (typeof(genl_rcv_msg))kallsyms_lookup_name("genl_rcv_msg");
  if ((!kfunc(genl_register_family) && !kfunc(__genl_register_family)) || !kfunc(genl_unregister_family)
      || !kfunc(genlmsg_put) || !kfunc(nla_put) || !kfunc(netlink_broadcast) || !genl_rcv_msg || !kfunc(__alloc_skb)
      || !kfunc(kfree_skb) || !kfunc(netlink_unicast) || !kvar(init_net))
    return -EOPNOTSUPP;
  if (!rekernel_genl_sock())
    return -ENOTCONN;
  return 0;
}

static int start_rekernel_genl_server(void) {
  int rc;
  // kmalloc 保证内核对象的对齐；family 大块清零后只填写已推导的配置。
  rekernel_genl_family = kmalloc(sizeof(*rekernel_genl_family) + sizeof(struct genl_multicast_group), GFP_ATOMIC);
  if (!rekernel_genl_family)
    return -ENOMEM;
  memset(rekernel_genl_family, 0, sizeof(*rekernel_genl_family) + sizeof(struct genl_multicast_group));
  struct genl_family_config* config = (void*)((char*)rekernel_genl_family + struct_offset.genl_family_config);
  struct genl_multicast_group* mcgrp = (void*)(rekernel_genl_family + 1);
  memcpy(config->name, REKERNEL_GENL_FAMILY_NAME, sizeof(REKERNEL_GENL_FAMILY_NAME));
  config->version = REKERNEL_GENL_VERSION;
  config->maxattr = REKERNEL_GENL_MAXATTR;
  memcpy(mcgrp->name, REKERNEL_GENL_MCGRP_NAME, sizeof(REKERNEL_GENL_MCGRP_NAME));
  *(struct genl_multicast_group**)((char*)rekernel_genl_family + struct_offset.genl_family_mcgrps) = mcgrp;
  unsigned int count = 1;
  memcpy((char*)rekernel_genl_family + struct_offset.genl_family_n_mcgrps, &count,
         struct_offset.genl_family_n_mcgrps_size);
  rc = hook_wrap(genl_rcv_msg, 2, genl_rcv_msg_before, NULL, NULL);
  if (rc)
    goto failed;
  rekernel_genl_hooked = true;
  rc = kfunc(genl_register_family) ? kfunc(genl_register_family)(rekernel_genl_family)
                                   : kfunc(__genl_register_family)(rekernel_genl_family);
  if (rc) {
    hook_unwrap(genl_rcv_msg, genl_rcv_msg_before, NULL);
    rekernel_genl_hooked = false;
    goto failed;
  }
  __atomic_store_n(&rekernel_genl_registered, true, __ATOMIC_RELEASE);
  logkm("Created Re:Kernel Generic Netlink family! ID: %d\n", genl_family_id());
  return 0;
failed:
  kfree(rekernel_genl_family);
  rekernel_genl_family = NULL;
  return rc < 0 ? rc : -EOPNOTSUPP;
}

static int stop_rekernel_genl_server(void) {
  if (__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE)) {
    int rc = kfunc(genl_unregister_family)(rekernel_genl_family);
    if (rc)
      return rc;
    __atomic_store_n(&rekernel_genl_registered, false, __ATOMIC_RELEASE);
  }
  if (rekernel_genl_hooked) {
    hook_unwrap(genl_rcv_msg, genl_rcv_msg_before, NULL);
    rekernel_genl_hooked = false;
  }
  if (rekernel_genl_family) {
    kfree(rekernel_genl_family);
    rekernel_genl_family = NULL;
  }
  return 0;
}

// Binder 调用上下文
struct rekernel_binder_context {
  struct task_struct* task;
  hook_fargs5_t* call;
  struct rekernel_binder_context* next;
};
static struct rekernel_binder_context* binder_contexts;
static unsigned int binder_context_guard, binder_context_unavailable;

// 沿用静态版的短期上下文，不依赖运行端未导出的 get_task_ext。
static struct binder_transaction_data* binder_current_transaction(void) {
  struct binder_transaction_data* tr = NULL;
  unsigned long flags = rekernel_context_lock(&binder_context_guard);
  if (!binder_context_unavailable) {
    for (struct rekernel_binder_context* context = binder_contexts; context; context = context->next) {
      if (context->task == current) {
        tr = (void*)context->call->arg2;
        break;
      }
    }
  }
  rekernel_context_unlock(&binder_context_guard, flags);
  return tr;
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
    // 嵌套分配失败时不借用外层调用的数据。
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

static void rekernel_report(int reporttype, int type, pid_t src_pid, struct task_struct* src, pid_t dst_pid,
                            struct task_struct* dst, bool oneway) {
  if (!__atomic_load_n(&rekernel_genl_registered, __ATOMIC_ACQUIRE))
    return;

  if (reporttype == NETWORK) {
    char binder_kmsg[PACKET_SIZE];
    snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv%d,data_len=%d;", dst_pid, type,
             src_pid);
#ifdef CONFIG_DEBUG
    logkm("%s\n", binder_kmsg);
#endif /* CONFIG_DEBUG */
    send_netlink_message(binder_kmsg);
    return;
  }

  if (!frozen_task_group(dst))
    return;

  if (task_uid(src).val == task_uid(dst).val)
    return;

  char binder_kmsg[PACKET_SIZE];
  switch (reporttype) {
    case BINDER:
      if (oneway && type == TRANSACTION) {
        struct binder_transaction_data* tr = binder_current_transaction();
        if (!tr)
          return;
        // 减少异步消息
        if (tr->code < 29 || tr->code > 32)
          return;

        size_t buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ? INTERFACETOKEN_BUFF_SIZE : tr->data_size;
        char* buf_data = memdup_user((char*)tr->data.ptr.buffer, buf_data_size);
        if (IS_ERR(buf_data))
          return;
        char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
        int i = 0;
        int j = PARCEL_OFFSET + 1;
        char* p = buf_data + PARCEL_OFFSET;
        while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
          buf[i++] = *p;
          j += 2;
          p += 2;
        }
        kvfree(buf_data);
        snprintf(binder_kmsg, sizeof(binder_kmsg),
                 "type=Binder,bindertype=%s,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d,"
                 "rpc_name=%s,code=%d;",
                 binder_type_names[type], oneway, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val, buf,
                 tr->code);
      } else {
        snprintf(binder_kmsg, sizeof(binder_kmsg),
                 "type=Binder,bindertype=%s,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;",
                 binder_type_names[type], oneway, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val);
      }
      break;
    case SIGNAL:
      snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;",
               type, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val);
      break;
    default:
      return;
  }
#ifdef CONFIG_DEBUG
  logkm("%s\n", binder_kmsg);
  logkm("src_comm=%s,dst_comm=%s\n", get_task_comm(src), get_task_comm(dst));
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
  send_netlink_message(binder_kmsg);
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

static bool binder_can_update_transaction(struct binder_transaction* t1, struct binder_transaction* t2) {
  struct binder_proc* t1_to_proc = binder_transaction_to_proc(t1);
  struct binder_buffer* t1_buffer = binder_transaction_buffer(t1);
  unsigned int t1_code = binder_transaction_code(t1);
  unsigned int t1_flags = binder_transaction_flags(t1);

  struct binder_proc* t2_to_proc = binder_transaction_to_proc(t2);
  struct binder_buffer* t2_buffer = binder_transaction_buffer(t2);
  // 与 rekx 基础去重一致，保留带 Binder 对象、FD 或额外缓冲区的消息。
  if (!t1_buffer || !t2_buffer || !t1_buffer->target_node || !t2_buffer->target_node || t1_buffer->offsets_size
      || t2_buffer->offsets_size || t1_buffer->extra_buffers_size || t2_buffer->extra_buffers_size)
    return false;
  binder_uintptr_t t1_ptr = binder_node_ptr(t1_buffer->target_node);
  binder_uintptr_t t1_cookie = binder_node_cookie(t1_buffer->target_node);
  unsigned int t2_code = binder_transaction_code(t2);
  unsigned int t2_flags = binder_transaction_flags(t2);
  binder_uintptr_t t2_ptr = binder_node_ptr(t2_buffer->target_node);
  binder_uintptr_t t2_cookie = binder_node_cookie(t2_buffer->target_node);

  if ((t1_flags & t2_flags & TF_ONE_WAY) != TF_ONE_WAY || !t1_to_proc || !t2_to_proc)
    return false;
  if (t1_to_proc == t2_to_proc && t1_code == t2_code && t1_flags == t2_flags
      && (struct_offset.binder_proc_is_frozen > 0 ? t1_buffer->pid == t2_buffer->pid : true)  // 4.19 以下无此数据
      && t1_ptr == t2_ptr && t1_cookie == t2_cookie)
    return true;
  return false;
}

static struct binder_transaction* binder_find_outdated_transaction_ilocked(struct binder_transaction* t,
                                                                           struct list_head* target_list) {
  struct binder_work* w;
  struct binder_transaction* first = NULL;

  list_for_each_entry(w, target_list, entry) {
    if (w->type != BINDER_WORK_TRANSACTION)
      continue;
    struct binder_transaction* t_queued = container_of(w, struct binder_transaction, work);
    if (binder_can_update_transaction(t_queued, t)) {
      if (first)
        return first;
      first = t_queued;
    }
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
  if (binder_transaction_buffer_release_ver6) {
    binder_transaction_buffer_release_v6(proc, thread, buffer, 0, is_failure);
  } else if (binder_transaction_buffer_release_ver5) {
    binder_size_t off_end_offset = ALIGN(buffer->data_size, sizeof(void*));
    off_end_offset += buffer->offsets_size;

    binder_transaction_buffer_release(proc, thread, buffer, off_end_offset, is_failure);
  } else if (binder_transaction_buffer_release_ver4) {
    binder_transaction_buffer_release_v4(proc, buffer, 0, is_failure);
  } else {
    binder_transaction_buffer_release_v3(proc, buffer, NULL);
  }
}

static inline void binder_stats_deleted(enum binder_stat_types type) {
  atomic_t* binder_stats_deleted_addr =
      (atomic_t*)((uintptr_t)kvar(binder_stats) + struct_offset.binder_stats_deleted_transaction);
  atomic_inc(binder_stats_deleted_addr);
}

static void binder_proc_transaction_before(hook_fargs3_t* args, void* udata) {
  struct binder_transaction* t = (struct binder_transaction*)args->arg0;
  struct binder_proc* proc = (struct binder_proc*)args->arg1;

  struct binder_buffer* buffer = binder_transaction_buffer(t);
  // 兼容不支持 trace 的内核
  if (!trace) {
    rekernel_binder_transaction(NULL, false, t, NULL);
  }
  unsigned int flags = binder_transaction_flags(t);
  if (!buffer || !buffer->target_node || !(flags & TF_ONE_WAY) || !frozen_task_group(proc->tsk))
    return;

  struct binder_node* node = buffer->target_node;
  struct binder_transaction* t_outdated = NULL;
  binder_node_lock(node);
  binder_inner_proc_lock(proc);
  if (!binder_proc_is_dead(proc) && !binder_is_frozen(proc) && frozen_task_group(proc->tsk)
      && binder_node_has_async_transaction(node)) {
    t_outdated = binder_find_outdated_transaction_ilocked(t, binder_node_async_todo(node));
  }
  if (t_outdated) {
    list_del_init(&t_outdated->work.entry);
    outstanding_txns_dec(proc);
  }

  binder_inner_proc_unlock(proc);
  binder_node_unlock(node);

  if (t_outdated) {
    struct binder_alloc* target_alloc = binder_proc_alloc(proc);
    struct binder_buffer* buffer = binder_transaction_buffer(t_outdated);
#ifdef CONFIG_DEBUG
    logkm("free_outdated pid=%d,uid=%d,data_size=%d\n", proc->pid, task_uid(proc->tsk).val, buffer->data_size);
#endif /* CONFIG_DEBUG */

    *(struct binder_buffer**)((uintptr_t)t_outdated + struct_offset.binder_transaction_buffer) = NULL;
    buffer->transaction = NULL;
    binder_release_entire_buffer(proc, NULL, buffer, true);
    binder_alloc_free_buf(target_alloc, buffer);
    if (binder_free_txn_fixups)
      binder_free_txn_fixups(t_outdated);
    kfree(t_outdated);
    binder_stats_deleted(BINDER_STAT_TRANSACTION);
  }
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
  int sig = (int)args->arg0;
  struct task_struct* dst = (struct task_struct*)args->arg2;

  if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT) {
    rekernel_report(SIGNAL, sig, task_tgid_nr(current), current, task_tgid_nr(dst), dst, false);
  }
}

static inline unsigned char* skb_transport_header(const struct sk_buff* skb) {
  return sk_buff_head(skb) + sk_buff_transport_header(skb);
}
static inline int skb_transport_offset(const struct sk_buff* skb) {
  return skb_transport_header(skb) - sk_buff_data(skb);
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

struct rekernel_hook {
  void* func;
  int args;
  void* before;
  void* after;
  void* data;
  bool installed;
};
static struct rekernel_hook rekernel_hooks[5];
static void stop_rekernel_hooks(void) {
  for (unsigned int i = ARRAY_SIZE(rekernel_hooks); i; i--) {
    struct rekernel_hook* hook = &rekernel_hooks[i - 1];
    if (hook->installed) {
      hook_unwrap(hook->func, hook->before, hook->after);
      hook->installed = false;
    }
  }
  if (trace) {
    tracepoint_probe_unregister(kvar(__tracepoint_binder_transaction), rekernel_binder_transaction, NULL);
    trace = false;
  }
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  lookup_name(cgroup_freezing);

  kfunc_lookup_name(__alloc_skb);
  kfunc_lookup_name(kfree_skb);
  kfunc_lookup_name(netlink_unicast);

  kvar_lookup_name(init_net);
  kfunc_lookup_name(tracepoint_probe_register);
  kfunc_lookup_name(tracepoint_probe_unregister);

  kfunc_lookup_name(_raw_spin_lock);
  kfunc_lookup_name(_raw_spin_unlock);
  kvar_lookup_name(__tracepoint_binder_transaction);

  lookup_name(binder_transaction_buffer_release);
  binder_transaction_buffer_release_v6 =
      (typeof(binder_transaction_buffer_release_v6))binder_transaction_buffer_release;
  binder_transaction_buffer_release_v4 =
      (typeof(binder_transaction_buffer_release_v4))binder_transaction_buffer_release;
  binder_transaction_buffer_release_v3 =
      (typeof(binder_transaction_buffer_release_v3))binder_transaction_buffer_release;
  lookup_name(binder_alloc_free_buf);
  binder_free_txn_fixups = (void*)kallsyms_lookup_name("binder_free_txn_fixups");
  kfunc_lookup_name(kfree);
  kfunc_lookup_name(kmalloc);
  kfunc_lookup_name(__kmalloc);
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

  rekernel_hooks[0] = (struct rekernel_hook){binder_proc_transaction, 3, binder_proc_transaction_before};
  rekernel_hooks[1] =
      (struct rekernel_hook){binder_transaction, 5, binder_transaction_before, binder_transaction_after};
  rekernel_hooks[2] = (struct rekernel_hook){do_send_sig_info, 4, do_send_sig_info_before};
  rekernel_hooks[3] = (struct rekernel_hook){tcp_v4_do_rcv, 2, tcp_rcv_before, NULL, &ipv4_version};
  rekernel_hooks[4] = (struct rekernel_hook){tcp_v6_do_rcv, 2, tcp_rcv_before, NULL, &ipv6_version};

  int rc = 0;
  rc = calculate_offsets();
  if (rc < 0)
    return rc;

  rc = prepare_rekernel_genl_server();
  if (rc)
    return rc;
  if ((!kfunc(kmalloc) && !kfunc(__kmalloc)) || !kfunc(kfree) || !kfunc(memdup_user) || !kfunc(kvfree)
      || !kfunc(_raw_spin_lock) || !kfunc(_raw_spin_unlock) || !kvar(binder_stats))
    return -EOPNOTSUPP;
  if (kfunc(tracepoint_probe_register) && kfunc(tracepoint_probe_unregister) && kvar(__tracepoint_binder_transaction)) {
    rc = tracepoint_probe_register(kvar(__tracepoint_binder_transaction), rekernel_binder_transaction, NULL);
    if (!rc)
      trace = true;
  }
  for (unsigned int i = 0; i < ARRAY_SIZE(rekernel_hooks); i++) {
    struct rekernel_hook* hook = &rekernel_hooks[i];
    rc = hook_wrap(hook->func, hook->args, hook->before, hook->after, hook->data);
    if (rc) {
      rc = -EOPNOTSUPP;
      goto failed;
    }
    hook->installed = true;
  }
  rc = start_rekernel_genl_server();
  if (!rc)
    return 0;
failed:
  stop_rekernel_hooks();
  return rc;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  static const char msg[] = "_(._.)_";
  if (!out_msg || outlen < (int)sizeof(msg))
    return -EINVAL;
  return compat_copy_to_user(out_msg, msg, sizeof(msg)) == sizeof(msg) ? 0 : -EFAULT;
}

static long inline_hook_exit(void* __user reserved) {
  int rc = stop_rekernel_genl_server();
  if (rc)
    return rc;
  stop_rekernel_hooks();
  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
