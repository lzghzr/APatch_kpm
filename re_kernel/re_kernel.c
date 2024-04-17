/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 Nep-Timeline. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "../demo.h"
#include "re_kernel.h"

KPM_NAME("re_kernel");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel 4.19 5.15");

#define NETLINK_REKERNEL_MAX 26
#define NETLINK_REKERNEL_MIN 22
#define USER_PORT 100
#define PACKET_SIZE 128
#define MIN_USERAPP_UID (10000)
#define MAX_SYSTEM_UID (2000)

#define SIGQUIT 3
#define SIGABRT 6
#define SIGKILL 9
#define SIGTERM 15
#define PF_FROZEN 0x00010000
#define MSG_DONTWAIT 0x40

struct sk_buff *(*__alloc_skb)(unsigned int size, int /*gfp_t*/ gfp_mask, int flags, int node);
struct nlmsghdr *(*__nlmsg_put)(struct sk_buff *skb, u32 portid, u32 seq, int type, int len, int flags);
void (*kfree_skb)(struct sk_buff *skb);
int (*netlink_unicast)(struct sock *ssk, struct sk_buff *skb, u32 portid, int nonblock);
struct net(*init_net);
struct sock *(*__netlink_kernel_create)(struct net *net, int unit, struct module *module, struct netlink_kernel_cfg *cfg);
void (*netlink_kernel_release)(struct sock *sk);
void (*_binder_inner_proc_lock)(struct binder_proc *proc, int line);
void (*_binder_inner_proc_unlock)(struct binder_proc *proc, int line);
struct binder_thread *(*binder_get_txn_from_and_acq_inner)(struct binder_transaction *t);
void (*binder_transaction)(struct binder_proc *proc, struct binder_thread *thread, struct binder_transaction_data *tr, int reply, binder_size_t extra_buffers_size);
int (*binder_inc_node_nilocked)(struct binder_node *node, int strong, int internal, struct list_head *target_list);
int (*security_binder_transaction)(const struct cred *from, const struct cred *to);
int (*do_send_sig_info)(int sig, struct siginfo *info, struct task_struct *p, enum pid_type type);

struct binder_transaction_data *tr_data;
struct binder_proc *from_proc, *to_proc;

static struct sock *rekernel_netlink;
static int netlink_unit;

static inline bool line_is_frozen(struct task_struct *task)
{
  // unknow group_leader_offset
  return true;
}

static int send_netlink_message(char *msg, uint16_t len)
{
  struct sk_buff *skbuffer;
  struct nlmsghdr *nlhdr;

  int sk_len = nlmsg_total_size(len);
  skbuffer = __alloc_skb(sk_len, GFP_ATOMIC, 0, NUMA_NO_NODE);
  if (!skbuffer)
  {
    printk("netlink alloc failure.\n");
    return -1;
  }

  nlhdr = __nlmsg_put(skbuffer, 0, 0, netlink_unit, len, 0);
  if (!nlhdr)
  {
    printk("nlmsg_put failaure.\n");
    kfree_skb(skbuffer);
    return -1;
  }

  memcpy(nlmsg_data(nlhdr), msg, len);
  return netlink_unicast(rekernel_netlink, skbuffer, USER_PORT, MSG_DONTWAIT);
}

static int start_rekernel_server(void)
{
  if (rekernel_netlink)
    return 0;
  struct netlink_kernel_cfg rekernel_cfg = {
      .input = NULL,
  };
  for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++)
  {
    rekernel_netlink = __netlink_kernel_create(init_net, netlink_unit, THIS_MODULE, &rekernel_cfg);
    if (rekernel_netlink != NULL)
      break;
  }
  if (rekernel_netlink == NULL)
  {
    printk("Failed to create Re:Kernel server!\n");
    return -1;
  }
  printk("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);
  return 0;
}

void binder_transaction_before(hook_fargs5_t *args, void *udata)
{
  if (start_rekernel_server() != 0)
  {
    return;
  }
  struct binder_proc *proc = (struct binder_proc *)args->arg0;
  struct binder_thread *thread = (struct binder_thread *)args->arg1;
  struct binder_transaction_data *tr = (struct binder_transaction_data *)args->arg2;
  int reply = (int)args->arg3;

  struct binder_proc *target_proc = NULL;
  if (reply)
  {
    binder_inner_proc_lock(proc);
    struct binder_transaction *in_reply_to = thread->transaction_stack;
    if (in_reply_to == NULL)
    {
      binder_inner_proc_unlock(proc);
      return;
    }
    if (in_reply_to->to_thread != thread)
    {
      binder_inner_proc_unlock(proc);
      return;
    }
    binder_inner_proc_unlock(proc);
    struct binder_thread *target_thread = binder_get_txn_from_and_acq_inner(in_reply_to);
    if (target_thread == NULL)
    {
      return;
    }
    if (target_thread->transaction_stack != in_reply_to)
    {
      binder_inner_proc_unlock(target_thread->proc);
      return;
    }
    target_proc = target_thread->proc;
    binder_inner_proc_unlock(target_thread->proc);

    if (target_proc && (NULL != target_proc->tsk) && (NULL != proc->tsk) && (task_uid(target_proc->tsk).val > MIN_USERAPP_UID) && (proc->pid != target_proc->pid) && line_is_frozen(target_proc->tsk))
    {
      char binder_kmsg[PACKET_SIZE];
      snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
      printk("re_kernel: %s\n", binder_kmsg);
#endif
      send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
  }
  else
  {
    tr_data = tr;
    from_proc = proc;
  }
}

void binder_inc_node_nilocked_after(hook_fargs4_t *args, void *udata)
{
  int strong = (int)args->arg1;
  int internal = (int)args->arg2;
  int target_list = (int)args->arg3;
  if (strong == 1 && internal == 0 && target_list == NULL)
  {
    struct binder_node *target_node = (struct binder_node *)args->arg0;
    to_proc = target_node->proc;
  }
}

void security_binder_transaction_before(hook_fargs2_t *args, void *udata)
{
  if (start_rekernel_server() != 0)
  {
    return;
  }
  if (!from_proc || !to_proc)
  {
    return;
  }
  struct binder_transaction_data *tr = tr_data;
  struct binder_proc *proc = from_proc;
  struct binder_proc *target_proc = to_proc;
  if (target_proc && (NULL != target_proc->tsk) && (NULL != proc->tsk) && (task_uid(target_proc->tsk).val <= MAX_SYSTEM_UID) && (proc->pid != target_proc->pid) && line_is_frozen(target_proc->tsk))
  {
    char binder_kmsg[PACKET_SIZE];
    snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", tr->flags & TF_ONE_WAY, proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
    printk("re_kernel: %s\n", binder_kmsg);
#endif
    send_netlink_message(binder_kmsg, strlen(binder_kmsg));
  }
}

void do_send_sig_info_before(hook_fargs4_t *args, void *udata)
{
  if (start_rekernel_server() != 0)
  {
    return;
  }
  int sig = (int)args->arg0;
  struct task_struct *p = (struct task_struct *)args->arg2;

  if (line_is_frozen(p) && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT))
  {
    char binder_kmsg[PACKET_SIZE];
    snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer=%d,dst=%d;", sig, task_uid(p).val, task_uid(current).val);
#ifdef DEBUG
    printk("re_kernel: %s\n", binder_kmsg);
#endif
    send_netlink_message(binder_kmsg, strlen(binder_kmsg));
  }
}

static long inline_hook_init(const char *args, const char *event, void *__user reserved)
{
  lookup_name(__alloc_skb);
  lookup_name(__nlmsg_put);
  lookup_name(kfree_skb);
  lookup_name(netlink_unicast);
  lookup_name(init_net);
  lookup_name(__netlink_kernel_create);
  lookup_name(netlink_kernel_release);
  lookup_name(_binder_inner_proc_lock);
  lookup_name(_binder_inner_proc_unlock);
  lookup_name(binder_get_txn_from_and_acq_inner);
  lookup_name(binder_transaction);
  lookup_name(binder_inc_node_nilocked);
  lookup_name(security_binder_transaction);
  lookup_name(do_send_sig_info);

  hook_func(binder_transaction, 5, binder_transaction_before, 0, 0);
  hook_func(binder_inc_node_nilocked, 4, 0, binder_inc_node_nilocked_after, 0);
  hook_func(security_binder_transaction, 2, security_binder_transaction_before, 0, 0);
  hook_func(do_send_sig_info, 4, do_send_sig_info_before, 0, 0);

  return 0;
}

static long inline_hook_exit(void *__user reserved)
{
  if (rekernel_netlink)
  {
    netlink_kernel_release(rekernel_netlink);
  }
  unhook_func(binder_transaction);
  unhook_func(binder_inc_node_nilocked);
  unhook_func(security_binder_transaction);
  unhook_func(do_send_sig_info);
}

KPM_INIT(inline_hook_init);
KPM_EXIT(inline_hook_exit);
