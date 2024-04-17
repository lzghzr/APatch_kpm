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
#include <asm/atomic.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "../demo.h"
#include "re_kernel.h"

KPM_NAME("re_kernel");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel");

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

atomic_t(*system_freezing_cnt);
bool (*freezing_slow_path)(struct task_struct *p);
struct sk_buff *(*__alloc_skb)(unsigned int size, int /*gfp_t*/ gfp_mask, int flags, int node);
struct nlmsghdr *(*__nlmsg_put)(struct sk_buff *skb, u32 portid, u32 seq, int type, int len, int flags);
void (*kfree_skb)(struct sk_buff *skb);
int (*netlink_unicast)(struct sock *ssk, struct sk_buff *skb, u32 portid, int nonblock);
struct net(*init_net);
struct sock *(*__netlink_kernel_create)(struct net *net, int unit, struct module *module, struct netlink_kernel_cfg *cfg);
void (*netlink_kernel_release)(struct sock *sk);
void (*_binder_inner_proc_lock)(struct binder_proc *proc, int line);
void (*_binder_inner_proc_unlock)(struct binder_proc *proc, int line);
void (*seq_printf)(struct seq_file *m, const char *f, ...);
int (*single_open)(struct file *file, int (*show)(struct seq_file *, void *), void *data);
ssize_t (*seq_read)(struct file *file, char __user *buf, size_t size, loff_t *ppos);
ssize_t (*seq_lseek)(struct file *file, char __user *buf, size_t size, loff_t *ppos);
int (*single_release)(struct inode *inode, struct file *file);
struct proc_dir_entry *(*proc_mkdir)(const char *name, struct proc_dir_entry *parent);
struct proc_dir_entry *(*proc_create)(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops);
struct binder_thread *(*binder_get_txn_from_and_acq_inner)(struct binder_transaction *t);
void (*binder_transaction)(struct binder_proc *proc, struct binder_thread *thread, struct binder_transaction_data *tr, int reply, binder_size_t extra_buffers_size);
int (*binder_inc_node_nilocked)(struct binder_node *node, int strong, int internal, struct list_head *target_list);
int (*security_binder_transaction)(const struct cred *from, const struct cred *to);
int (*do_send_sig_info)(int sig, struct siginfo *info, struct task_struct *p, enum pid_type type);

extern struct task_struct_offset task_struct_offset;
extern struct cred_offset cred_offset;

static int oneway;
struct binder_proc *from_proc, *to_proc;

static struct sock *rekernel_netlink;
static int netlink_unit;
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

static int rekernel_unit_show(struct seq_file *m, void *v)
{
  seq_printf(m, "%d\n", netlink_unit);
  return 0;
}
static int rekernel_unit_open(struct inode *inode, struct file *file)
{
  return single_open(file, rekernel_unit_show, NULL);
}
static ssize_t seq_read_func(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
  return seq_read(file, buf, size, ppos);
}
static ssize_t seq_lseek_func(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
  return seq_lseek(file, buf, size, ppos);
}
static int single_release_func(struct inode *inode, struct file *file)
{
  return single_release(inode, file);
}

static inline bool frozen(struct task_struct *p)
{
  unsigned int flags = *(unsigned int *)((uintptr_t)p + task_struct_offset.stack_offset + 0xf);
  return flags & PF_FROZEN;
}
static inline bool freezing(struct task_struct *p)
{
  if (likely(!atomic_read((atomic_t *)system_freezing_cnt)))
    return false;
  return freezing_slow_path(p);
}
static inline bool line_is_frozen(struct task_struct *task)
{
  return true;
  struct task_struct *group_leader = *(struct task_struct **)((uintptr_t)task + task_struct_offset.thread_pid_offset - 0x5 /* 0x28 */);
  return frozen(group_leader) || freezing(group_leader);
}

static int send_netlink_message(char *msg, uint16_t len)
{
  struct sk_buff *skbuffer;
  struct nlmsghdr *nlhdr;

  int sk_len = (len + 0x13) & 0x1FFFC;
  skbuffer = __alloc_skb(sk_len, 0x480020LL, 0LL, 0xFFFFFFFFLL);
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
  struct netlink_kernel_cfg rekernel_cfg = {
      .input = NULL,
  };
  if (rekernel_netlink)
    return 0;
  for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++)
  {
    rekernel_netlink = __netlink_kernel_create(init_net, netlink_unit, 0LL, &rekernel_cfg);
    if (rekernel_netlink != NULL)
      break;
  }
  if (rekernel_netlink == NULL)
  {
    printk("Failed to create Re:Kernel server!\n");
    return -1;
  }
  printk("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

  rekernel_dir = proc_mkdir("rekernel", NULL);
  const ssize_t seq_reada = seq_read;
  static const struct file_operations rekernel_unit_fops = {
      .open = rekernel_unit_open,
      .read = seq_read_func,
      .llseek = seq_lseek_func,
      .release = single_release_func,
      .owner = THIS_MODULE,
  };
  if (!rekernel_dir)
    printk("create /proc/rekernel failed!\n");
  else
  {
    char buff[32];
    sprintf(buff, "%d", netlink_unit);
    rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir, &rekernel_unit_fops);
    if (!rekernel_unit_entry)
      printk("create rekernel unit failed!\n");
  }
  return 0;
}

static uid_t get_task_uid(struct task_struct *tsk)
{
  struct cred *cred = *(struct cred **)((uintptr_t)tsk + task_struct_offset.cred_offset);
  uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
  return uid;
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

    if (target_proc && (NULL != target_proc->tsk) && (NULL != proc->tsk) && (get_task_uid(target_proc->tsk) > MIN_USERAPP_UID) && (proc->pid != target_proc->pid) && line_is_frozen(target_proc->tsk))
    {
      char binder_kmsg[PACKET_SIZE];
      snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, get_task_uid(proc->tsk), target_proc->pid, get_task_uid(target_proc->tsk));
#ifdef DEBUG
      printk("re_kernel: type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;\n", proc->pid, get_task_uid(proc->tsk), target_proc->pid, get_task_uid(target_proc->tsk));
#endif
      send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
  }
  else
  {
    oneway = tr->flags;
    from_proc = proc;
  }
}

void binder_inc_node_nilocked_after(hook_fargs4_t *args, void *udata)
{
  if (start_rekernel_server() != 0)
  {
    return;
  }
  int strong = (int)args->arg1;
  int internal = (int)args->arg2;
  int target_list = (int)args->arg3;
  if (strong == 1 && internal == 0 && target_list == 0)
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
  struct binder_proc *proc = from_proc;
  struct binder_proc *target_proc = to_proc;
  if (target_proc && (NULL != target_proc->tsk) && (NULL != proc->tsk) && (get_task_uid(target_proc->tsk) <= MAX_SYSTEM_UID) && (proc->pid != target_proc->pid) && line_is_frozen(target_proc->tsk))
  {
    char binder_kmsg[PACKET_SIZE];
    snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", oneway & TF_ONE_WAY, proc->pid, get_task_uid(proc->tsk), target_proc->pid, get_task_uid(target_proc->tsk));
#ifdef DEBUG
    printk("re_kernel: type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;\n", proc->pid, get_task_uid(proc->tsk), target_proc->pid, get_task_uid(target_proc->tsk));
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
    snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer=%d,dst=%d;", sig, get_task_uid(p), get_task_uid(current));
#ifdef DEBUG
    printk("re_kernel: type=Signal,signal=%d,killer=%d,dst=%d;", sig, get_task_uid(p), get_task_uid(current));
#endif
    send_netlink_message(binder_kmsg, strlen(binder_kmsg));
  }
}

static long inline_hook_init(const char *args, const char *event, void *__user reserved)
{
  lookup_name(system_freezing_cnt);
  lookup_name(freezing_slow_path);
  lookup_name(__alloc_skb);
  lookup_name(__nlmsg_put);
  lookup_name(kfree_skb);
  lookup_name(netlink_unicast);
  lookup_name(init_net);
  lookup_name(__netlink_kernel_create);
  lookup_name(netlink_kernel_release);
  lookup_name(_binder_inner_proc_lock);
  lookup_name(_binder_inner_proc_unlock);
  lookup_name(seq_printf);
  lookup_name(single_open);
  lookup_name(seq_read);
  lookup_name(seq_lseek);
  lookup_name(single_release);
  lookup_name(proc_mkdir);
  lookup_name(proc_create);
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
