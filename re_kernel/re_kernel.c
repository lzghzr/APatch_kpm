/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

/*   SPDX-License-Identifier: GPL-3.0-only   */
/*
 * Copyright (C) 2024 Nep-Timeline. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "../demo.h"
#include "re_kernel.h"

KPM_NAME("re_kernel");
KPM_VERSION(RK_VERSION);
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel, support 4.9, 4.19, 5.4, 5.15");

#define NETLINK_REKERNEL_MAX 26
#define NETLINK_REKERNEL_MIN 22
#define USER_PORT 100
#define PACKET_SIZE 128
#define MIN_USERAPP_UID 10000

#define SIGQUIT 3
#define SIGABRT 6
#define SIGKILL 9
#define SIGTERM 15
#define PF_FROZEN 0x00010000
#define JOBCTL_TRAP_FREEZE_BIT 23
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)
#define MSG_DONTWAIT 0x40

// 延迟加载, KernelPatch支持 事件加载 后弃用
static struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);
// send_netlink_message
static struct sk_buff* (*__alloc_skb)(unsigned int size, int /*gfp_t*/ gfp_mask, int flags, int node);
static struct nlmsghdr* (*__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
static void (*kfree_skb)(struct sk_buff* skb);
static int (*netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
// start_rekernel_server
static struct net(*init_net);
static struct sock* (*__netlink_kernel_create)(struct net* net, int unit, struct module* module, struct netlink_kernel_cfg* cfg);
static void (*netlink_kernel_release)(struct sock* sk);
// prco
static struct proc_dir_entry* (*proc_mkdir)(const char* name, struct proc_dir_entry* parent);
static struct proc_dir_entry* (*proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops, void* data);
static void (*proc_remove)(struct proc_dir_entry* de);
// hook binder_transaction
static struct binder_node* (*binder_get_node_from_ref)(struct binder_proc* proc, u32 desc, bool need_strong_ref, struct binder_ref_data* rdata);
static void (*binder_transaction)(struct binder_proc* proc, struct binder_thread* thread, struct binder_transaction_data* tr, int reply, binder_size_t extra_buffers_size);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);

static long group_leader_offset, context_offset;

static struct sock* rekernel_netlink;
static long netlink_unit;
static struct proc_dir_entry* rekernel_dir, * rekernel_unit_entry;

static const struct file_operations rekernel_unit_fops = {
    .open = NULL,
    .read = NULL,
    .release = NULL,
    .owner = THIS_MODULE,
};

// 判断线程是否进入 frozen 状态
static inline bool is_jobctl_frozen(struct task_struct* task)
{
    unsigned int jobctl = *(unsigned int*)((uintptr_t)task + task_struct_offset.active_mm_offset + 0x58);
    return ((jobctl & JOBCTL_TRAP_FREEZE) != 0);
}
static inline bool frozen(struct task_struct* p)
{
    unsigned int flags = *(unsigned int*)((uintptr_t)p + task_struct_offset.stack_offset + 0xC);
    return flags & PF_FROZEN;
}
static inline bool is_frozen_tg(struct task_struct* task)
{
    struct task_struct* group_leader = *(struct task_struct**)((uintptr_t)task + group_leader_offset);
    return is_jobctl_frozen(task) || frozen(group_leader);
}

// 发送 netlink 消息
static int send_netlink_message(char* msg, uint16_t len)
{
    struct sk_buff* skbuffer;
    struct nlmsghdr* nlhdr;

    int sk_len = nlmsg_total_size(len);
    skbuffer = __alloc_skb(sk_len, GFP_ATOMIC, 0, NUMA_NO_NODE);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = __nlmsg_put(skbuffer, 0, 0, netlink_unit, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        kfree_skb(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(rekernel_netlink, skbuffer, USER_PORT, MSG_DONTWAIT);
}

// 创建 netlink 服务
static int start_rekernel_server(void)
{
    struct netlink_kernel_cfg rekernel_cfg = {
        .input = NULL,
    };
    for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
        rekernel_netlink = __netlink_kernel_create(init_net, netlink_unit, THIS_MODULE, &rekernel_cfg);
        if (rekernel_netlink != NULL) {
            break;
        }
    }
    if (rekernel_netlink == NULL) {
        printk("Failed to create Re:Kernel server!\n");
        return -1;
    }
    printk("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

    rekernel_dir = proc_mkdir("rekernel", NULL);
    if (!rekernel_dir) {
        printk("create /proc/rekernel failed!\n");
    } else {
        char buff[32];
        sprintf(buff, "%d", netlink_unit);
        rekernel_unit_entry = proc_create_data(buff, 0644, rekernel_dir, &rekernel_unit_fops, NULL);
        if (!rekernel_unit_entry) {
            printk("create rekernel unit failed!\n");
        }
    }

    return 0;
}

static void binder_transaction_before(hook_fargs5_t* args, void* udata)
{
    struct binder_proc* proc = (struct binder_proc*)args->arg0;
    struct binder_thread* thread = (struct binder_thread*)args->arg1;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)args->arg2;
    int reply = (int)args->arg3;

    if (context_offset == 0) {
        context_offset = -1;
        u64 l_pid = proc->pid * 0x100000000;
        int l_pid_offset = 0;
        for (int i = 0x48; i < 0x300; i += 0x8) {
            u64 ptr = *(u64*)((uintptr_t)proc + i);
            if (l_pid == ptr) {
                l_pid_offset = i;
            } else if (l_pid_offset && ptr > 0x100000000) {
                context_offset = i;
                break;
            }
        }
    }

    struct binder_proc* target_proc = NULL;
    struct binder_node* target_node = NULL;
    if (reply) {
        struct binder_transaction* in_reply_to = thread->transaction_stack;
        if (in_reply_to == NULL || in_reply_to->to_thread != thread) {
            return;
        }
        struct binder_thread* target_thread = in_reply_to->from;
        if (target_thread == NULL || target_thread->transaction_stack != in_reply_to) {
            return;
        }
        target_proc = target_thread->proc;

        // 目前测试下来并无有效数据
#ifdef DEBUG
        if (target_proc && target_proc->tsk && (proc->pid != target_proc->pid) && is_jobctl_frozen(target_proc->tsk))
#else
        if (!(tr->flags & TF_ONE_WAY) && target_proc && target_proc->tsk && (task_uid(target_proc->tsk).val <= MIN_USERAPP_UID) && (proc->pid != target_proc->pid) && is_jobctl_frozen(target_proc->tsk))
#endif
        {
            char binder_kmsg[PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", tr->flags & TF_ONE_WAY, thread->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
        }
    } else {
        if (tr->target.handle) {
            target_node = binder_get_node_from_ref(proc, tr->target.handle, true, NULL);
            if (target_node) {
                target_proc = target_node->proc;
            }
        } else if (context_offset > 0) {
            struct binder_context* context = *(struct binder_context**)((uintptr_t)proc + context_offset);
            target_node = context->binder_context_mgr_node;
            if (target_node) {
                target_proc = target_node->proc;
            }
        }

        // 目前测试下来只有 oneway=0, target>10000 时数据有效
#ifdef DEBUG
        if (target_proc && target_proc->tsk && (proc->pid != target_proc->pid) && is_jobctl_frozen(target_proc->tsk))
#else
        if (!(tr->flags & TF_ONE_WAY) && target_proc && target_proc->tsk && (task_uid(target_proc->tsk).val >= MIN_USERAPP_UID) && (proc->pid != target_proc->pid) && is_jobctl_frozen(target_proc->tsk))
#endif
        {
            char binder_kmsg[PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", (tr->flags & TF_ONE_WAY), proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
        }
    }
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata)
{
    int sig = (int)args->arg0;
    struct task_struct* p = (struct task_struct*)args->arg2;

    if (is_jobctl_frozen(p) && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT)) {
        char binder_kmsg[PACKET_SIZE];
        snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer=%d,dst=%d;", sig, task_uid(p).val, task_uid(current).val);
#ifdef DEBUG
        printk("re_kernel: %s\n", binder_kmsg);
#endif
        send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
}

static long start_hook()
{
    if (start_rekernel_server() != 0) {
        return -1;
    }
    hook_func(binder_transaction, 5, binder_transaction_before, 0, 0);
    hook_func(do_send_sig_info, 4, do_send_sig_info_before, 0, 0);
    return 0;
}

static char ap[] = "/proc/";
static void do_filp_open_after(hook_fargs3_t* args, void* udata)
{
    char** fname = *(char***)args->arg1;
    if (unlikely(!memcmp(fname, ap, sizeof(ap) - 1))) {
        start_hook();
        unhook_func(do_filp_open);
    }
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved)
{
    struct pid* (*get_task_pid)(struct task_struct* task, enum pid_type type);
    lookup_name(get_task_pid);
    struct task_struct* task = current;
    struct pid* pid = get_task_pid(task, PIDTYPE_PID);
    for (int i = task_struct_offset.active_mm_offset; i < task_struct_offset.cred_offset; i += 0x8) {
        if (*(struct pid**)((uintptr_t)task + i) == pid) {
            group_leader_offset = i - 0x28;
            break;
        }
    }
    if (!group_leader_offset) {
        return -11;
    }

    lookup_name(do_filp_open);
    lookup_name(__alloc_skb);
    lookup_name(__nlmsg_put);
    lookup_name(kfree_skb);
    lookup_name(netlink_unicast);
    lookup_name(init_net);
    lookup_name(__netlink_kernel_create);
    lookup_name(netlink_kernel_release);
    lookup_name(proc_mkdir);
    lookup_name(proc_create_data);
    lookup_name(proc_remove);
    lookup_name(binder_get_node_from_ref);
    lookup_name(binder_transaction);
    lookup_name(do_send_sig_info);

    char load_file[] = "load-file";
    if (event && !memcmp(event, load_file, sizeof(load_file))) {
        return start_hook();
    } else {
        hook_func(do_filp_open, 3, 0, do_filp_open_after, 0);
    }

    return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen)
{
    char msg[64];
    snprintf(msg, sizeof(msg), "g_p=0x%x, c_p=0x%x\n", group_leader_offset, context_offset);
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long inline_hook_exit(void* __user reserved)
{
    if (rekernel_netlink && netlink_kernel_release) {
        netlink_kernel_release(rekernel_netlink);
    }
    if (rekernel_dir && proc_remove) {
        proc_remove(rekernel_dir);
    }
    unhook_func(binder_transaction);
    unhook_func(do_send_sig_info);

    return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
