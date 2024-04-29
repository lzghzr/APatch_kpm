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
#define MAX_SYSTEM_UID 2000
#define RESERVE_ORDER 17
#define WARN_AHEAD_SPACE	(1 << RESERVE_ORDER)

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

struct task_struct* skfunc_def(get_pid_task)(struct pid* pid, enum pid_type type);
struct pid* skfunc_def(get_task_pid)(struct task_struct* task, enum pid_type type);
pid_t skfunc_def(pid_vnr)(struct pid* pid);
struct pid* skfunc_def(find_vpid)(pid_t nr);
// is_frozen_tg
bool (*cgroup_freezing)(struct task_struct* task);
atomic_t skvar_def(system_freezing_cnt);
bool skfunc_def(freezing_slow_path)(struct task_struct* p);
// send_netlink_message
struct sk_buff* skfunc_def(__alloc_skb)(unsigned int size, int /*gfp_t*/ gfp_mask, int flags, int node);
struct nlmsghdr* skfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
void skfunc_def(kfree_skb)(struct sk_buff* skb);
int skfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
// start_rekernel_server
static struct net skvar_def(init_net);
struct sock* skfunc_def(__netlink_kernel_create)(struct net* net, int unit, struct module* module, struct netlink_kernel_cfg* cfg);
void skfunc_def(netlink_kernel_release)(struct sock* sk);
// prco
struct proc_dir_entry* skfunc_def(proc_mkdir)(const char* name, struct proc_dir_entry* parent);
struct proc_dir_entry* skfunc_def(proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops, void* data);
void skfunc_def(proc_remove)(struct proc_dir_entry* de);
// hook binder_alloc_new_buf_locked
static struct binder_buffer* (*binder_alloc_new_buf_locked)(struct binder_alloc* alloc, size_t data_size, size_t offsets_size, size_t extra_buffers_size, int is_async, int pid);
// hook binder_transaction
static struct binder_node* (*binder_get_node_from_ref)(struct binder_proc* proc, u32 desc, bool need_strong_ref, struct binder_ref_data* rdata);
static void (*binder_transaction)(struct binder_proc* proc, struct binder_thread* thread, struct binder_transaction_data* tr, int reply, binder_size_t extra_buffers_size);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);

static long task_struct_group_leader_offset,
context_offset, vma_offset, free_async_space_offset, binder_alloc_offset;

static struct sock* rekernel_netlink;
static long netlink_unit;
static struct proc_dir_entry* rekernel_dir, * rekernel_unit_entry;

static const struct file_operations rekernel_unit_fops = {
    .open = NULL,
    .read = NULL,
    .release = NULL,
    .owner = THIS_MODULE,
};
// pid
static inline pid_t task_pid(struct task_struct* task) {
    struct pid* pid = skfunc(get_task_pid)(task, PIDTYPE_PID);
    return skfunc(pid_vnr)(pid);
}
// tgid
static inline pid_t task_tgid(struct task_struct* task) {
    struct task_struct* group_leader = *(struct task_struct**)((uintptr_t)task + task_struct_group_leader_offset);
    struct pid* group_leader_pid = skfunc(get_task_pid)(group_leader, PIDTYPE_PID);
    return skfunc(pid_vnr)(group_leader_pid);
}
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
static inline bool freezing(struct task_struct* p)
{
    if (likely(!atomic_read(skvar(system_freezing_cnt))))
        return false;
    return skfunc(freezing_slow_path)(p);
}
static inline bool is_frozen_tg(struct task_struct* task)
{
    struct task_struct* group_leader = *(struct task_struct**)((uintptr_t)task + task_struct_group_leader_offset);
    return ((cgroup_task_frozen(task) && is_jobctl_frozen(task)) || frozen(group_leader) || freezing(group_leader);
}

// 发送 netlink 消息
static int send_netlink_message(char* msg, uint16_t len)
{
    struct sk_buff* skbuffer;
    struct nlmsghdr* nlhdr;

    int sk_len = nlmsg_total_size(len);
    skbuffer = skfunc(__alloc_skb)(sk_len, GFP_ATOMIC, 0, NUMA_NO_NODE);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = skfunc(__nlmsg_put)(skbuffer, 0, 0, netlink_unit, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        skfunc(kfree_skb)(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return skfunc(netlink_unicast)(rekernel_netlink, skbuffer, USER_PORT, MSG_DONTWAIT);
}

// 创建 netlink 服务
static int start_rekernel_server(void)
{
    struct netlink_kernel_cfg rekernel_cfg = {
        .input = NULL,
    };
    for (netlink_unit = NETLINK_REKERNEL_MAX; netlink_unit >= NETLINK_REKERNEL_MIN; netlink_unit--) {
        rekernel_netlink = skfunc(__netlink_kernel_create)(skvar(init_net), netlink_unit, THIS_MODULE, &rekernel_cfg);
        if (rekernel_netlink != NULL) {
            break;
        }
    }
    if (rekernel_netlink == NULL) {
        printk("Failed to create Re:Kernel server!\n");
        return -1;
    }
    printk("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

    rekernel_dir = skfunc(proc_mkdir)("rekernel", NULL);
    if (!rekernel_dir) {
        printk("create /proc/rekernel failed!\n");
    } else {
        char buff[32];
        sprintf(buff, "%d", netlink_unit);
        rekernel_unit_entry = skfunc(proc_create_data)(buff, 0644, rekernel_dir, &rekernel_unit_fops, NULL);
        if (!rekernel_unit_entry) {
            printk("create rekernel unit failed!\n");
        }
    }

    return 0;
}

static void binder_alloc_new_buf_locked_before(hook_fargs6_t* args, void* udata)
{
    struct binder_alloc* alloc = (struct binder_alloc*)args->arg0;
    size_t data_size = args->arg1;
    size_t offsets_size = args->arg2;
    size_t extra_buffers_size = args->arg3;
    int is_async = args->arg4;
    // 计算 free_async_space_offset
    if (free_async_space_offset == 0) {
        free_async_space_offset = -1;
        int first = 0;
        for (int i = 0x30;i < 0x100;i += 0x8) {
            u64 ptr = *(u64*)((uintptr_t)alloc + i);
            if (ptr > 1L << 0x8 && ptr < 1L << 0x20) {
                if (first && (i - first) == 0x10) {
                    vma_offset = i - 0x48;
                    free_async_space_offset = i - 0x10;
                    // buffer_size_offset = i;
                    // binder_alloc_pid_offset = i + 0xC;
                    break;
                } else {
                    first = i;
                }
            }
        }
    }
    // 计算 binder_alloc_offset
    if (binder_alloc_offset == 0) {
        binder_alloc_offset = -1;
        int count = 0;
        for (int i = 0;i < 0x200;i += 0x8) {
            u64 ptr = *(u64*)((uintptr_t)alloc - i);
            if (ptr > 1L << 0x30) {
                count++;
            } else {
                count = 0;
            }
            if (count == 8) {
                binder_alloc_offset = i;
                break;
            }
        }
    }

    if (free_async_space_offset <= 0 || binder_alloc_offset <= 0) {
        return;
    }
    if (!*(struct vm_area_struct**)((uintptr_t)alloc + vma_offset)) {
        return;
    }
    size_t size, data_offsets_size;
    data_offsets_size = ALIGN(data_size, sizeof(void*)) + ALIGN(offsets_size, sizeof(void*));
    if (data_offsets_size < data_size || data_offsets_size < offsets_size) {
        return;
    }
    size = data_offsets_size + ALIGN(extra_buffers_size, sizeof(void*));
    if (size < data_offsets_size || size < extra_buffers_size) {
        return;
    }
    size_t free_async_space = *(size_t*)((uintptr_t)alloc + free_async_space_offset);
    if (is_async
        && (free_async_space < 3 * (size + sizeof(struct binder_buffer))
            || (free_async_space < WARN_AHEAD_SPACE))) {
        struct binder_proc* target_proc = *(struct binder_proc**)((uintptr_t)alloc - binder_alloc_offset);
        if (target_proc
            && (NULL != target_proc->tsk)
            && is_frozen_tg(target_proc->tsk)) {
            char binder_kmsg[PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d;", get_current_task_ext()->pid, task_uid(current).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
        }
    }
}

static void binder_transaction_before(hook_fargs5_t* args, void* udata)
{
    struct binder_proc* proc = (struct binder_proc*)args->arg0;
    struct binder_thread* thread = (struct binder_thread*)args->arg1;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)args->arg2;
    int reply = (int)args->arg3;

    if (context_offset == 0) {
        context_offset = -1;
        u64 l_pid = proc->pid * 1L << 0x20;
        int l_pid_offset = 0;
        for (int i = 0x48; i < 0x300; i += 0x8) {
            u64 ptr = *(u64*)((uintptr_t)proc + i);
            if (l_pid == ptr) {
                l_pid_offset = i;
            } else if (l_pid_offset && ptr > 1L << 0x20) {
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
        if (target_proc
            && (NULL != target_proc->tsk)
            && (NULL != proc->tsk)
            && (task_uid(target_proc->tsk).val <= MAX_SYSTEM_UID)
            && (proc->pid != target_proc->pid)
            && is_frozen_tg(target_proc->tsk)) {
            char binder_kmsg[PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
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
        if (target_proc
            && (NULL != target_proc->tsk)
            && (NULL != proc->tsk)
            && (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
            && (proc->pid != target_proc->pid)
            && is_frozen_tg(target_proc->tsk)) {
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
    struct task_struct* dst = (struct task_struct*)args->arg2;

    if (is_frozen_tg(dst)
        && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT)) {
        char binder_kmsg[PACKET_SIZE];
        snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_pid(current), task_uid(current).val, task_pid(dst), task_uid(dst).val);
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
    hook_func(binder_alloc_new_buf_locked, 6, binder_alloc_new_buf_locked_before, 0, 0);
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
    lookup_name(do_filp_open);
    skfunc_lookup_name(get_pid_task);
    skfunc_lookup_name(get_task_pid);
    skfunc_lookup_name(pid_vnr);
    skfunc_lookup_name(find_vpid);
    lookup_name(cgroup_freezing);
    skvar_lookup_name(system_freezing_cnt);
    skfunc_lookup_name(freezing_slow_path);
    skfunc_lookup_name(__alloc_skb);
    skfunc_lookup_name(__nlmsg_put);
    skfunc_lookup_name(kfree_skb);
    skfunc_lookup_name(netlink_unicast);
    skvar_lookup_name(init_net);
    skfunc_lookup_name(__netlink_kernel_create);
    skfunc_lookup_name(netlink_kernel_release);
    skfunc_lookup_name(proc_mkdir);
    skfunc_lookup_name(proc_create_data);
    skfunc_lookup_name(proc_remove);

    // 计算偏移量
    struct task_struct* task = current;
    struct pid* pid = skfunc(get_task_pid)(task, PIDTYPE_PID);
    // task_struct_group_leader_offset
    for (int i = task_struct_offset.active_mm_offset; i < task_struct_offset.cred_offset; i += 0x8) {
        if (*(struct pid**)((uintptr_t)task + i) == pid) {
            // task_struct_thread_pid_offset = i;
            task_struct_group_leader_offset = i - 0x28;
            break;
        }
    }
    if (!task_struct_group_leader_offset) {
        return -11;
    }

    binder_alloc_new_buf_locked = (typeof(binder_alloc_new_buf_locked))kallsyms_lookup_name("binder_alloc_new_buf_locked");
    if (binder_alloc_new_buf_locked) {
        pr_info("kernel function %s addr: %llx\n", "binder_alloc_new_buf_locked", binder_alloc_new_buf_locked);
    } else {
        binder_alloc_new_buf_locked = (typeof(binder_alloc_new_buf_locked))kallsyms_lookup_name("binder_alloc_new_buf");
        if (binder_alloc_new_buf_locked) {
            pr_info("kernel function %s addr: %llx\n", "binder_alloc_new_buf", binder_alloc_new_buf_locked);
        } else {
            return -21;
        }
    }
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
    snprintf(msg, sizeof(msg), "c_p=0x%x, f_p=0x%x, b_p=0x%x\n", context_offset, free_async_space_offset, binder_alloc_offset);
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long inline_hook_exit(void* __user reserved)
{
    if (rekernel_netlink && skfunc(netlink_kernel_release)) {
        skfunc(netlink_kernel_release)(rekernel_netlink);
    }
    if (rekernel_dir && skfunc(proc_remove)) {
        skfunc(proc_remove)(rekernel_dir);
    }
    unhook_func(binder_alloc_new_buf_locked);
    unhook_func(binder_transaction);
    unhook_func(do_send_sig_info);

    return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
