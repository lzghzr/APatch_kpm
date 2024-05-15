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

#ifdef DEBUG
#include <uapi/linux/limits.h>
#endif /* DEBUG */

#include "re_kernel.h"
#include "re_utils.h"

KPM_NAME("re_kernel");
KPM_VERSION(RK_VERSION);
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel, support 4.4, 4.9, 4.14, 4.19, 5.4, 5.10, 5.15");

#define NETLINK_REKERNEL_MAX 26
#define NETLINK_REKERNEL_MIN 22
#define REKERNEL_USER_PORT 100
#define REKERNEL_PACKET_SIZE 128
#define REKERNEL_MIN_USERAPP_UID 10000
#define REKERNEL_MAX_SYSTEM_UID 2000
#define REKERNEL_WARN_AHEAD_MSGS 3
#define REKERNEL_RESERVE_ORDER 17
#define REKERNEL_WARN_AHEAD_SPACE (1 << REKERNEL_RESERVE_ORDER)

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// cgroup_freezing
bool kfunc_def(cgroup_freezing)(struct task_struct* task);
// send_netlink_message
struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
void kfunc_def(kfree_skb)(struct sk_buff* skb);
int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
// start_rekernel_server
static struct net kvar_def(init_net);
struct sock* kfunc_def(__netlink_kernel_create)(struct net* net, int unit, struct module* module, struct netlink_kernel_cfg* cfg);
void kfunc_def(netlink_kernel_release)(struct sock* sk);
// prco
struct proc_dir_entry* kfunc_def(proc_mkdir)(const char* name, struct proc_dir_entry* parent);
struct proc_dir_entry* kfunc_def(proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops, void* data);
void kfunc_def(proc_remove)(struct proc_dir_entry* de);

ssize_t kfunc_def(seq_read)(struct file* file, char __user* buf, size_t size, loff_t* ppos);
loff_t kfunc_def(seq_lseek)(struct file* file, loff_t offset, int whence);
void kfunc_def(seq_printf)(struct seq_file* m, const char* f, ...);
int kfunc_def(single_open)(struct file* file, int (*show)(struct seq_file*, void*), void* data);
int kfunc_def(single_release)(struct inode* inode, struct file* file);
// hook binder_proc_transaction
static int (*binder_proc_transaction)(struct binder_transaction* t, struct binder_proc* proc, struct binder_thread* thread);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);
#ifdef DEBUG
int kfunc_def(get_cmdline)(struct task_struct* task, char* buffer, int buflen);
#endif /* DEBUG */

static uint64_t task_struct_flags_offset = UZERO, task_struct_jobctl_offset = UZERO, task_struct_pid_offset = UZERO, task_struct_group_leader_offset = UZERO, task_struct_frozen_offset = UZERO, task_struct_css_set_offset = UZERO,
binder_proc_alloc_offset = UZERO,
binder_alloc_pid_offset = UZERO, binder_alloc_buffer_size_offset = UZERO, binder_alloc_free_async_space_offset = UZERO, binder_alloc_vma_offset = UZERO,
css_set_dfl_cgrp_offset = UZERO,
cgroup_flags_offset = UZERO,
task_struct_frozen_bit = UZERO;

static struct sock* rekernel_netlink;
static unsigned long rekernel_netlink_unit = UZERO;
static struct proc_dir_entry* rekernel_dir, * rekernel_unit_entry;

// pid
static inline pid_t task_pid(struct task_struct* task)
{
    pid_t pid = *(pid_t*)((uintptr_t)task + task_struct_pid_offset);
    return pid;
}
// tgid
static inline pid_t task_tgid(struct task_struct* task)
{
    pid_t tgid = *(pid_t*)((uintptr_t)task + task_struct_pid_offset + 0x4);
    return tgid;
}
// 判断线程是否进入 frozen 状态
static inline bool cgroup_task_frozen(struct task_struct* task)
{
    if (task_struct_frozen_offset == UZERO) {
        return false;
    }
    unsigned int frozen = *(unsigned int*)((uintptr_t)task + task_struct_frozen_offset);
    return bit(frozen, task_struct_frozen_bit);
}
static inline bool cgroup_task_freeze(struct task_struct* task)
{
    bool ret = false;
    if (task_struct_css_set_offset == UZERO || css_set_dfl_cgrp_offset == UZERO || cgroup_flags_offset == UZERO) {
        return false;
    }

    struct css_set* css_set = *(struct css_set**)((uintptr_t)task + task_struct_css_set_offset);
    struct cgroup* cgrp = *(struct cgroup**)((uintptr_t)css_set + css_set_dfl_cgrp_offset);
    unsigned long cgrp_flags = *(unsigned long*)((uintptr_t)cgrp + cgroup_flags_offset);
    ret = bit(cgrp_flags, CGRP_FREEZE);
    return ret;
}
static inline bool frozen(struct task_struct* p)
{
    unsigned int flags = *(unsigned int*)((uintptr_t)p + task_struct_flags_offset);
    return (flags & PF_FROZEN);
}
static inline bool frozen_task_group(struct task_struct* task)
{
    return (cgroup_task_frozen(task) || cgroup_task_freeze(task) || cgroup_freezing(task) || frozen(task));
}

// 发送 netlink 消息
static int send_netlink_message(char* msg, uint16_t len)
{
    struct sk_buff* skbuffer;
    struct nlmsghdr* nlhdr;

    skbuffer = nlmsg_new(len, GFP_ATOMIC);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = nlmsg_put(skbuffer, 0, 0, rekernel_netlink_unit, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        nlmsg_free(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(rekernel_netlink, skbuffer, REKERNEL_USER_PORT, MSG_DONTWAIT);
}

// 创建 netlink 服务
static __noinline void netlink_rcv_msg(struct sk_buff* skb) {
}

static int rekernel_unit_show(struct seq_file* m, void* v)
{
    kfunc(seq_printf)(m, "%d\n", rekernel_netlink_unit);
    return 0;
}
static __noinline int rekernel_unit_open(struct inode* inode, struct file* file)
{
    return single_open(file, rekernel_unit_show, NULL);
}
static __noinline ssize_t seq_read(struct file* file, char __user* buf, size_t size, loff_t* ppos) {
    return kfunc(seq_read)(file, buf, size, ppos);
}
static __noinline loff_t seq_lseek(struct file* file, loff_t offset, int whence) {
    return kfunc(seq_lseek)(file, offset, whence);
}
static __noinline int single_release(struct inode* inode, struct file* file) {
    return kfunc(single_release)(inode, file);
}
static const struct file_operations rekernel_unit_fops = {
    .open = rekernel_unit_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .owner = THIS_MODULE,
};

static int start_rekernel_server(void)
{
    if (rekernel_netlink_unit != UZERO) {
        return 0;
    }

    struct netlink_kernel_cfg rekernel_cfg = {
        .input = netlink_rcv_msg,
    };

    for (rekernel_netlink_unit = NETLINK_REKERNEL_MAX; rekernel_netlink_unit >= NETLINK_REKERNEL_MIN; rekernel_netlink_unit--) {
        rekernel_netlink = netlink_kernel_create(kvar(init_net), rekernel_netlink_unit, &rekernel_cfg);
        if (rekernel_netlink != NULL) {
            break;
        }
    }
    if (rekernel_netlink == NULL) {
        printk("Failed to create Re:Kernel server!\n");
        return -1;
    }
    printk("Created Re:Kernel server! NETLINK UNIT: %d\n", rekernel_netlink_unit);

    rekernel_dir = proc_mkdir("rekernel", NULL);
    if (!rekernel_dir) {
        printk("create /proc/rekernel failed!\n");
    } else {
        char buff[32];
        sprintf(buff, "%d", rekernel_netlink_unit);
        rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir, &rekernel_unit_fops);
        if (!rekernel_unit_entry) {
            printk("create rekernel unit failed!\n");
        }
    }

    return 0;
}

static void binder_proc_transaction_before(hook_fargs3_t* args, void* udata) {
    if (start_rekernel_server() != 0) {
        return;
    }
    struct binder_transaction* t = (struct binder_transaction*)args->arg0;
    struct binder_proc* target_proc = (struct binder_proc*)args->arg1;

    if (!t->from) { // oneway=1
#ifndef QUIET
        struct binder_alloc* target_alloc = (struct binder_alloc*)((uintptr_t)target_proc + binder_proc_alloc_offset);
        size_t free_async_space = *(size_t*)((uintptr_t)target_alloc + binder_alloc_free_async_space_offset);
        size_t buffer_size = *(size_t*)((uintptr_t)target_alloc + binder_alloc_buffer_size_offset);
        if (target_proc->tsk
            && frozen_task_group(target_proc->tsk)) {
            if (free_async_space < (buffer_size / 10 + 0x300)) {
                char binder_kmsg[REKERNEL_PACKET_SIZE];
                snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d;", task_pid(current), task_uid(current).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
                printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
                send_netlink_message(binder_kmsg, strlen(binder_kmsg));
            }
        }
#endif /* QUIET */
    } else {
        struct binder_proc* proc = t->from->proc;
        if (proc
            && proc->tsk
            && target_proc->tsk
            && task_uid(target_proc->tsk).val > REKERNEL_MIN_USERAPP_UID
            && proc->pid != target_proc->pid
            && frozen_task_group(target_proc->tsk)) {
            char binder_kmsg[REKERNEL_PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
        }
    }
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata) {
    if (start_rekernel_server() != 0) {
        return;
    }
    int sig = (int)args->arg0;
    struct task_struct* dst = (struct task_struct*)args->arg2;

    if ((sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT)
        && frozen_task_group(dst)) {
        char binder_kmsg[REKERNEL_PACKET_SIZE];
        snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_tgid(current), task_uid(current).val, task_tgid(dst), task_uid(dst).val);
#ifdef DEBUG
        char cmdline[PATH_MAX];
        memset(&cmdline, 0, PATH_MAX);
        int res = get_cmdline(current, cmdline, PATH_MAX - 1);
        cmdline[res] = '\0';
        printk("re_kernel: %s cmdline=%s,comm=%s\n", binder_kmsg, cmdline, get_task_comm(current));
#endif /* DEBUG */
        send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
}

static long calculate_offsets()
{
    // 获取 cgroup 相关偏移，没有就是不支持 CGRP_FREEZE
    // cgroup_exit_count = 1; task->css_set
    // cgroup_exit_count = 2; css_set->dfl_cgrp
    // cgroup_exit_count = 3; cgroup->flags
    void (*cgroup_exit)(struct task_struct* task);
    lookup_name(cgroup_exit);

    bool cgroup_exit_start = false;
    u32 cgroup_exit_count = 0;
    uint32_t* cgroup_exit_src = (uint32_t*)cgroup_exit;
    for (u32 i = 0; i < 0x50; i++) {
#ifdef DEBUG
        printk("re_kernel: cgroup_exit %x %llx\n", i, cgroup_exit_src[i]);
#endif /* DEBUG */
        if (cgroup_exit_src[i] == ARM64_RET) {
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 2 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            cgroup_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 1 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            css_set_dfl_cgrp_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 2;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            task_struct_css_set_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 1;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_ADD_64) == INST_ADD_64) {
            uint32_t sh = bit(cgroup_exit_src[i], 22);
            uint64_t imm12 = imm12 = bits32(cgroup_exit_src[i], 21, 10);
            if (sh) {
                task_struct_css_set_offset = sign64_extend((imm12 << 12u), 16u);
            } else {
                task_struct_css_set_offset = sign64_extend((imm12), 16u);
            }
            cgroup_exit_count = 1;
        } else if ((cgroup_exit_src[i] & MASK_TBNZ) == INST_TBNZ) {
            cgroup_exit_start = true;
        }
    }
    // 获取 task_struct->frozen, task_struct->jobctl, 没有就是不支持 PF_FROZEN
    void (*recalc_sigpending_and_wake)(struct task_struct* t);
    lookup_name(recalc_sigpending_and_wake);

    uint32_t* recalc_sigpending_and_wake_src = (uint32_t*)recalc_sigpending_and_wake;
    for (u32 i = 0; i < 0x20; i++) {
#ifdef DEBUG
        printk("re_kernel: recalc_sigpending_and_wake %x %llx\n", i, recalc_sigpending_and_wake_src[i]);
#endif /* DEBUG */
        if (recalc_sigpending_and_wake_src[i] == ARM64_RET) {
            break;
        } else if ((recalc_sigpending_and_wake_src[i] & MASK_TBZ) == INST_TBZ || (recalc_sigpending_and_wake_src[i] & MASK_TBNZ) == INST_TBNZ) {
            if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRB) == INST_LDRB) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12), 16u);
                break;
            } else if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRH) == INST_LDRH) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12 << 1u), 16u);
                break;
            }
        } else if ((recalc_sigpending_and_wake_src[i] & MASK_LDRB_X0) == INST_LDRB_X0) {
            uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i], 21, 10);
            task_struct_jobctl_offset = sign64_extend((imm12), 16u) - 0x2;
        }
    }
    // 获取 binder_proc->alloc
    void (*binder_free_proc)(struct binder_proc* proc);
    binder_free_proc = (typeof(binder_free_proc))kallsyms_lookup_name("binder_free_proc");
    if (!binder_free_proc) {
        binder_free_proc = (typeof(binder_free_proc))kallsyms_lookup_name("binder_proc_dec_tmpref");
    }

    uint32_t* binder_free_proc_src = (uint32_t*)binder_free_proc;
    for (u32 i = 0; i < 0x70; i++) {
#ifdef DEBUG
        printk("re_kernel: binder_free_proc %x %llx\n", i, binder_free_proc_src[i]);
#endif /* DEBUG */
        if ((binder_free_proc_src[i] & MASK_ADD_64_Rn_X19_Rd_X0) == INST_ADD_64_Rn_X19_Rd_X0) {
            uint32_t sh = bit(binder_free_proc_src[i], 22);
            uint64_t imm12 = imm12 = bits32(binder_free_proc_src[i], 21, 10);
            if (sh) {
                binder_proc_alloc_offset = sign64_extend((imm12 << 12u), 16u);
            } else {
                binder_proc_alloc_offset = sign64_extend((imm12), 16u);
            }
            break;
        }
    }
    if (binder_proc_alloc_offset == UZERO) {
        return -11;
    }
    // 获取 binder_alloc->pid, task_struct->pid, task_struct->group_leader
    void (*binder_alloc_init)(struct task_struct* t);
    lookup_name(binder_alloc_init);

    uint32_t* binder_alloc_init_src = (uint32_t*)binder_alloc_init;
    for (u32 i = 0; i < 0x20; i++) {
#ifdef DEBUG
        printk("re_kernel: binder_alloc_init %x %llx\n", i, binder_alloc_init_src[i]);
#endif /* DEBUG */
        if (binder_alloc_init_src[i] == ARM64_RET) {
            break;
        } else if ((binder_alloc_init_src[i] & MASK_STR_32_x0) == INST_STR_32_x0) {
            uint64_t imm12 = bits32(binder_alloc_init_src[i], 21, 10);
            binder_alloc_pid_offset = sign64_extend((imm12 << 0b10u), 16u); // 0x74
            binder_alloc_buffer_size_offset = binder_alloc_pid_offset - 0xC; // 0x68
            binder_alloc_free_async_space_offset = binder_alloc_pid_offset - 0x1C; // 0x58
            binder_alloc_vma_offset = binder_alloc_pid_offset - 0x54;              // 0x20
            break;
        } else if ((binder_alloc_init_src[i] & MASK_LDR_32_) == INST_LDR_32_) {
            uint64_t imm12 = bits32(binder_alloc_init_src[i], 21, 10);
            task_struct_pid_offset = sign64_extend((imm12 << 0b10u), 16u);
        } else if ((binder_alloc_init_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(binder_alloc_init_src[i], 21, 10);
            task_struct_group_leader_offset = sign64_extend((imm12 << 0b11u), 16u);
        }
    }
    if (binder_alloc_pid_offset == UZERO || task_struct_pid_offset == UZERO || task_struct_group_leader_offset == UZERO) {
        return -11;
    }
    // 获取 task_struct->flags
    bool (*freezing_slow_path)(struct task_struct* p);
    lookup_name(freezing_slow_path);

    uint32_t* freezing_slow_path_src = (uint32_t*)freezing_slow_path;
    for (u32 i = 0; i < 0x20; i++) {
#ifdef DEBUG
        printk("re_kernel: freezing_slow_path %x %llx\n", i, freezing_slow_path_src[i]);
#endif /* DEBUG */
        if (freezing_slow_path_src[i] == ARM64_RET) {
            break;
        } else if ((freezing_slow_path_src[i] & MASK_LDR_32_X0) == INST_LDR_32_X0) {
            uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
            task_struct_flags_offset = sign64_extend((imm12 << 0b10u), 16u);
            break;
        } else if ((freezing_slow_path_src[i] & MASK_LDR_64_X0) == INST_LDR_64_X0) {
            uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
            task_struct_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        }
    }
    if (task_struct_flags_offset == UZERO) {
        return -11;
    }

    return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved)
{
    kfunc_lookup_name(cgroup_freezing);
    kfunc_lookup_name(__alloc_skb);
    kfunc_lookup_name(__nlmsg_put);
    kfunc_lookup_name(kfree_skb);
    kfunc_lookup_name(netlink_unicast);
    kvar_lookup_name(init_net);
    kfunc_lookup_name(__netlink_kernel_create);
    kfunc_lookup_name(netlink_kernel_release);
    kfunc_lookup_name(proc_mkdir);
    kfunc_lookup_name(proc_create_data);
    kfunc_lookup_name(proc_remove);
    kfunc_lookup_name(seq_read);
    kfunc_lookup_name(seq_lseek);
    kfunc_lookup_name(seq_printf);
    kfunc_lookup_name(single_open);
    kfunc_lookup_name(single_release);
#ifdef DEBUG
    kfunc_lookup_name(get_cmdline);
#endif /* DEBUG */

    lookup_name(binder_proc_transaction);
    lookup_name(do_send_sig_info);

    int rc = calculate_offsets();
    if (rc < 0) {
        return rc;
    }

    hook_func(binder_proc_transaction, 3, binder_proc_transaction_before, NULL, NULL);
    hook_func(do_send_sig_info, 4, do_send_sig_info_before, NULL, NULL);

    return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen)
{
    printk("re_kernel:\n\
task_struct_flags_offset=0x%llx\n\
task_struct_jobctl_offset=0x%llx\n\
task_struct_pid_offset=0x%llx\n\
task_struct_group_leader_offset=0x%llx\n\
task_struct_frozen_offset=0x%llx\n\
task_struct_css_set_offset=0x%llx\n",
task_struct_flags_offset,
task_struct_jobctl_offset,
task_struct_pid_offset,
task_struct_group_leader_offset,
task_struct_frozen_offset,
task_struct_css_set_offset);
    printk("re_kernel:\
binder_proc_alloc_offset=0x%llx\n\
binder_alloc_pid_offset=0x%llx\n\
binder_alloc_buffer_size_offset=0x%llx\n\
binder_alloc_free_async_space_offset=0x%llx\n\
binder_alloc_vma_offset=0x%llx\n",
binder_proc_alloc_offset,
binder_alloc_pid_offset,
binder_alloc_buffer_size_offset,
binder_alloc_free_async_space_offset,
binder_alloc_vma_offset);
    printk("re_kernel:\
css_set_dfl_cgrp_offset=0x%llx\n\
cgroup_flags_offset=0x%llx\n\
task_struct_frozen_bit=0x%llx\n",
css_set_dfl_cgrp_offset,
cgroup_flags_offset,
task_struct_frozen_bit);
    char msg[64];
    snprintf(msg, sizeof(msg), "_(._.)_");
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long inline_hook_exit(void* __user reserved)
{
    if (rekernel_netlink) {
        netlink_kernel_release(rekernel_netlink);
    }
    if (rekernel_dir) {
        proc_remove(rekernel_dir);
    }

    unhook_func(binder_proc_transaction);
    unhook_func(do_send_sig_info);

    return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
