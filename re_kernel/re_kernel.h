#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>
#include <linux/include/linux/export.h>

// android/binder.c
struct binder_alloc;

typedef atomic_t atomic_long_t;
struct mutex {
    atomic_long_t owner;
    spinlock_t wait_lock;
    // unknow
};

struct rb_node {
    unsigned long __rb_parent_color;
    struct rb_node* rb_right;
    struct rb_node* rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
    struct rb_node* rb_node;
};
struct binder_context {
    struct binder_node* binder_context_mgr_node;
    struct mutex context_mgr_node_lock;
    // unknow
};
struct binder_alloc;
struct binder_proc {
    struct hlist_node proc_node;
    struct rb_root threads;
    struct rb_root nodes;
    struct rb_root refs_by_desc;
    struct rb_root refs_by_node;
    struct list_head waiting_threads;
    int pid;
    struct task_struct* tsk;
    // unknow
};

struct binder_priority {
    unsigned int sched_policy;
    int prio;
};
struct binder_work {
    struct list_head entry;
    enum binder_work_type {
        BINDER_WORK_TRANSACTION = 1,
        BINDER_WORK_TRANSACTION_COMPLETE,
        BINDER_WORK_RETURN_ERROR,
        BINDER_WORK_NODE,
        BINDER_WORK_DEAD_BINDER,
        BINDER_WORK_DEAD_BINDER_AND_CLEAR,
        BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
    } type;
};
struct binder_transaction {
    int debug_id;
    struct binder_work work;
    struct binder_thread* from;
    struct binder_transaction* from_parent;
    struct binder_proc* to_proc;
    struct binder_thread* to_thread;
    struct binder_transaction* to_parent;
    unsigned need_reply : 1;
    struct binder_buffer* buffer;
    unsigned int code;
    unsigned int flags;
    struct binder_priority priority;
    struct binder_priority saved_priority;
    bool set_priority_called;
    // unknow
};

struct binder_error {
    struct binder_work work;
    uint32_t cmd;
};
struct wait_queue_head {
    spinlock_t lock;
    struct list_head head;
};
typedef struct wait_queue_head wait_queue_head_t;
enum binder_stat_types {
    BINDER_STAT_PROC,
    BINDER_STAT_THREAD,
    BINDER_STAT_NODE,
    BINDER_STAT_REF,
    BINDER_STAT_DEATH,
    BINDER_STAT_TRANSACTION,
    BINDER_STAT_TRANSACTION_COMPLETE,
    BINDER_STAT_COUNT
};
struct binder_stats {
    atomic_t br[(((29201u) >> 0) & ((1 << 8) - 1)) + 1];
    atomic_t bc[(((1078485778) >> 0) & ((1 << 8) - 1)) + 1];
    atomic_t obj_created[BINDER_STAT_COUNT];
    atomic_t obj_deleted[BINDER_STAT_COUNT];
};
struct binder_thread {
    struct binder_proc* proc;
    struct rb_node rb_node;
    struct list_head waiting_thread_node;
    int pid;
    int looper;
    bool looper_need_return;
    struct binder_transaction* transaction_stack;
    struct list_head todo;
    bool process_todo;
    struct binder_error return_error;
    struct binder_error reply_error;
    wait_queue_head_t wait;
    struct binder_stats stats;
    atomic_t tmp_ref;
    bool is_dead;
    struct task_struct* task;
    // unknow
};

// linux/netlink.h
struct sk_buff ;
struct net;
struct sock;
struct netlink_kernel_cfg {
    unsigned int groups;
    unsigned int flags;
    void (*input)(struct sk_buff* skb);
    struct mutex* cb_mutex;
    int (*bind)(struct net* net, int group);
    void (*unbind)(struct net* net, int group);
    bool (*compare)(struct net* net, struct sock* sk);
};

struct nlmsghdr {
    __u32 nlmsg_len;
    __u16 nlmsg_type;
    __u16 nlmsg_flags;
    __u32 nlmsg_seq;
    __u32 nlmsg_pid;
};
#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)

// linux/gfp.h
#define NUMA_NO_NODE (-1)
#define ___GFP_HIGH 0x20u
#define ___GFP_ATOMIC 0x80000u
#define ___GFP_KSWAPD_RECLAIM 0x400000u
#define __GFP_HIGH ((__force gfp_t)___GFP_HIGH)
#define __GFP_ATOMIC ((__force gfp_t)___GFP_ATOMIC)
#define __GFP_KSWAPD_RECLAIM ((__force gfp_t)___GFP_KSWAPD_RECLAIM)
#define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)

// linux/fs.h
struct kiocb;
struct iov_iter;
struct dir_context;
struct poll_table_struct;
struct vm_area_struct;
struct file_lock;
struct page;
struct pipe_inode_info;
struct seq_file;
struct open_flags;
struct file_operations {
    struct module* owner;
    loff_t(*llseek)(struct file*, loff_t, int);
    ssize_t(*read)(struct file*, char __user*, size_t, loff_t*);
    ssize_t(*write)(struct file*, const char __user*, size_t, loff_t*);
    ssize_t(*read_iter)(struct kiocb*, struct iov_iter*);
    ssize_t(*write_iter)(struct kiocb*, struct iov_iter*);
    int (*iterate)(struct file*, struct dir_context*);
    int (*iterate_shared)(struct file*, struct dir_context*);
    __poll_t(*poll)(struct file*, struct poll_table_struct*);
    long (*unlocked_ioctl)(struct file*, unsigned int, unsigned long);
    long (*compat_ioctl)(struct file*, unsigned int, unsigned long);
    int (*mmap)(struct file*, struct vm_area_struct*);
    unsigned long mmap_supported_flags;
    int (*open)(struct inode*, struct file*);
    int (*flush)(struct file*, fl_owner_t id);
    int (*release)(struct inode*, struct file*);
    int (*fsync)(struct file*, loff_t, loff_t, int datasync);
    int (*fasync)(int, struct file*, int);
    int (*lock)(struct file*, int, struct file_lock*);
    ssize_t(*sendpage)(struct file*, struct page*, int, size_t, loff_t*, int);
    unsigned long (*get_unmapped_area)(struct file*, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock)(struct file*, int, struct file_lock*);
    ssize_t(*splice_write)(struct pipe_inode_info*, struct file*, loff_t*, size_t, unsigned int);
    ssize_t(*splice_read)(struct file*, loff_t*, struct pipe_inode_info*, size_t, unsigned int);
    int (*setlease)(struct file*, long, struct file_lock**, void**);
    long (*fallocate)(struct file* file, int mode, loff_t offset,
        loff_t len);
    void (*show_fdinfo)(struct seq_file* m, struct file* f);
    // unknow
};

// linux/schde.h
#define PF_FROZEN 0x00010000

struct task_struct {
    unsigned int __state;
    // unknow
};

// uapi/asm/signal.h
#define SIGQUIT 3
#define SIGABRT 6
#define SIGKILL 9
#define SIGTERM 15

struct siginfo;

// linux/socket.h
#define MSG_DONTWAIT 0x40

// include/linux/cgroup-defs.h
enum {
    CGRP_NOTIFY_ON_RELEASE,
    CGRP_CPUSET_CLONE_CHILDREN,
    CGRP_FREEZE,
    CGRP_FROZEN,
};
struct cgroup;
struct css_set;

#endif /* __RE_KERNEL_H */
