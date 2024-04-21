#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define THIS_MODULE ((struct module *)0)

// uapi/linux/android/binder.h
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;

enum transaction_flags {
    TF_ONE_WAY = 0x01,     /* this is a one-way call: async, no return */
    TF_ROOT_OBJECT = 0x04, /* contents are the component's root object */
    TF_STATUS_CODE = 0x08, /* contents are a 32-bit status code */
    TF_ACCEPT_FDS = 0x10,  /* allow replies with file descriptors */
};

struct binder_transaction_data {
    /* The first two are only used for bcTRANSACTION and brTRANSACTION,
     * identifying the target and contents of the transaction.
     */
    union {
        /* target descriptor of command transaction */
        __u32 handle;
        /* target descriptor of return transaction */
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie; /* target object cookie */
    __u32 code;              /* transaction command */

    /* General information about the transaction. */
    __u32 flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size;    /* number of bytes of data */
    binder_size_t offsets_size; /* number of bytes of offsets */

    /* If this transaction is inline, the data immediately
     * follows here; otherwise, it ends with a pointer to
     * the data buffer.
     */
    union {
        struct {
            /* transaction data */
            binder_uintptr_t buffer;
            /* offsets from buffer to flat_binder_object structs */
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

// android/binder.c
struct siginfo;

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
    /* unknow */
};
struct binder_proc {
    struct hlist_node proc_node;
    struct rb_root threads;
    struct rb_root nodes;
    struct rb_root refs_by_desc;
    struct rb_root refs_by_node;
    struct list_head waiting_threads;
    int pid;
    struct task_struct* tsk;
    /* unknow */
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
    /* unsigned is_dead:1; */ /* not used at the moment */

    struct binder_buffer* buffer;
    unsigned int code;
    unsigned int flags;
    struct binder_priority priority;
    struct binder_priority saved_priority;
    bool set_priority_called;
    kuid_t sender_euid;
    binder_uintptr_t security_ctx;
    /**
     * @lock:  protects @from, @to_proc, and @to_thread
     *
     * @from, @to_proc, and @to_thread can be set to NULL
     * during thread teardown
     */
    spinlock_t lock;
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
struct binder_thread {
    struct binder_proc* proc;
    struct rb_node rb_node;
    struct list_head waiting_thread_node;
    int pid;
    int looper;              /* only modified by this thread */
    bool looper_need_return; /* can be written by other thread */
    struct binder_transaction* transaction_stack;
    struct list_head todo;
    bool process_todo;
    struct binder_error return_error;
    struct binder_error reply_error;
    wait_queue_head_t wait;
    /* unknow */
};

struct binder_node {
    int debug_id;
    spinlock_t lock;
    struct binder_work work;
    union {
        struct rb_node rb_node;
        struct hlist_node dead_node;
    };
    struct binder_proc* proc;
    struct hlist_head refs;
    int internal_strong_refs;
    int local_weak_refs;
    int local_strong_refs;
    int tmp_refs;
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
    struct {
        /*
         * bitfield elements protected by
         * proc inner_lock
         */
        u8 has_strong_ref : 1;
        u8 pending_strong_ref : 1;
        u8 has_weak_ref : 1;
        u8 pending_weak_ref : 1;
    };
    struct {
        /*
         * invariant after initialization
         */
        u8 sched_policy : 2;
        u8 inherit_rt : 1;
        u8 accept_fds : 1;
        u8 txn_security_ctx : 1;
        u8 min_priority;
    };
    bool has_async_transaction;
    struct list_head async_todo;
};

// linux/netlink.h
typedef s64 ktime_t;
struct sk_buff {
    union {
        struct {
            /* These two members must be first. */
            struct sk_buff* next;
            struct sk_buff* prev;

            union {
                struct net_device* dev;
                /* Some protocols might use this space to store information,
                 * while device pointer would be NULL.
                 * UDP receive path is one user.
                 */
                unsigned long dev_scratch;
            };
        };
        struct rb_node rbnode; /* used in netem, ip4 defrag, and tcp stack */
        struct list_head list;
    };

    union {
        struct sock* sk;
        int ip_defrag_offset;
    };

    union {
        ktime_t tstamp;
        u64 skb_mstamp;
    };
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    char cb[48] __aligned(8);

    union {
        struct {
            unsigned long _skb_refdst;
            void (*destructor)(struct sk_buff* skb);
        };
        struct list_head tcp_tsorted_anchor;
    };
    /* unknow */
};
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
    __u32 nlmsg_len;   /* Length of message including header */
    __u16 nlmsg_type;  /* Message content */
    __u16 nlmsg_flags; /* Additional flags */
    __u32 nlmsg_seq;   /* Sequence number */
    __u32 nlmsg_pid;   /* Sending process port ID */
};
#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
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
struct binder_ref_data;
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
    /* unknow */
};

#endif
