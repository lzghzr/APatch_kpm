#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define THIS_MODULE ((struct module *)0)
#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

struct binder_alloc;

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

struct binder_buffer {
    struct list_head entry; /* free and allocated entries by address */
    struct rb_node rb_node; /* free entry by size or allocated entry */
    /* by address */
    unsigned free : 1;
    unsigned allow_user_free : 1;
    unsigned async_transaction : 1;
    unsigned debug_id : 29;

    struct binder_transaction* transaction;

    struct binder_node* target_node;
    size_t data_size;
    size_t offsets_size;
    size_t extra_buffers_size;
    void __user* user_data;
    int    pid;
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

// asm/atomic.h
#define atomic_read(v)		READ_ONCE((v)->counter)

// linux/schde/jobctl.h
/*
 * task->jobctl flags
 */
#define JOBCTL_STOP_SIGMASK	0xffff	/* signr of the last group stop */

#define JOBCTL_STOP_DEQUEUED_BIT 16	/* stop signal dequeued */
#define JOBCTL_STOP_PENDING_BIT	17	/* task should stop for group stop */
#define JOBCTL_STOP_CONSUME_BIT	18	/* consume group stop count */
#define JOBCTL_TRAP_STOP_BIT	19	/* trap for STOP */
#define JOBCTL_TRAP_NOTIFY_BIT	20	/* trap for NOTIFY */
#define JOBCTL_TRAPPING_BIT	21	/* switching to TRACED */
#define JOBCTL_LISTENING_BIT	22	/* ptracer is listening for events */
#define JOBCTL_TRAP_FREEZE_BIT	23	/* trap for cgroup freezer */

#define JOBCTL_STOP_DEQUEUED	(1UL << JOBCTL_STOP_DEQUEUED_BIT)
#define JOBCTL_STOP_PENDING	(1UL << JOBCTL_STOP_PENDING_BIT)
#define JOBCTL_STOP_CONSUME	(1UL << JOBCTL_STOP_CONSUME_BIT)
#define JOBCTL_TRAP_STOP	(1UL << JOBCTL_TRAP_STOP_BIT)
#define JOBCTL_TRAP_NOTIFY	(1UL << JOBCTL_TRAP_NOTIFY_BIT)
#define JOBCTL_TRAPPING		(1UL << JOBCTL_TRAPPING_BIT)
#define JOBCTL_LISTENING	(1UL << JOBCTL_LISTENING_BIT)
#define JOBCTL_TRAP_FREEZE	(1UL << JOBCTL_TRAP_FREEZE_BIT)

#define JOBCTL_TRAP_MASK	(JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
#define JOBCTL_PENDING_MASK	(JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

// linux/schde.h

/*
 * Per process flags
 */
#define PF_VCPU			0x00000001	/* I'm a virtual CPU */
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_EXITING		0x00000004	/* Getting shut down */
#define PF_IO_WORKER		0x00000010	/* Task is an IO worker */
#define PF_WQ_WORKER		0x00000020	/* I'm a workqueue worker */
#define PF_FORKNOEXEC		0x00000040	/* Forked but didn't exec */
#define PF_MCE_PROCESS		0x00000080      /* Process policy on mce errors */
#define PF_SUPERPRIV		0x00000100	/* Used super-user privileges */
#define PF_DUMPCORE		0x00000200	/* Dumped core */
#define PF_SIGNALED		0x00000400	/* Killed by a signal */
#define PF_MEMALLOC		0x00000800	/* Allocating memory */
#define PF_NPROC_EXCEEDED	0x00001000	/* set_user() noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH		0x00002000	/* If unset the fpu must be initialized before use */
#define PF_NOFREEZE		0x00008000	/* This thread should not be frozen */
#define PF_FROZEN		0x00010000	/* Frozen for system suspend */
#define PF_KSWAPD		0x00020000	/* I am kswapd */
#define PF_MEMALLOC_NOFS	0x00040000	/* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO	0x00080000	/* All allocation requests will inherit GFP_NOIO */
#define PF_LOCAL_THROTTLE	0x00100000	/* Throttle writes only against the bdi I write to,
* I am cleaning dirty pages from some other bdi. */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define PF_RANDOMIZE		0x00400000	/* Randomize virtual address space */
#define PF_SWAPWRITE		0x00800000	/* Allowed to write to swap */
#define PF_NO_SETAFFINITY	0x04000000	/* Userland is not allowed to meddle with cpus_mask */
#define PF_MCE_EARLY		0x08000000      /* Early kill for mce process policy */
#define PF_MEMALLOC_PIN		0x10000000	/* Allocation context constrained to zones which allow long term pinning. */
#define PF_FREEZER_SKIP		0x40000000	/* Freezer should not count it as freezable */
#define PF_SUSPEND_TASK		0x80000000      /* This thread called freeze_processes() and should not be frozen */

// uapi/asm/signal.h
#define NSIG		32
#define _NSIG		64
#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPOLL		SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR		30
#define SIGSYS		31
#define	SIGUNUSED	31

/* These should not be considered constants from userland.  */
#define SIGRTMIN	32
#define SIGRTMAX	_NSIG

#define SIGSWI		32


#define __SIGINFO \
struct {          \
	int si_signo; \
	int si_errno; \
	int si_code;  \
}
typedef struct kernel_siginfo {
    __SIGINFO;
} kernel_siginfo_t;

// linux/socket.h

#define MSG_OOB		1
#define MSG_PEEK	2
#define MSG_DONTROUTE	4
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC	8
#define MSG_PROBE	0x10	/* Do not send. Only probe path f.e. for MTU */
#define MSG_TRUNC	0x20
#define MSG_DONTWAIT	0x40	/* Nonblocking io		 */
#define MSG_EOR         0x80	/* End of record */
#define MSG_WAITALL	0x100	/* Wait for a full request */
#define MSG_FIN         0x200
#define MSG_SYN		0x400
#define MSG_CONFIRM	0x800	/* Confirm path validity */
#define MSG_RST		0x1000
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
#define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE	0x8000	/* Sender will send more */
#define MSG_WAITFORONE	0x10000	/* recvmmsg(): block until 1+ packets avail */
#define MSG_SENDPAGE_NOPOLICY 0x10000 /* sendpage() internal : do no apply policy */
#define MSG_SENDPAGE_NOTLAST 0x20000 /* sendpage() internal : not the last page */
#define MSG_BATCH	0x40000 /* sendmmsg(): more messages coming */
#define MSG_EOF         MSG_FIN
#define MSG_NO_SHARED_FRAGS 0x80000 /* sendpage() internal : page frags are not shared */
#define MSG_SENDPAGE_DECRYPTED	0x100000 /* sendpage() internal : page may carry
                      * plain text and require encryption
                      */

#define MSG_ZEROCOPY	0x4000000	/* Use user data in kernel path */
#define MSG_FASTOPEN	0x20000000	/* Send data in TCP SYN */
#define MSG_CMSG_CLOEXEC 0x40000000	/* Set close_on_exec for file
                       descriptor received through
                       SCM_RIGHTS */

typedef struct refcount_struct {
    atomic_t refs;
} refcount_t;
struct task_struct {
    unsigned int			__state;
    // unknow
};

// include/linux/cgroup-defs.h

/* bits in struct cgroup flags field */
enum {
    /* Control Group requires release notifications to userspace */
    CGRP_NOTIFY_ON_RELEASE,
    /*
     * Clone the parent's configuration when creating a new child
     * cpuset cgroup.  For historical reasons, this option can be
     * specified at mount time and thus is implemented here.
     */
    CGRP_CPUSET_CLONE_CHILDREN,

    /* Control group has to be frozen. */
    CGRP_FREEZE,

    /* Cgroup is frozen. */
    CGRP_FROZEN,
};

struct cftype;
/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long* addr)
{
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}
#define CGROUP_SUBSYS_COUNT 0
struct percpu_ref {
    /*
     * The low bit of the pointer indicates whether the ref is in percpu
     * mode; if set, then get/put will manipulate the atomic_t.
     */
    unsigned long		percpu_count_ptr;

    /*
     * 'percpu_ref' is often embedded into user structure, and only
     * 'percpu_count_ptr' is required in fast path, move other fields
     * into 'percpu_ref_data', so we can reduce memory footprint in
     * fast path.
     */
    struct percpu_ref_data* data;
};
/*
 * Per-subsystem/per-cgroup state maintained by the system.  This is the
 * fundamental structural building block that controllers deal with.
 *
 * Fields marked with "PI:" are public and immutable and may be accessed
 * directly without synchronization.
 */
struct cgroup_subsys_state {
    /* PI: the cgroup that this css is attached to */
    struct cgroup* cgroup;

    /* PI: the cgroup subsystem that this css is attached to */
    struct cgroup_subsys* ss;

    /* reference count - access via css_[try]get() and css_put() */
    struct percpu_ref refcnt;

    /* siblings list anchored at the parent's ->children */
    struct list_head sibling;
    struct list_head children;

    /* flush target list anchored at cgrp->rstat_css_list */
    struct list_head rstat_css_node;

    /*
     * PI: Subsys-unique ID.  0 is unused and root is always 1.  The
     * matching css can be looked up using css_from_id().
     */
    int id;

    unsigned int flags;

    /*
     * Monotonically increasing unique serial number which defines a
     * uniform order among all csses.  It's guaranteed that all
     * ->children lists are in the ascending order of ->serial_nr and
     * used to allow interrupting and resuming iterations.
     */
    u64 serial_nr;

    /*
     * Incremented by online self and children.  Used to guarantee that
     * parents are not offlined before their children.
     */
    atomic_t online_cnt;

    /* percpu_ref killing and RCU release */

    // unknow

    /*
     * PI: the parent css.	Placed here for cache proximity to following
     * fields of the containing structure.
     */
    // struct cgroup_subsys_state* parent;
};
/*
 * cgroup_file is the handle for a file instance created in a cgroup which
 * is used, for example, to generate file changed notifications.  This can
 * be obtained by setting cftype->file_offset.
 */
struct cgroup_file {
    /* do not access any fields from outside cgroup core */
    struct kernfs_node* kn;
    unsigned long notified_at;
    // unknow
};
struct task_cputime {
    u64				stime;
    u64				utime;
    unsigned long long		sum_exec_runtime;
};
struct cgroup_base_stat {
    struct task_cputime cputime;
};
struct cgroup {
    /* self css with NULL ->ss, points back to this cgroup */
    struct cgroup_subsys_state self;

    unsigned long flags;		/* "unsigned long" so bitops work */

    /*
     * The depth this cgroup is at.  The root is at depth zero and each
     * step down the hierarchy increments the level.  This along with
     * ancestor_ids[] can determine whether a given cgroup is a
     * descendant of another without traversing the hierarchy.
     */
    int level;

    /* Maximum allowed descent tree depth */
    int max_depth;

    /*
     * Keep track of total numbers of visible and dying descent cgroups.
     * Dying cgroups are cgroups which were deleted by a user,
     * but are still existing because someone else is holding a reference.
     * max_descendants is a maximum allowed number of descent cgroups.
     *
     * nr_descendants and nr_dying_descendants are protected
     * by cgroup_mutex and css_set_lock. It's fine to read them holding
     * any of cgroup_mutex and css_set_lock; for writing both locks
     * should be held.
     */
    int nr_descendants;
    int nr_dying_descendants;
    int max_descendants;

    /*
     * Each non-empty css_set associated with this cgroup contributes
     * one to nr_populated_csets.  The counter is zero iff this cgroup
     * doesn't have any tasks.
     *
     * All children which have non-zero nr_populated_csets and/or
     * nr_populated_children of their own contribute one to either
     * nr_populated_domain_children or nr_populated_threaded_children
     * depending on their type.  Each counter is zero iff all cgroups
     * of the type in the subtree proper don't have any tasks.
     */
    int nr_populated_csets;
    int nr_populated_domain_children;
    int nr_populated_threaded_children;

    int nr_threaded_children;	/* # of live threaded child cgroups */

    struct kernfs_node* kn;		/* cgroup kernfs entry */
    struct cgroup_file procs_file;	/* handle for "cgroup.procs" */
    struct cgroup_file events_file;	/* handle for "cgroup.events" */

    /*
     * The bitmask of subsystems enabled on the child cgroups.
     * ->subtree_control is the one configured through
     * "cgroup.subtree_control" while ->child_ss_mask is the effective
     * one which may have more subsystems enabled.  Controller knobs
     * are made available iff it's enabled in ->subtree_control.
     */
    u16 subtree_control;
    u16 subtree_ss_mask;
    u16 old_subtree_control;
    u16 old_subtree_ss_mask;

    /* Private pointers for each registered subsystem */
    struct cgroup_subsys_state __rcu* subsys[CGROUP_SUBSYS_COUNT];

    struct cgroup_root* root;

    /*
     * List of cgrp_cset_links pointing at css_sets with tasks in this
     * cgroup.  Protected by css_set_lock.
     */
    struct list_head cset_links;

    /*
     * On the default hierarchy, a css_set for a cgroup with some
     * susbsys disabled will point to css's which are associated with
     * the closest ancestor which has the subsys enabled.  The
     * following lists all css_sets which point to this cgroup's css
     * for the given subsystem.
     */
    struct list_head e_csets[CGROUP_SUBSYS_COUNT];

    /*
     * If !threaded, self.  If threaded, it points to the nearest
     * domain ancestor.  Inside a threaded subtree, cgroups are exempt
     * from process granularity and no-internal-task constraint.
     * Domain level resource consumptions which aren't tied to a
     * specific task are charged to the dom_cgrp.
     */
    struct cgroup* dom_cgrp;
    struct cgroup* old_dom_cgrp;		/* used while enabling threaded */

    /* per-cpu recursive resource statistics */
    struct cgroup_rstat_cpu __percpu* rstat_cpu;
    struct list_head rstat_css_list;

    /* cgroup basic resource statistics */
    struct cgroup_base_stat last_bstat;
    struct cgroup_base_stat bstat;
    // umknow
};
struct css_set {
    /*
     * Set of subsystem states, one for each subsystem. This array is
     * immutable after creation apart from the init_css_set during
     * subsystem registration (at boot time).
     */
    struct cgroup_subsys_state* subsys[CGROUP_SUBSYS_COUNT];

    /* reference count */
    refcount_t refcount;

    /*
     * For a domain cgroup, the following points to self.  If threaded,
     * to the matching cset of the nearest domain ancestor.  The
     * dom_cset provides access to the domain cgroup and its csses to
     * which domain level resource consumptions should be charged.
     */
    struct css_set* dom_cset;

    /* the default cgroup associated with this css_set */
    struct cgroup* dfl_cgrp;

    /* internal task count, protected by css_set_lock */
    int nr_tasks;

    /*
     * Lists running through all tasks using this cgroup group.
     * mg_tasks lists tasks which belong to this cset but are in the
     * process of being migrated out or in.  Protected by
     * css_set_rwsem, but, during migration, once tasks are moved to
     * mg_tasks, it can be read safely while holding cgroup_mutex.
     */
    struct list_head tasks;
    struct list_head mg_tasks;
    struct list_head dying_tasks;

    /* all css_task_iters currently walking this cset */
    struct list_head task_iters;

    /*
     * On the default hierarhcy, ->subsys[ssid] may point to a css
     * attached to an ancestor instead of the cgroup this css_set is
     * associated with.  The following node is anchored at
     * ->subsys[ssid]->cgroup->e_csets[ssid] and provides a way to
     * iterate through all css's attached to a given cgroup.
     */
    struct list_head e_cset_node[CGROUP_SUBSYS_COUNT];

    /* all threaded csets whose ->dom_cset points to this cset */
    struct list_head threaded_csets;
    struct list_head threaded_csets_node;

    /*
     * List running through all cgroup groups in the same hash
     * slot. Protected by css_set_lock
     */
    struct hlist_node hlist;

    /*
     * List of cgrp_cset_links pointing at cgroups referenced from this
     * css_set.  Protected by css_set_lock.
     */
    struct list_head cgrp_links;

    /*
     * List of csets participating in the on-going migration either as
     * source or destination.  Protected by cgroup_mutex.
     */
    struct list_head mg_preload_node;
    struct list_head mg_node;

    /*
     * If this cset is acting as the source of migration the following
     * two fields are set.  mg_src_cgrp and mg_dst_cgrp are
     * respectively the source and destination cgroups of the on-going
     * migration.  mg_dst_cset is the destination cset the target tasks
     * on this cset should be migrated to.  Protected by cgroup_mutex.
     */
    struct cgroup* mg_src_cgrp;
    struct cgroup* mg_dst_cgrp;
    struct css_set* mg_dst_cset;

    /* dead and being drained, ignore for migration */
    bool dead;

    /* For RCU-protected deletion */
    struct rcu_head rcu_head;
};

#endif /* __RE_KERNEL_H */
