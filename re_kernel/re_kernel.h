#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define THIS_MODULE ((struct module *)0)

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

// linux/sched/jobctl.h
#define JOBCTL_TRAP_FREEZE_BIT 23
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)

// android/binder.c
struct binder_alloc;
struct binder_transaction_data;

enum transaction_flags {
  TF_ONE_WAY = 0x01,
  TF_ROOT_OBJECT = 0x04,
  TF_STATUS_CODE = 0x08,
  TF_ACCEPT_FDS = 0x10,
  TF_CLEAR_BUF = 0x20,
  TF_UPDATE_TXN = 0x40,
};

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

struct binder_work {
  struct list_head entry;
  enum binder_work_type {
    BINDER_WORK_TRANSACTION = 1,
    BINDER_WORK_TRANSACTION_COMPLETE,
    BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT, // 6.1
    BINDER_WORK_RETURN_ERROR,
    BINDER_WORK_NODE,
    BINDER_WORK_DEAD_BINDER,
    BINDER_WORK_DEAD_BINDER_AND_CLEAR,
    BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
  } type;
};
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
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
    u8 has_strong_ref : 1;
    u8 pending_strong_ref : 1;
    u8 has_weak_ref : 1;
    u8 pending_weak_ref : 1;
  };
  struct {
    u8 sched_policy : 2;
    u8 inherit_rt : 1;
    u8 accept_fds : 1;
    u8 txn_security_ctx : 1;
    u8 min_priority;
  };
  bool has_async_transaction;
  struct list_head async_todo;
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

struct binder_buffer {
  struct list_head entry;
  struct rb_node rb_node;
  unsigned free : 1;
  unsigned clear_on_free : 1; // 6.1
  unsigned allow_user_free : 1;
  unsigned async_transaction : 1;
  unsigned oneway_spam_suspect : 1; // 6.1
  // unsigned debug_id : 29;
  unsigned debug_id : 27; // 6.1
  struct binder_transaction* transaction;
  struct binder_node* target_node;
  size_t data_size;
  size_t offsets_size;
  size_t extra_buffers_size;
  void __user* user_data;
  int pid;
};

struct binder_priority {
  unsigned int sched_policy;
  int prio;
};
struct binder_transaction {
  int debug_id;
  struct binder_work work;
  struct binder_thread* from;
  // unknow
  // pid_t from_pid; // 6.1
  // pid_t from_tid; // 6.1
  // struct binder_transaction* from_parent;
  // struct binder_proc* to_proc;
  // struct binder_thread* to_thread;
  // struct binder_transaction* to_parent;
  // unsigned need_reply : 1;
  // struct binder_buffer* buffer;
  // unsigned int code;
  // unsigned int flags;
  // struct binder_priority priority;
  // struct binder_priority saved_priority;
  // bool set_priority_called;
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
  atomic_t br[18];
  // atomic_t br[20]; // 6.1
  atomic_t bc[19];
  atomic_t obj_created[BINDER_STAT_COUNT];
  atomic_t obj_deleted[BINDER_STAT_COUNT];
};

struct binder_thread {
  struct binder_proc* proc;
  // unknow
};

// linux/netlink.h
struct sk_buff;
struct net;
struct sock;
struct netlink_kernel_cfg {
  char unknow[0x30];
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
  char unknow[0x120];
};

// linux/schde.h
#define PF_FROZEN 0x00010000

// uapi/asm/signal.h
#define SIGQUIT 3
#define SIGABRT 6
#define SIGKILL 9
#define SIGTERM 15

struct siginfo;

// linux/socket.h
#define MSG_DONTWAIT 0x40

// linux/tracepoint-defs.h
struct tracepoint;

// net/tcp_states.h
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,
  TCP_NEW_SYN_RECV,
  TCP_MAX_STATES
};

enum {
  TCPF_ESTABLISHED = (1 << TCP_ESTABLISHED),
  TCPF_SYN_SENT = (1 << TCP_SYN_SENT),
  TCPF_SYN_RECV = (1 << TCP_SYN_RECV),
  TCPF_FIN_WAIT1 = (1 << TCP_FIN_WAIT1),
  TCPF_FIN_WAIT2 = (1 << TCP_FIN_WAIT2),
  TCPF_TIME_WAIT = (1 << TCP_TIME_WAIT),
  TCPF_CLOSE = (1 << TCP_CLOSE),
  TCPF_CLOSE_WAIT = (1 << TCP_CLOSE_WAIT),
  TCPF_LAST_ACK = (1 << TCP_LAST_ACK),
  TCPF_LISTEN = (1 << TCP_LISTEN),
  TCPF_CLOSING = (1 << TCP_CLOSING),
  TCPF_NEW_SYN_RECV = (1 << TCP_NEW_SYN_RECV),
};

// net/sock.h
typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct sock_common {
  union {
    __addrpair skc_addrpair;
    struct {
      __be32 skc_daddr;
      __be32 skc_rcv_saddr;
    };
  };
  union {
    unsigned int skc_hash;
    __u16 skc_u16hashes[2];
  };
  union {
    __portpair skc_portpair;
    struct {
      __be16 skc_dport;
      __u16 skc_num;
    };
  };
  unsigned short skc_family;
  volatile unsigned char skc_state;
  unsigned char skc_reuse : 4;
  unsigned char skc_reuseport : 1;
  unsigned char skc_ipv6only : 1;
  unsigned char skc_net_refcnt : 1;
  int skc_bound_dev_if;
  union {
    struct hlist_node skc_bind_node;
    struct hlist_node skc_portaddr_node;
  };
  struct proto* skc_prot;
  // unknow
};

struct sock {
  struct sock_common __sk_common;
#define sk_node __sk_common.skc_node
#define sk_nulls_node __sk_common.skc_nulls_node
#define sk_refcnt __sk_common.skc_refcnt
#define sk_tx_queue_mapping __sk_common.skc_tx_queue_mapping
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
#define sk_rx_queue_mapping __sk_common.skc_rx_queue_mapping
#endif

#define sk_dontcopy_begin __sk_common.skc_dontcopy_begin
#define sk_dontcopy_end __sk_common.skc_dontcopy_end
#define sk_hash __sk_common.skc_hash
#define sk_portpair __sk_common.skc_portpair
#define sk_num __sk_common.skc_num
#define sk_dport __sk_common.skc_dport
#define sk_addrpair __sk_common.skc_addrpair
#define sk_daddr __sk_common.skc_daddr
#define sk_rcv_saddr __sk_common.skc_rcv_saddr
#define sk_family __sk_common.skc_family
#define sk_state __sk_common.skc_state
#define sk_reuse __sk_common.skc_reuse
#define sk_reuseport __sk_common.skc_reuseport
#define sk_ipv6only __sk_common.skc_ipv6only
#define sk_net_refcnt __sk_common.skc_net_refcnt
#define sk_bound_dev_if __sk_common.skc_bound_dev_if
#define sk_bind_node __sk_common.skc_bind_node
#define sk_prot __sk_common.skc_prot
#define sk_net __sk_common.skc_net
#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr
#define sk_cookie __sk_common.skc_cookie
#define sk_incoming_cpu __sk_common.skc_incoming_cpu
#define sk_flags __sk_common.skc_flags
#define sk_rxhash __sk_common.skc_rxhash
  // unknow
};

// linux/skbuff.h
typedef s64 ktime_t;
struct sk_buff {
  union {
    struct {
      struct sk_buff* next;
      struct sk_buff* prev;
      union {
        struct net_device* dev;
        unsigned long dev_scratch;
      };
    };
    struct rb_node rbnode;
    struct list_head list;
  };
  union {
    struct sock* sk;
    int ip_defrag_offset;
  };
  union {
    ktime_t tstamp;
    u64 skb_mstamp_ns;
  };
  char cb[48] __aligned(8);
  union {
    struct {
      unsigned long _skb_refdst;
      void (*destructor)(struct sk_buff* skb);
    };
    struct list_head tcp_tsorted_anchor;
  };
  // unknow
};

#endif /* __RE_KERNEL_H */
