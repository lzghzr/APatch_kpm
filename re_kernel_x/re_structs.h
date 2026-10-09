#ifndef __RE_STRUCTS_H
#define __RE_STRUCTS_H

// include/linux/sched/jobctl.h
#define JOBCTL_TRAP_FREEZE_BIT 23
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)

// include/uapi/linux/android/binder.h
enum transaction_flags {
  TF_ONE_WAY = 0x01,
  TF_ROOT_OBJECT = 0x04,
  TF_STATUS_CODE = 0x08,
  TF_ACCEPT_FDS = 0x10,
  TF_CLEAR_BUF = 0x20,
  TF_UPDATE_TXN = 0x40,
};

typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
struct binder_transaction_data {
  union {
    __u32 handle;
    binder_uintptr_t ptr;
  } target;
  binder_uintptr_t cookie;
  __u32 code;
  __u32 flags;
  pid_t sender_pid;
  uid_t sender_euid;
  binder_size_t data_size;
  binder_size_t offsets_size;
  union {
    struct {
      binder_uintptr_t buffer;
      binder_uintptr_t offsets;
    } ptr;
    __u8 buf[8];
  } data;
};

// include/linux/rbtree_types.h
struct rb_node {
  unsigned long __rb_parent_color;
  struct rb_node* rb_right;
  struct rb_node* rb_left;
} __attribute__((aligned(sizeof(long))));
struct rb_root {
  struct rb_node* rb_node;
};

// drivers/android/binder_alloc.h
struct binder_alloc;

struct binder_buffer {
  struct list_head entry;
  struct rb_node rb_node;
  unsigned free : 1;
  unsigned clear_on_free : 1;  // 6.1
  unsigned allow_user_free : 1;
  unsigned async_transaction : 1;
  unsigned oneway_spam_suspect : 1;  // 6.1
  // unsigned debug_id : 29;
  unsigned debug_id : 27;  // 6.1
  struct binder_transaction* transaction;
  struct binder_node* target_node;
  size_t data_size;
  size_t offsets_size;
  size_t extra_buffers_size;
  void __user* user_data;
  int pid;
};
// drivers/android/binder_internal.h
struct binder_work {
  struct list_head entry;
  enum binder_work_type {
    BINDER_WORK_TRANSACTION = 1,
    BINDER_WORK_TRANSACTION_COMPLETE,
    BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT,  // 6.1
    BINDER_WORK_RETURN_ERROR,
    BINDER_WORK_NODE,
    BINDER_WORK_DEAD_BINDER,
    BINDER_WORK_DEAD_BINDER_AND_CLEAR,
    BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
  } type;
};

struct binder_node {
  int debug_id;
  // spinlock_t lock; // harmony
  // struct binder_work work;
  // union {
  //   struct rb_node rb_node;
  //   struct hlist_node dead_node;
  // };
  // struct binder_proc* proc;
  // struct hlist_head refs;
  // int internal_strong_refs;
  // int local_weak_refs;
  // int local_strong_refs;
  // int tmp_refs;
  // binder_uintptr_t ptr;
  // binder_uintptr_t cookie;
  // struct {
  //   u8 has_strong_ref : 1;
  //   u8 pending_strong_ref : 1;
  //   u8 has_weak_ref : 1;
  //   u8 pending_weak_ref : 1;
  // };
  // struct {
  //   u8 sched_policy : 2;
  //   u8 inherit_rt : 1;
  //   u8 accept_fds : 1;
  //   u8 txn_security_ctx : 1;
  //   u8 min_priority;
  // };
  // bool has_async_transaction;
  // struct list_head async_todo;
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
  // unknow
};

struct binder_transaction {
  int debug_id;
  struct binder_work work;
  // struct binder_thread* from; // harmony
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
  // atomic_t br[18];
  atomic_t br[20];  // 6.1
  atomic_t bc[19];
  atomic_t obj_created[BINDER_STAT_COUNT];
  atomic_t obj_deleted[BINDER_STAT_COUNT];
};

struct binder_thread {
  struct binder_proc* proc;
  // struct rb_node rb_node;
  // struct list_head waiting_thread_node;
  // int pid;
  // int looper;
  // bool looper_need_return;
  // struct binder_transaction* transaction_stack;
  // struct list_head todo;
  // bool process_todo;
};

// linux/netlink.h
struct net;

// uapi/linux/netlink.h
struct nlmsghdr {
  __u32 nlmsg_len;
  __u16 nlmsg_type;
  __u16 nlmsg_flags;
  __u32 nlmsg_seq;
  __u32 nlmsg_pid;
};
#define NLM_F_DUMP 0x300
#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))

struct nlattr {
  __u16 nla_len;
  __u16 nla_type;
};
#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))

// uapi/linux/genetlink.h
struct genlmsghdr {
  __u8 cmd;
  __u8 version;
  __u16 reserved;
};
#define GENL_NAMSIZ 16
#define GENL_HDRLEN NLMSG_ALIGN(sizeof(struct genlmsghdr))

// net/genetlink.h
struct genl_ops;
struct genl_multicast_group {
  char name[GENL_NAMSIZ];
  char unknow[0x30];
} __aligned(8);
struct nla_policy;
struct genl_family_config {
  unsigned int hdrsize;
  char name[GENL_NAMSIZ];
  unsigned int version;
  unsigned int maxattr;
};
struct genl_family {
  char unknow[0x400];
} __aligned(8);

// linux/gfp.h
#define NUMA_NO_NODE (-1)
#define ___GFP_HIGH 0x20u
#define ___GFP_ATOMIC 0x80000u
#define ___GFP_KSWAPD_RECLAIM 0x400000u
#define __GFP_HIGH ((__force gfp_t)___GFP_HIGH)
#define __GFP_ATOMIC ((__force gfp_t)___GFP_ATOMIC)
#define __GFP_KSWAPD_RECLAIM ((__force gfp_t)___GFP_KSWAPD_RECLAIM)
#define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)

// uapi/asm/signal.h
#define SIGQUIT 3
#define SIGABRT 6
#define SIGKILL 9
#define SIGTERM 15

struct siginfo;

// linux/tracepoint-defs.h
struct tracepoint;

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

// include/net/scm.h
struct scm_creds {
  u32 pid;
  kuid_t uid;
  kgid_t gid;
};

// include/linux/netlink.h
struct netlink_skb_parms {
  struct scm_creds creds;
  __u32 portid;
  __u32 dst_group;
  __u32 flags;
  struct sock* sk;
  bool nsid_is_set;
  int nsid;
};
#define NETLINK_CB(skb) (*(struct netlink_skb_parms*)&((skb)->cb))

// uapi/linux/tcp.h
struct tcphdr {
  __be16 source;
  __be16 dest;
  __be32 seq;
  __be32 ack_seq;
  __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
  __be16 window;
  __sum16 check;
  __be16 urg_ptr;
};

#endif /* __RE_STRUCTS_H */
