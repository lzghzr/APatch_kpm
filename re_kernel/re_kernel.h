#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define THIS_MODULE ((struct module*)0)

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a) - 1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

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
#define NETLINK_MAX_COOKIE_LEN 20
struct sk_buff;
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
struct netlink_ext_ack {
  const char* _msg;
  const struct nlattr* bad_attr;
  const struct nla_policy* policy;
  u8 cookie[NETLINK_MAX_COOKIE_LEN];
  u8 cookie_len;
};

// tools/include/uapi/linux/netlink.h
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
#define NLMSG_DATA(nlh) ((void*)(((char*)nlh) + NLMSG_HDRLEN))

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
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_TRYHARD 4
#define MSG_CTRUNC 8
#define MSG_PROBE 0x10
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#define MSG_FIN 0x200
#define MSG_SYN 0x400
#define MSG_CONFIRM 0x800
#define MSG_RST 0x1000
#define MSG_ERRQUEUE 0x2000
#define MSG_NOSIGNAL 0x4000
#define MSG_MORE 0x8000
#define MSG_WAITFORONE 0x10000
#define MSG_SENDPAGE_NOPOLICY 0x10000
#define MSG_SENDPAGE_NOTLAST 0x20000
#define MSG_BATCH 0x40000
#define MSG_EOF MSG_FIN
#define MSG_NO_SHARED_FRAGS 0x80000
#define MSG_SENDPAGE_DECRYPTED 0x100000

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
#define sk_rx_queue_mapping __sk_common.skc_rx_queue_mapping

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

// uapi/linux/ip.h
struct iphdr {
  __u8 ihl : 4, version : 4;
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __sum16 check;
  __be32 saddr;
  __be32 daddr;
};

// uapi/linux/ipv6.h
struct ipv6hdr {
  __u8 priority : 4, version : 4;
  __u8 flow_lbl[3];

  __be16 payload_len;
  __u8 nexthdr;
  __u8 hop_limit;

  // unknow
  // struct in6_addr saddr;
  // struct in6_addr daddr;
};

// uapi/linux/swab.h
#define ___constant_swab16(x) ((__u16)((((__u16)(x) & (__u16)0x00ffU) << 8) | (((__u16)(x) & (__u16)0xff00U) >> 8)))

#define ___constant_swab32(x)                                                                     \
  ((__u32)((((__u32)(x) & (__u32)0x000000ffUL) << 24) | (((__u32)(x) & (__u32)0x0000ff00UL) << 8) \
           | (((__u32)(x) & (__u32)0x00ff0000UL) >> 8) | (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab64(x)                                                                                         \
  ((__u64)((((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40)  \
           | (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)(x) & (__u64)0x00000000ff000000ULL) << 8) \
           | (((__u64)(x) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) \
           | (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40)                                                      \
           | (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

#define ___constant_swahw32(x) \
  ((__u32)((((__u32)(x) & (__u32)0x0000ffffUL) << 16) | (((__u32)(x) & (__u32)0xffff0000UL) >> 16)))

#define ___constant_swahb32(x) \
  ((__u32)((((__u32)(x) & (__u32)0x00ff00ffUL) << 8) | (((__u32)(x) & (__u32)0xff00ff00UL) >> 8)))

#define swab16(x) ___constant_swab16(x)
#define swab32(x) ___constant_swab32(x)
#define swab64(x) ___constant_swab64(x)
#define swahw32(x) ___constant_swahw32(x)
#define swahb32(x) ___constant_swahb32(x)

#endif /* __RE_KERNEL_H */
