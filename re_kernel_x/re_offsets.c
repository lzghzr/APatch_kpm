struct struct_offset {
  int16_t binder_alloc_buffer_size;
  int16_t binder_alloc_buffer;
  int16_t binder_alloc_free_async_space;
  int16_t binder_alloc_pid;
  int16_t binder_node_async_todo;
  int16_t binder_node_cookie;
  int16_t binder_node_has_async_transaction;
  int16_t binder_node_lock;
  int16_t binder_node_ptr;
  int16_t binder_proc_alloc;
  int16_t binder_proc_context;
  int16_t binder_proc_inner_lock;
  int16_t binder_proc_is_frozen;
  int16_t binder_proc_outer_lock;
  int16_t binder_proc_outstanding_txns;
  int16_t binder_stats_deleted_transaction;
  int16_t binder_transaction_buffer;
  int16_t binder_transaction_code;
  int16_t binder_transaction_flags;
  int16_t binder_transaction_from;
  int16_t binder_transaction_to_proc;
  int16_t net_genl_sock;
  int16_t genl_family_id;
  int16_t genl_family_config;
  int16_t genl_family_mcgrps;
  int16_t genl_family_n_mcgrps;
  int16_t genl_family_n_mcgrps_size;
  int16_t genl_family_mcgrp_offset;
  int16_t sk_buff_data;
  int16_t sk_buff_head;
  int16_t sk_buff_len;
  int16_t sk_buff_network_header;
  int16_t sk_buff_tail;
  int16_t sk_buff_transport_header;
  int16_t task_struct_group_leader;
  int16_t task_struct_jobctl;
  int16_t task_struct_pid;
  int16_t task_struct_tgid;
  int16_t task_struct_cred;
  int16_t cred_uid;
  int16_t task_struct_comm;
  int16_t sock_sk_net;
  int16_t binder_proc_is_dead;
  int16_t binder_buffer_data;
  int16_t binder_release_abi;
};

// 独立数据段供离线替换；volatile 保证访问从表中读取，不折叠成指令立即数。
volatile struct struct_offset struct_offset __attribute__((section(".data.re_offsets"), used)) = {
    .binder_alloc_buffer = 0x40,
    .binder_alloc_buffer_size = 0x78,
    .binder_alloc_free_async_space = 0x68,
    .binder_alloc_pid = 0x84,
    .binder_node_async_todo = 0x70,
    .binder_node_cookie = 0x60,
    .binder_node_has_async_transaction = 0x6b,
    .binder_node_lock = 0x4,
    .binder_node_ptr = 0x58,
    .binder_proc_alloc = 0x1a8,
    .binder_proc_context = 0x240,
    .binder_proc_inner_lock = 0x248,
    .binder_proc_is_frozen = 0x71,
    .binder_proc_outer_lock = 0x24c,
    .binder_proc_outstanding_txns = 0x6c,
    .binder_stats_deleted_transaction = 0xcc,
    .binder_transaction_buffer = 0x50,
    .binder_transaction_code = 0x58,
    .binder_transaction_flags = 0x5c,
    .binder_transaction_from = 0x20,
    .binder_transaction_to_proc = 0x30,
    .net_genl_sock = 0x118,
    .genl_family_id = 0x0,
    .genl_family_config = 0x4,
    .genl_family_mcgrps = 0x50,
    .genl_family_n_mcgrps = 0x27,
    .genl_family_n_mcgrps_size = 0x1,
    .genl_family_mcgrp_offset = 0x20,
    .sk_buff_data = 0xd8,
    .sk_buff_head = 0xd0,
    .sk_buff_len = 0x70,
    .sk_buff_network_header = 0xb4,
    .sk_buff_tail = 0xc8,
    .sk_buff_transport_header = 0xb2,
    .task_struct_group_leader = 0x618,
    .task_struct_jobctl = 0x580,
    .task_struct_pid = 0x5d8,
    .task_struct_tgid = 0x5dc,
    .task_struct_cred = 0x798,
    .cred_uid = 0x4,
    .task_struct_comm = 0x7a8,
    .sock_sk_net = 0x30,
    .binder_proc_is_dead = 0x70,
    .binder_buffer_data = -1,
    .binder_release_abi = 6,
};
// task_comm
static inline const char* task_comm(struct task_struct* task) {
  const char* comm = (const char*)((uintptr_t)task + struct_offset.task_struct_comm);
  return comm;
}
// task_uid
#undef task_uid
static inline kuid_t task_uid(struct task_struct* task) {
  struct cred* cred = *(struct cred**)((uintptr_t)task + struct_offset.task_struct_cred);
  kuid_t uid = *(kuid_t*)((uintptr_t)cred + struct_offset.cred_uid);
  return uid;
}
// task_tgid
static inline pid_t task_tgid_nr(struct task_struct* task) {
  pid_t tgid = *(pid_t*)((uintptr_t)task + struct_offset.task_struct_tgid);
  return tgid;
}
// task_jobctl
static inline unsigned long task_jobctl(struct task_struct* task) {
  unsigned long jobctl = *(unsigned long*)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// binder_proc_is_frozen
static inline bool binder_proc_is_frozen(struct binder_proc* proc) {
  bool is_frozen = *(bool*)((uintptr_t)proc + struct_offset.binder_proc_is_frozen);
  return is_frozen;
}
// binder_proc_alloc
static inline struct binder_alloc* binder_proc_alloc(struct binder_proc* proc) {
  struct binder_alloc* alloc = (struct binder_alloc*)((uintptr_t)proc + struct_offset.binder_proc_alloc);
  return alloc;
}
//  binder_proc_inner_lock
static inline spinlock_t* binder_proc_inner_lock(struct binder_proc* proc) {
  spinlock_t* inner_lock = (spinlock_t*)((uintptr_t)proc + struct_offset.binder_proc_inner_lock);
  return inner_lock;
}
//  binder_proc_outstanding_txns
static inline int* binder_proc_outstanding_txns(struct binder_proc* proc) {
  int* outstanding_txns = (int*)((uintptr_t)proc + struct_offset.binder_proc_outstanding_txns);
  return outstanding_txns;
}
// binder_alloc_free_async_space
static inline size_t binder_alloc_free_async_space(struct binder_alloc* alloc) {
  size_t free_async_space = *(size_t*)((uintptr_t)alloc + struct_offset.binder_alloc_free_async_space);
  return free_async_space;
}
// binder_alloc_buffer_size
static inline size_t binder_alloc_buffer_size(struct binder_alloc* alloc) {
  size_t buffer_size = *(size_t*)((uintptr_t)alloc + struct_offset.binder_alloc_buffer_size);
  return buffer_size;
}
// binder_transaction_from
static inline struct binder_thread* binder_transaction_from(struct binder_transaction* t) {
  struct binder_thread* from = *(struct binder_thread**)((uintptr_t)t + struct_offset.binder_transaction_from);
  return from;
}
// binder_transaction_to_proc
static inline struct binder_proc* binder_transaction_to_proc(struct binder_transaction* t) {
  struct binder_proc* to_proc = *(struct binder_proc**)((uintptr_t)t + struct_offset.binder_transaction_to_proc);
  return to_proc;
}
// binder_transaction_buffer
static inline struct binder_buffer* binder_transaction_buffer(struct binder_transaction* t) {
  struct binder_buffer* buffer = *(struct binder_buffer**)((uintptr_t)t + struct_offset.binder_transaction_buffer);
  return buffer;
}
// binder_transaction_code
static inline unsigned int binder_transaction_code(struct binder_transaction* t) {
  unsigned int code = *(unsigned int*)((uintptr_t)t + struct_offset.binder_transaction_code);
  return code;
}
// binder_transaction_flags
static inline unsigned int binder_transaction_flags(struct binder_transaction* t) {
  unsigned int flags = *(unsigned int*)((uintptr_t)t + struct_offset.binder_transaction_flags);
  return flags;
}
// binder_node_lock_ptr
static inline spinlock_t* binder_node_lock_ptr(struct binder_node* node) {
  spinlock_t* lock = (spinlock_t*)((uintptr_t)node + struct_offset.binder_node_lock);
  return lock;
}
// binder_node_ptr
static inline binder_uintptr_t binder_node_ptr(struct binder_node* node) {
  binder_uintptr_t ptr = *(binder_uintptr_t*)((uintptr_t)node + struct_offset.binder_node_ptr);
  return ptr;
}
// binder_node_cookie
static inline binder_uintptr_t binder_node_cookie(struct binder_node* node) {
  binder_uintptr_t cookie = *(binder_uintptr_t*)((uintptr_t)node + struct_offset.binder_node_cookie);
  return cookie;
}
// binder_node_has_async_transaction
static inline bool binder_node_has_async_transaction(struct binder_node* node) {
  bool has_async_transaction = *(bool*)((uintptr_t)node + struct_offset.binder_node_has_async_transaction);
  return has_async_transaction;
}
// binder_node_async_todo
static inline struct list_head* binder_node_async_todo(struct binder_node* node) {
  struct list_head* async_todo = (struct list_head*)((uintptr_t)node + struct_offset.binder_node_async_todo);
  return async_todo;
}
// sk_buff_len
static inline unsigned int sk_buff_len(const struct sk_buff* skb) {
  unsigned int len = *(unsigned int*)((uintptr_t)skb + struct_offset.sk_buff_len);
  return len;
}
// sk_buff_transport_header
static inline __u16 sk_buff_transport_header(const struct sk_buff* skb) {
  __u16 transport_header = *(__u16*)((uintptr_t)skb + struct_offset.sk_buff_transport_header);
  return transport_header;
}
// sk_buff_tail
static inline unsigned int sk_buff_tail(const struct sk_buff* skb) {
  unsigned int tail = *(unsigned int*)((uintptr_t)skb + struct_offset.sk_buff_tail);
  return tail;
}
// sk_buff_head
static inline unsigned char* sk_buff_head(const struct sk_buff* skb) {
  unsigned char* head = *(unsigned char**)((uintptr_t)skb + struct_offset.sk_buff_head);
  return head;
}
// sk_buff_data
static inline unsigned char* sk_buff_data(const struct sk_buff* skb) {
  unsigned char* data = *(unsigned char**)((uintptr_t)skb + struct_offset.sk_buff_data);
  return data;
}

// genl_family_id
static inline int genl_family_id(const struct genl_family* family) {
  int id = *(int*)((uintptr_t)family + struct_offset.genl_family_id);
  return id;
}
// genl_family_config
static inline struct genl_family_config* genl_family_config(struct genl_family* family) {
  struct genl_family_config* config =
      (struct genl_family_config*)((uintptr_t)family + struct_offset.genl_family_config);
  return config;
}
// genl_family_n_mcgrps
static inline unsigned int genl_family_n_mcgrps(const struct genl_family* family) {
  unsigned int n_mcgrps = 0;
  memcpy(&n_mcgrps, (void*)((uintptr_t)family + struct_offset.genl_family_n_mcgrps),
         struct_offset.genl_family_n_mcgrps_size);
  return n_mcgrps;
}
// genl_family_mcgrp_offset
static inline unsigned int genl_family_mcgrp_offset(const struct genl_family* family) {
  unsigned int mcgrp_offset = *(unsigned int*)((uintptr_t)family + struct_offset.genl_family_mcgrp_offset);
  return mcgrp_offset;
}
// net_genl_sock
static inline struct sock* net_genl_sock(struct net* net) {
  struct sock* genl_sock = *(struct sock**)((uintptr_t)net + struct_offset.net_genl_sock);
  return genl_sock;
}
// sock_net
static inline struct net* sock_net(const struct sock* sk) {
  struct net* net = *(struct net**)((uintptr_t)sk + struct_offset.sock_sk_net);
  return net;
}

static inline bool binder_proc_is_dead(struct binder_proc* proc) {
  return *(bool*)((uintptr_t)proc + struct_offset.binder_proc_is_dead);
}
