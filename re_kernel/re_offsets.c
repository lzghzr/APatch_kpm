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

#ifdef CONFIG_KPM_BASELINES
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
#else
struct struct_offset struct_offset = {};
#endif /* CONFIG_KPM_BASELINES */

// task_comm
static inline const char* task_comm(struct task_struct* task) {
#ifdef CONFIG_KPM_BASELINES
  const char* comm = (const char*)((uintptr_t)task + struct_offset.task_struct_comm);
  return comm;
#else
  return get_task_comm(task);
#endif
}
#ifdef CONFIG_KPM_BASELINES
// task_uid
#undef task_uid
static inline kuid_t task_uid(struct task_struct* task) {
  struct cred* cred = *(struct cred**)((uintptr_t)task + struct_offset.task_struct_cred);
  kuid_t uid = *(kuid_t*)((uintptr_t)cred + struct_offset.cred_uid);
  return uid;
}
#endif /* CONFIG_KPM_BASELINES */

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
// binder_proc_is_dead
static inline bool binder_proc_is_dead(struct binder_proc* proc) {
  return *(bool*)((uintptr_t)proc + struct_offset.binder_proc_is_dead);
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

#ifndef CONFIG_KPM_BASELINES
#include "re_btf.c"

static long calculate_offsets() {
  int btf = calculate_btf_offsets();
  if (btf != -ENODATA)
    return btf;

  // 获取 binder_transaction_buffer_release 版本, 以参数数量做判断
  uint32_t* binder_transaction_buffer_release_src = (uint32_t*)binder_transaction_buffer_release;
  for (u32 i = 0; i < 0x100; i++) {
    if (i < 0x10) {
      if (inst_get_str_imm_uint_rt(binder_transaction_buffer_release_src[i]) == 4
          || inst_get_mov_reg_rm(binder_transaction_buffer_release_src[i]) == 4
          || inst_get_uxtb_rn(binder_transaction_buffer_release_src[i]) == 4) {
        binder_transaction_buffer_release_ver5 = true;
      } else if (inst_get_str_imm_uint_rt(binder_transaction_buffer_release_src[i]) == 3
                 || inst_get_mov_reg_rm(binder_transaction_buffer_release_src[i]) == 3
                 || inst_get_uxtb_rn(binder_transaction_buffer_release_src[i]) == 3) {
        binder_transaction_buffer_release_ver4 = true;
      }
    } else if (!binder_transaction_buffer_release_ver5) {
      break;
    } else if (inst_get_and_imm_imm(binder_transaction_buffer_release_src[i]) == -8) {
      for (u32 j = 1; j < 0x3; j++) {
        if (inst_is_cbz(binder_transaction_buffer_release_src[i + j])
            || inst_is_tbnz(binder_transaction_buffer_release_src[i + j])) {
          binder_transaction_buffer_release_ver6 = true;
          break;
        }
      }
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_transaction_buffer_release_ver6=%d\n", binder_transaction_buffer_release_ver6);
  logkm("binder_transaction_buffer_release_ver5=%d\n", binder_transaction_buffer_release_ver5);
  logkm("binder_transaction_buffer_release_ver4=%d\n", binder_transaction_buffer_release_ver4);
#endif /* CONFIG_DEBUG */

  // 获取 binder_proc->is_frozen, 没有就是不支持
  uint32_t* binder_proc_transaction_src = (uint32_t*)binder_proc_transaction;
  for (u32 i = 0; i < 0x70; i++) {
    if (inst_is_ret(binder_proc_transaction_src[i])) {
      break;
    } else if (!struct_offset.binder_node_has_async_transaction
               && inst_is_strb_imm_uint(binder_proc_transaction_src[i])) {
      uint64_t offset = inst_get_strb_imm_uint_imm(binder_proc_transaction_src[i]);
      if (offset < 0x6B || offset > 0x7B)
        continue;
      struct_offset.binder_node_has_async_transaction = offset;
      struct_offset.binder_node_ptr = offset - 0x13;
      struct_offset.binder_node_cookie = offset - 0xB;
      struct_offset.binder_node_async_todo = offset + 0x5;
      // 目前只有 harmony 内核需要特殊设置
      if (offset == 0x7B) {
        struct_offset.binder_node_lock = 0x8;
        struct_offset.binder_transaction_from = 0x28;
      } else {
        struct_offset.binder_node_lock = 0x4;
        struct_offset.binder_transaction_from = 0x20;
      }
    } else if (!struct_offset.binder_transaction_buffer
               && inst_get_ldr_imm_uint_size(binder_proc_transaction_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(binder_proc_transaction_src[i]) == 0) {
      struct_offset.binder_transaction_buffer = inst_get_ldr_imm_uint_imm(binder_proc_transaction_src[i]);
      struct_offset.binder_transaction_to_proc = struct_offset.binder_transaction_buffer - 0x20;
      struct_offset.binder_transaction_code = struct_offset.binder_transaction_buffer + 0x8;
      struct_offset.binder_transaction_flags = struct_offset.binder_transaction_buffer + 0xC;
    } else if (inst_is_orr_reg(binder_proc_transaction_src[i])
               && inst_is_strb_imm_uint(binder_proc_transaction_src[i + 1])) {
      uint64_t binder_proc_sync_recv_offset = inst_get_strb_imm_uint_imm(binder_proc_transaction_src[i + 1]);
      // is_dead/is_frozen/sync_recv 为连续 bool，与现有冻结字段一起取得。
      struct_offset.binder_proc_is_dead = binder_proc_sync_recv_offset - 2;
      struct_offset.binder_proc_is_frozen = binder_proc_sync_recv_offset - 1;
      struct_offset.binder_proc_outstanding_txns = binder_proc_sync_recv_offset - 0x6;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_transaction_from=0x%x\n", struct_offset.binder_transaction_from);                      // 0x20
  logkm("binder_transaction_to_proc=0x%x\n", struct_offset.binder_transaction_to_proc);                // 0x30
  logkm("binder_transaction_buffer=0x%x\n", struct_offset.binder_transaction_buffer);                  // 0x50
  logkm("binder_transaction_code=0x%x\n", struct_offset.binder_transaction_code);                      // 0x58
  logkm("binder_transaction_flags=0x%x\n", struct_offset.binder_transaction_flags);                    // 0x5C
  logkm("binder_node_lock=0x%x\n", struct_offset.binder_node_lock);                                    // 0x4
  logkm("binder_node_ptr=0x%x\n", struct_offset.binder_node_ptr);                                      // 0x58
  logkm("binder_node_cookie=0x%x\n", struct_offset.binder_node_cookie);                                // 0x60
  logkm("binder_node_has_async_transaction=0x%x\n", struct_offset.binder_node_has_async_transaction);  // 0x6B
  logkm("binder_node_async_todo=0x%x\n", struct_offset.binder_node_async_todo);                        // 0x70
  logkm("binder_proc_outstanding_txns=0x%x\n", struct_offset.binder_proc_outstanding_txns);            // 0x6C
  logkm("binder_proc_is_frozen=0x%x\n", struct_offset.binder_proc_is_frozen);                          // 0x71
#endif /* CONFIG_DEBUG */
  if (struct_offset.binder_node_lock <= 0 || struct_offset.binder_node_has_async_transaction <= 0
      || struct_offset.binder_transaction_buffer <= 0)
    return -11;

  // 旧 Binder 没有 is_frozen，从短 tmpref helper 的 proc 参数读取 is_dead。
  if (!struct_offset.binder_proc_is_frozen) {
    void (*binder_proc_dec_tmpref)(struct binder_proc* proc);
    lookup_name(binder_proc_dec_tmpref);
    uint32_t* binder_proc_dec_tmpref_src = (uint32_t*)binder_proc_dec_tmpref;
    int proc_reg = 0;
    for (u32 i = 0; i < 0x20; i++) {
      if (inst_is_ret(binder_proc_dec_tmpref_src[i]))
        break;
      if (inst_get_mov_reg_sf(binder_proc_dec_tmpref_src[i]) == 1
          && inst_get_mov_reg_rm(binder_proc_dec_tmpref_src[i]) == 0)
        proc_reg = inst_get_mov_reg_rd(binder_proc_dec_tmpref_src[i]);
      if (inst_get_ldrb_imm_uint_rn(binder_proc_dec_tmpref_src[i]) != proc_reg)
        continue;
      int reg = inst_get_ldrb_imm_uint_rt(binder_proc_dec_tmpref_src[i]);
      for (u32 j = i + 1; j < i + 4 && j < 0x20; j++) {
        if (inst_get_cbz_sf(binder_proc_dec_tmpref_src[j]) == 0
            && inst_get_cbz_rt(binder_proc_dec_tmpref_src[j]) == reg) {
          struct_offset.binder_proc_is_dead = inst_get_ldrb_imm_uint_imm(binder_proc_dec_tmpref_src[i]);
          break;
        }
      }
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_proc_is_dead=0x%x\n", struct_offset.binder_proc_is_dead);
#endif /* CONFIG_DEBUG */
  if (struct_offset.binder_proc_is_dead <= 0)
    return -11;

  // 获取 task_struct->jobctl
  void (*task_clear_jobctl_trapping)(struct task_struct* t);
  lookup_name(task_clear_jobctl_trapping);

  uint32_t* task_clear_jobctl_trapping_src = (uint32_t*)task_clear_jobctl_trapping;
  for (u32 i = 0; i < 0x10; i++) {
    if (inst_is_ret(task_clear_jobctl_trapping_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(task_clear_jobctl_trapping_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(task_clear_jobctl_trapping_src[i]) == 0) {
      struct_offset.task_struct_jobctl = inst_get_ldr_imm_uint_imm(task_clear_jobctl_trapping_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_jobctl=0x%x\n", struct_offset.task_struct_jobctl);  // 0x580
#endif                                                                   /* CONFIG_DEBUG */
  if (struct_offset.task_struct_jobctl <= 0)
    return -11;

  // 获取 binder_proc->context, binder_proc->inner_lock, binder_proc->outer_lock
  uint32_t* binder_transaction_src = (uint32_t*)binder_transaction;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(binder_transaction_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(binder_transaction_src[i]) == 0b11) {
      uint64_t offset = inst_get_ldr_imm_uint_imm(binder_transaction_src[i]);
      if (offset < 0x200 || offset > 0x300)
        continue;
      struct_offset.binder_proc_context = offset;
      struct_offset.binder_proc_inner_lock = offset + 0x8;
      struct_offset.binder_proc_outer_lock = offset + 0xC;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_proc_context=0x%x\n", struct_offset.binder_proc_context);        // 0x240
  logkm("binder_proc_inner_lock=0x%x\n", struct_offset.binder_proc_inner_lock);  // 0x248
  logkm("binder_proc_outer_lock=0x%x\n", struct_offset.binder_proc_outer_lock);  // 0x24C
#endif                                                                           /* CONFIG_DEBUG */
  if (struct_offset.binder_proc_context <= 0)
    return -11;

  // 获取 binder_proc->alloc
  void (*binder_free_proc)(struct binder_proc* proc);
  lookup_name_continue(binder_free_proc);
  if (!binder_free_proc) {
    void* binder_proc_dec_tmpref;
    lookup_name(binder_proc_dec_tmpref);
    binder_free_proc = binder_proc_dec_tmpref;
  }

  uint32_t* binder_free_proc_src = (uint32_t*)binder_free_proc;
  for (u32 i = 0x10; i + 1 < 0x40; i++) {
    if (inst_get_mov_reg_rd(binder_free_proc_src[i]) == 29 && inst_get_mov_reg_rm(binder_free_proc_src[i]) == 0) {
      break;
    } else if (inst_get_add_imm_sf(binder_free_proc_src[i]) == 1 && inst_get_add_imm_rd(binder_free_proc_src[i]) == 0
               && inst_get_add_imm_rn(binder_free_proc_src[i]) == 19 && inst_is_bl(binder_free_proc_src[i + 1])) {
      struct_offset.binder_proc_alloc = inst_get_add_imm_imm(binder_free_proc_src[i]);
      if (struct_offset.binder_proc_alloc > struct_offset.binder_proc_context) {
        continue;
      }
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_proc_alloc=0x%x\n", struct_offset.binder_proc_alloc);  // 0x1A8
#endif                                                                 /* CONFIG_DEBUG */
  if (struct_offset.binder_proc_alloc <= 0)
    return -11;

  // 获取 binder_alloc->pid, task_struct->pid, task_struct->group_leader
  void (*binder_alloc_init)(struct task_struct* t);
  lookup_name(binder_alloc_init);

  uint32_t* binder_alloc_init_src = (uint32_t*)binder_alloc_init;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(binder_alloc_init_src[i])) {
      for (u32 j = 1; j < 0x10 && j <= i; j++) {
        if (inst_get_add_imm_sf(binder_alloc_init_src[i - j]) == 1) {
          uint64_t binder_alloc_buffers_offset = inst_get_add_imm_imm(binder_alloc_init_src[i - j]);
          struct_offset.binder_alloc_buffer = binder_alloc_buffers_offset - 0x8;
          struct_offset.binder_alloc_free_async_space = binder_alloc_buffers_offset + 0x20;
          struct_offset.binder_alloc_buffer_size = binder_alloc_buffers_offset + 0x30;
          break;
        }
      }
      break;
    } else if (!struct_offset.binder_alloc_pid && inst_get_str_imm_uint_size(binder_alloc_init_src[i]) == 0b10
               && inst_get_str_imm_uint_rn(binder_alloc_init_src[i]) == 0
               && inst_get_str_imm_uint_rt(binder_alloc_init_src[i]) != 31) {
      struct_offset.binder_alloc_pid = inst_get_str_imm_uint_imm(binder_alloc_init_src[i]);
    } else if (!struct_offset.binder_alloc_pid && inst_get_ldr_imm_uint_size(binder_alloc_init_src[i]) == 0b10) {
      struct_offset.task_struct_pid = inst_get_ldr_imm_uint_imm(binder_alloc_init_src[i]);
      struct_offset.task_struct_tgid = struct_offset.task_struct_pid + 0x4;
    } else if (!struct_offset.binder_alloc_pid && inst_get_ldr_imm_uint_size(binder_alloc_init_src[i]) == 0b11) {
      struct_offset.task_struct_group_leader = inst_get_ldr_imm_uint_imm(binder_alloc_init_src[i]);
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_alloc_pid=0x%x\n", struct_offset.binder_alloc_pid);                            // 0x84
  logkm("binder_alloc_buffer_size=0x%x\n", struct_offset.binder_alloc_buffer_size);            // 0x78
  logkm("binder_alloc_free_async_space=0x%x\n", struct_offset.binder_alloc_free_async_space);  // 0x68
  logkm("binder_alloc_buffer=0x%x\n", struct_offset.binder_alloc_buffer);                      // 0x40
  logkm("task_struct_pid=0x%x\n", struct_offset.task_struct_pid);                              // 0x5D8
  logkm("task_struct_tgid=0x%x\n", struct_offset.task_struct_tgid);                            // 0x5DC
  logkm("task_struct_group_leader=0x%x\n", struct_offset.task_struct_group_leader);            // 0x618
#endif                                                                                         /* CONFIG_DEBUG */
  if (struct_offset.binder_alloc_buffer_size <= 0 || struct_offset.binder_alloc_pid <= 0
      || struct_offset.task_struct_pid <= 0 || struct_offset.task_struct_group_leader <= 0)
    return -11;

  // 获取 binder_transaction->from；独立入口在加锁后读取 from 并检查空指针。
  void* binder_get_txn_from_and_acq_inner;
  lookup_name_continue(binder_get_txn_from_and_acq_inner);
  if (binder_get_txn_from_and_acq_inner) {
    uint32_t* binder_get_txn_from_and_acq_inner_src = (uint32_t*)binder_get_txn_from_and_acq_inner;
    int transaction_reg = -1;
    bool argument = true;
    struct_offset.binder_transaction_from = -1;
    for (u32 i = 0; i + 1 < 0x1A; i++) {
      uint32_t word = binder_get_txn_from_and_acq_inner_src[i];
      if (inst_is_ret(word))
        break;
      if (inst_get_mov_reg_rd(word) == transaction_reg || inst_get_add_imm_rd(word) == transaction_reg)
        transaction_reg = -1;
      if (inst_is_bl(word) || inst_is_blr(word))
        argument = false;
      if (argument && inst_get_mov_reg_sf(word) == 1 && inst_get_mov_reg_rm(word) == 0
          && inst_get_mov_reg_rd(word) >= 19 && inst_get_mov_reg_rd(word) <= 28)
        transaction_reg = inst_get_mov_reg_rd(word);
      if (inst_get_ldr_imm_uint_size(word) == 0b11 && inst_get_ldr_imm_uint_rn(word) == transaction_reg
          && inst_get_ldr_imm_uint_rt(word) != 31 && inst_get_cbz_sf(binder_get_txn_from_and_acq_inner_src[i + 1]) == 1
          && inst_get_cbz_rt(binder_get_txn_from_and_acq_inner_src[i + 1]) == inst_get_ldr_imm_uint_rt(word)) {
        struct_offset.binder_transaction_from = inst_get_ldr_imm_uint_imm(word);
        break;
      }
      if (inst_get_ldr_imm_uint_rt(word) == transaction_reg)
        transaction_reg = -1;
    }
#ifdef CONFIG_DEBUG
    logkm("binder_transaction_from=0x%x\n", struct_offset.binder_transaction_from);
#endif /* CONFIG_DEBUG */
    if (struct_offset.binder_transaction_from < 0)
      return -11;
  }

  // 获取 binder_stats_deleted_addr
  void (*binder_free_transaction)(struct binder_transaction* t);
  lookup_name_continue(binder_free_transaction);
  if (!binder_free_transaction) {
    void* binder_send_failed_reply;
    lookup_name(binder_send_failed_reply);
    binder_free_transaction = binder_send_failed_reply;
  }

  uint32_t* binder_free_transaction_src = (uint32_t*)binder_free_transaction;
  for (u32 i = 0; i < 0x90; i++) {
    if (inst_is_adrp(binder_free_transaction_src[i])) {
      uint64_t inst_addr = (uint64_t)binder_free_transaction + i * 4;
      uint64_t adrp_offset = inst_get_adrp_label(binder_free_transaction_src[i]);
      uint64_t adrp_addr = (inst_addr + adrp_offset) & 0xFFFFFFFFFFFFF000;
      if (adrp_addr - ((uint64_t)kvar(binder_stats) & 0xFFFFFFFFFFFFF000) <= 0x1000) {
        uint64_t binder_stats_addr = (uint64_t)kvar(binder_stats) & 0xFFF;
        for (u32 j = 0; j < 0x10 && i + j < 0x90; j++) {
          if (inst_get_add_imm_sf(binder_free_transaction_src[i + j]) == 1) {
            uint64_t adrl_addr = inst_get_add_imm_imm(binder_free_transaction_src[i + j]);
            uint64_t deleted_offset = (adrl_addr - binder_stats_addr) & 0xFFF;
            if (deleted_offset == 0) {
              for (u32 k = 0; k < 0x10 && i + j + k < 0x90; k++) {
                if (inst_get_add_imm_sf(binder_free_transaction_src[i + j + k]) == 1) {
                  uint64_t offset = inst_get_add_imm_imm(binder_free_transaction_src[i + j + k]);
                  if (offset > 0xC0 && offset < 0xE0) {
                    struct_offset.binder_stats_deleted_transaction = offset;
                    break;
                  }
                }
              }
            } else if (deleted_offset > 0xC0 && deleted_offset < 0xE0) {
              struct_offset.binder_stats_deleted_transaction = deleted_offset;
              break;
            }
          }
        }
        break;
      }
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_stats_deleted_transaction=0x%llx\n",
        struct_offset.binder_stats_deleted_transaction);  // 0xCC
#endif                                                    /* CONFIG_DEBUG */
  if (struct_offset.binder_stats_deleted_transaction <= 0)
    return -11;

  // 获取 sk_buff->len
  void (*skb_trim)(struct sk_buff* skb, unsigned int len);
  lookup_name(skb_trim);

  uint32_t* skb_trim_src = (uint32_t*)skb_trim;
  for (u32 i = 0; i < 0x8; i++) {
    if (inst_is_ret(skb_trim_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(skb_trim_src[i]) == 0b10) {
      struct_offset.sk_buff_len = inst_get_ldr_imm_uint_imm(skb_trim_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("sk_buff_len=0x%x\n", struct_offset.sk_buff_len);  // 0x70
#endif                                                     /* CONFIG_DEBUG */
  if (struct_offset.sk_buff_len <= 0)
    return -11;

  // 获取 sk_buff->network_header, sk_buff->head
  void (*ipv6_find_tlv)(const struct sk_buff* skb, int offset, int type);
  lookup_name(ipv6_find_tlv);

  uint32_t* ipv6_find_tlv_src = (uint32_t*)ipv6_find_tlv;
  for (u32 i = 0; i < 0x8; i++) {
    if (inst_is_ret(ipv6_find_tlv_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(ipv6_find_tlv_src[i]) == 0b11) {
      struct_offset.sk_buff_head = inst_get_ldr_imm_uint_imm(ipv6_find_tlv_src[i]);
      struct_offset.sk_buff_data = struct_offset.sk_buff_head + 0x8;
    } else if (inst_is_ldrh_imm_uint(ipv6_find_tlv_src[i])) {
      struct_offset.sk_buff_network_header = inst_get_ldrh_imm_uint_imm(ipv6_find_tlv_src[i]);
      struct_offset.sk_buff_transport_header = struct_offset.sk_buff_network_header - 0x2;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("sk_buff_network_header=0x%x\n", struct_offset.sk_buff_network_header);  // 0xB4
  logkm("sk_buff_head=0x%x\n", struct_offset.sk_buff_head);                      // 0xD0
  logkm("sk_buff_data=0x%x\n", struct_offset.sk_buff_data);                      // 0xD8
#endif                                                                           /* CONFIG_DEBUG */
  if (struct_offset.sk_buff_network_header <= 0 || struct_offset.sk_buff_head <= 0)
    return -11;

  // Generic Netlink 偏移推导
  // 获取 genl_family->id、hdrsize；name/version/maxattr 的相对位置由配置段定义。
  void* genlmsg_put;
  lookup_name(genlmsg_put);

  uint32_t* genlmsg_put_src = (uint32_t*)genlmsg_put;
  struct_offset.genl_family_id = -1;
  struct_offset.genl_family_config = -1;
  int family_reg = 3;
  int config_reg = -1;
  bool config_first = false;
  for (u32 i = 0; i < 0x19; i++) {
    uint32_t word = genlmsg_put_src[i];
    if (inst_is_bl(word) || inst_is_blr(word) || inst_is_ret(word))
      break;
    if (inst_get_mov_reg_sf(word) == 1 && inst_get_mov_reg_rm(word) == 3)
      family_reg = inst_get_mov_reg_rd(word);
    if (inst_get_mov_reg_rd(word) == config_reg || inst_get_movz_imm_rd(word) == config_reg
        || inst_get_add_imm_rd(word) == config_reg)
      config_reg = -1;
    if (inst_get_ldr_imm_uint_size(word) == 0b10
        && (inst_get_ldr_imm_uint_rn(word) == 3 || inst_get_ldr_imm_uint_rn(word) == family_reg)) {
      int offset = inst_get_ldr_imm_uint_imm(word);
      // hdrsize 位于结构体头部时，id 直接作为 __nlmsg_put 的第四个参数。
      if (offset >= 28 && inst_get_ldr_imm_uint_rt(word) == 3 && config_reg >= 0 && i + 2 < 0x19
          && inst_get_add_imm_sf(genlmsg_put_src[i + 1]) == 0 && inst_get_add_imm_rd(genlmsg_put_src[i + 1]) == 4
          && inst_get_add_imm_rn(genlmsg_put_src[i + 1]) == config_reg
          && inst_get_add_imm_imm(genlmsg_put_src[i + 1]) == 4 && inst_is_bl(genlmsg_put_src[i + 2])) {
        struct_offset.genl_family_id = offset;
        struct_offset.genl_family_config = 0;
        config_first = true;
        break;
      }
      if (inst_get_ldr_imm_uint_rt(word) == config_reg)
        config_reg = -1;
      if (offset == 0 && inst_get_ldr_imm_uint_rt(word) != 31)
        config_reg = inst_get_ldr_imm_uint_rt(word);
      // 编译器可以调整读取顺序，保留两个最小且不同的偏移。
      if (struct_offset.genl_family_id < 0 || offset < struct_offset.genl_family_id) {
        struct_offset.genl_family_config = struct_offset.genl_family_id;
        struct_offset.genl_family_id = offset;
      } else if (offset != struct_offset.genl_family_id
                 && (struct_offset.genl_family_config < 0 || offset < struct_offset.genl_family_config)) {
        struct_offset.genl_family_config = offset;
      }
      if (struct_offset.genl_family_id >= 0 && struct_offset.genl_family_config == struct_offset.genl_family_id + 4)
        break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("genl_family_id=0x%x\n", struct_offset.genl_family_id);
  logkm("genl_family_config=0x%x\n", struct_offset.genl_family_config);
#endif /* CONFIG_DEBUG */
  if (struct_offset.genl_family_id < 0
      || (!config_first && struct_offset.genl_family_config != struct_offset.genl_family_id + 4))
    return -11;

  // 获取 genl_family->n_mcgrps、mcgrp_offset。
  void* genlmsg_multicast_allns;
  lookup_name(genlmsg_multicast_allns);

  uint32_t* genlmsg_multicast_allns_src = (uint32_t*)genlmsg_multicast_allns;
  struct_offset.genl_family_n_mcgrps = -1;
  struct_offset.genl_family_n_mcgrps_size = 0;
  struct_offset.genl_family_mcgrp_offset = -1;
  for (u32 i = 0; i < 0x20; i++) {
    uint32_t word = genlmsg_multicast_allns_src[i];
    if (inst_get_ldr_imm_uint_size(word) == 0b10 && inst_get_ldr_imm_uint_rn(word) == 0) {
      if (struct_offset.genl_family_n_mcgrps < 0) {
        struct_offset.genl_family_n_mcgrps = inst_get_ldr_imm_uint_imm(word);
        struct_offset.genl_family_n_mcgrps_size = 4;
      } else {
        struct_offset.genl_family_mcgrp_offset = inst_get_ldr_imm_uint_imm(word);
        break;
      }
    } else if (struct_offset.genl_family_n_mcgrps < 0 && inst_is_ldrb_imm_uint(word)
               && inst_get_ldrb_imm_uint_rn(word) == 0) {
      struct_offset.genl_family_n_mcgrps = inst_get_ldrb_imm_uint_imm(word);
      struct_offset.genl_family_n_mcgrps_size = 1;
    }
    if (inst_is_bl(word) || inst_is_blr(word) || inst_is_ret(word))
      break;
  }
#ifdef CONFIG_DEBUG
  logkm("genl_family_n_mcgrps=0x%x\n", struct_offset.genl_family_n_mcgrps);
  logkm("genl_family_n_mcgrps_size=%d\n", struct_offset.genl_family_n_mcgrps_size);
  logkm("genl_family_mcgrp_offset=0x%x\n", struct_offset.genl_family_mcgrp_offset);
#endif /* CONFIG_DEBUG */
  if (struct_offset.genl_family_n_mcgrps < 0 || struct_offset.genl_family_mcgrp_offset < 0)
    return -11;

  struct_offset.genl_family_mcgrps = -1;
  // 已确认的 32 位计数布局：mcgrps 指针、n_ops、n_mcgrps、mcgrp_offset 连续排列。
  if (struct_offset.genl_family_n_mcgrps_size == 4
      && struct_offset.genl_family_mcgrp_offset == struct_offset.genl_family_n_mcgrps + 4) {
    struct_offset.genl_family_mcgrps = struct_offset.genl_family_n_mcgrps - (int)(sizeof(void*) + sizeof(unsigned int));
  } else {
    // 独立的组播校验入口：检查组数后，用 mcgrps 读取首组 name[0]。
    uint32_t* genl_validate_assign_mc_groups_src = (uint32_t*)kallsyms_lookup_name("genl_validate_assign_mc_groups");
    if (genl_validate_assign_mc_groups_src) {
      int count_reg = -1;
      bool count = false;
      for (u32 i = 0; i < 0x18; i++) {
        uint32_t word = genl_validate_assign_mc_groups_src[i];
        if (inst_is_bl(word) || inst_is_blr(word) || inst_is_ret(word))
          break;
        if (!count
            && (inst_get_mov_reg_rd(word) == count_reg || inst_get_movz_imm_rd(word) == count_reg
                || inst_get_ldr_imm_uint_rt(word) == count_reg))
          count_reg = -1;
        if (inst_get_ldrb_imm_uint_rn(word) == 0 && inst_get_ldrb_imm_uint_rt(word) != 31
            && inst_get_ldrb_imm_uint_imm(word) == struct_offset.genl_family_n_mcgrps)
          count_reg = inst_get_ldrb_imm_uint_rt(word);
        if (inst_get_cbz_sf(word) == 0 && inst_get_cbz_rt(word) == count_reg)
          count = true;
        if (!count || inst_get_ldr_imm_uint_size(word) != 0b11 || inst_get_ldr_imm_uint_rn(word) != 0)
          continue;
        int rt = inst_get_ldr_imm_uint_rt(word);
        if (rt == 31)
          continue;
        for (u32 j = i + 1; j + 1 < 0x18 && j <= i + 3; j++) {
          uint32_t next = genl_validate_assign_mc_groups_src[j];
          if (inst_is_bl(next) || inst_is_blr(next) || inst_is_ret(next))
            break;
          if (inst_get_ldrb_imm_uint_rn(next) == rt && inst_get_ldrb_imm_uint_imm(next) == 0
              && inst_get_cbz_sf(genl_validate_assign_mc_groups_src[j + 1]) == 0
              && inst_get_cbz_rt(genl_validate_assign_mc_groups_src[j + 1]) == inst_get_ldrb_imm_uint_rt(next)) {
            struct_offset.genl_family_mcgrps = inst_get_ldr_imm_uint_imm(word);
            break;
          }
          if (inst_get_ldr_imm_uint_rt(next) == rt || inst_get_mov_reg_rd(next) == rt)
            break;
        }
        if (struct_offset.genl_family_mcgrps >= 0)
          break;
      }
    }
  }
  if (struct_offset.genl_family_mcgrps < 0) {
    // 获取 genl_family->mcgrps。
    void* genl_unregister_family;
    lookup_name(genl_unregister_family);

    // 注销组播的局部模式：mcgrps 指针参与数组寻址，事件参数 w0 为 CTRL_CMD_DELMCAST_GRP(8)。
    uint32_t* genl_unregister_family_src = (uint32_t*)genl_unregister_family;
    for (u32 i = 0x30; i < 0x55; i++) {
      uint32_t word = genl_unregister_family_src[i];
      if (inst_is_ret(word))
        break;
      if (inst_get_ldr_imm_uint_size(word) != 0b11)
        continue;
      int rt = inst_get_ldr_imm_uint_rt(word);
      bool event = false;
      for (u32 j = i > 0x31 ? i - 2 : 0x30; j <= i + 4 && j < 0x55; j++) {
        uint32_t next = genl_unregister_family_src[j];
        if (inst_is_bl(next) || inst_is_blr(next) || inst_is_ret(next)) {
          if (j > i)
            break;
          event = false;
          continue;
        }
        if ((inst_get_movz_imm_sf(next) == 0 && inst_get_movz_imm_rd(next) == 0 && inst_get_movz_imm_hw(next) == 0
             && inst_get_movz_imm_imm16(next) == 8)
            || (inst_get_orr_imm_sf(next) == 0 && inst_get_orr_imm_rn(next) == 31 && inst_get_orr_imm_rd(next) == 0
                && inst_get_orr_imm_imm(next) == 8))
          event = true;
        bool array = inst_get_add_ext_sf(next) == 1 && inst_get_add_ext_rd(next) == 2 && inst_get_add_ext_rn(next) == rt
                     && inst_get_add_ext_option(next) == 0b110 && inst_get_add_ext_imm3(next) == 4;
        // flags 扩展了 name[16] 后，循环按 17/18 字节累加偏移，再与组指针相加。
        if (inst_get_add_reg_sf(next) == 1 && inst_get_add_reg_rd(next) == 2 && inst_get_add_reg_rn(next) == rt
            && inst_get_add_reg_shift(next) == 0 && inst_get_add_reg_imm6(next) == 0 && j + 4 < 0x55
            && inst_is_bl(genl_unregister_family_src[j + 1])) {
          uint32_t step = genl_unregister_family_src[j + 4];
          int reg = inst_get_add_reg_rm(next);
          array = reg != 31 && inst_get_add_imm_sf(step) == 1 && inst_get_add_imm_rd(step) == reg
                  && inst_get_add_imm_rn(step) == reg
                  && (inst_get_add_imm_imm(step) == 17 || inst_get_add_imm_imm(step) == 18);
        }
        if (j > i && event && array) {
          struct_offset.genl_family_mcgrps = inst_get_ldr_imm_uint_imm(word);
          break;
        }
        // 后续读取或 MOV 覆盖加载结果后，ADD 已经不再使用这次指针读取。
        if (j > i
            && (inst_get_ldr_imm_uint_rt(next) == rt || inst_get_mov_reg_rd(next) == rt
                || inst_get_movz_imm_rd(next) == rt || inst_get_orr_imm_rd(next) == rt))
          break;
      }
      if (struct_offset.genl_family_mcgrps >= 0)
        break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("genl_family_mcgrps=0x%x\n", struct_offset.genl_family_mcgrps);
#endif /* CONFIG_DEBUG */
  if (struct_offset.genl_family_mcgrps < 0 || struct_offset.genl_family_mcgrps % sizeof(void*))
    return -11;

  // 获取 net->genl_sock。
  void* genl_pernet_exit;
  lookup_name(genl_pernet_exit);

  uint32_t* genl_pernet_exit_src = (uint32_t*)genl_pernet_exit;
  struct_offset.net_genl_sock = -1;
  for (u32 i = 0; i < 0x8; i++) {
    uint32_t word = genl_pernet_exit_src[i];
    if (inst_get_ldr_imm_uint_size(word) == 0b11 && inst_get_ldr_imm_uint_rn(word) == 0
        && inst_get_ldr_imm_uint_rt(word) == 0) {
      struct_offset.net_genl_sock = inst_get_ldr_imm_uint_imm(word);
      break;
    }
    if (inst_is_bl(word) || inst_is_blr(word) || inst_is_ret(word))
      break;
  }
#ifdef CONFIG_DEBUG
  logkm("net_genl_sock=0x%x\n", struct_offset.net_genl_sock);
#endif /* CONFIG_DEBUG */
  if (struct_offset.net_genl_sock < 0)
    return -11;

  // 核对 family 的字段范围和重叠；直接读取的字段已由 LDR 编码保证对齐。
  unsigned int fields[][2] = {{struct_offset.genl_family_id, sizeof(unsigned int)},
                              {struct_offset.genl_family_config, sizeof(struct genl_family_config)},
                              {struct_offset.genl_family_mcgrps, sizeof(void*)},
                              {struct_offset.genl_family_n_mcgrps, struct_offset.genl_family_n_mcgrps_size},
                              {struct_offset.genl_family_mcgrp_offset, sizeof(unsigned int)}};
  for (u32 i = 0; i < ARRAY_SIZE(fields); i++) {
    if (fields[i][0] + fields[i][1] > sizeof(struct genl_family))
      return -11;
    for (u32 j = 0; j < i; j++) {
      if (fields[i][0] < fields[j][0] + fields[j][1] && fields[j][0] < fields[i][0] + fields[i][1])
        return -11;
    }
  }
  return 0;
}

#endif /* CONFIG_KPM_BASELINES */
