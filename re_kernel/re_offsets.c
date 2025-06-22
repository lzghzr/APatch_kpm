// task_pid
static inline pid_t task_pid_nr(struct task_struct* task) {
  pid_t pid = *(pid_t*)((uintptr_t)task + struct_offset.task_struct_pid);
  return pid;
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
// binder_alloc_buffer
static inline void __user* binder_alloc_buffer(struct binder_alloc* alloc) {
  void __user* buffer = *(void __user**)((uintptr_t)alloc + struct_offset.binder_alloc_buffer);
  return buffer;
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

static long calculate_offsets() {
  // 获取 binder_transaction_buffer_release 版本, 以参数数量做判断
  uint32_t* binder_transaction_buffer_release_src = (uint32_t*)binder_transaction_buffer_release;
  for (u32 i = 0; i < 0x100; i++) {
#ifdef CONFIG_DEBUG
    logkm("binder_transaction_buffer_release %x %llx\n", i, binder_transaction_buffer_release_src[i]);
#endif /* CONFIG_DEBUG */
    if (i < 0x10) {
      if (inst_get_str_imm_uint_rt(binder_transaction_buffer_release_src[i]) == 4
          || inst_get_mov_reg_rm(binder_transaction_buffer_release_src[i]) == 4
          || inst_get_uxtb_rn(binder_transaction_buffer_release_src[i]) == 4) {
        binder_transaction_buffer_release_ver5 = IZERO;
      } else if (inst_get_str_imm_uint_rt(binder_transaction_buffer_release_src[i]) == 3
                 || inst_get_mov_reg_rm(binder_transaction_buffer_release_src[i]) == 3
                 || inst_get_uxtb_rn(binder_transaction_buffer_release_src[i]) == 3) {
        binder_transaction_buffer_release_ver4 = IZERO;
      }
    } else if (binder_transaction_buffer_release_ver5 == UZERO) {
      break;
    } else if (inst_get_and_imm_imm(binder_transaction_buffer_release_src[i]) == -8) {
      for (u32 j = 1; j < 0x3; j++) {
        if (inst_is_cbz(binder_transaction_buffer_release_src[i + j])
            || inst_is_tbnz(binder_transaction_buffer_release_src[i + j])) {
          binder_transaction_buffer_release_ver6 = IZERO;
          break;
        }
      }
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_transaction_buffer_release_ver6=0x%llx\n", binder_transaction_buffer_release_ver6);
  logkm("binder_transaction_buffer_release_ver5=0x%llx\n", binder_transaction_buffer_release_ver5);
  logkm("binder_transaction_buffer_release_ver4=0x%llx\n", binder_transaction_buffer_release_ver4);
#endif /* CONFIG_DEBUG */
  // 获取 binder_proc->is_frozen, 没有就是不支持
  uint32_t* binder_proc_transaction_src = (uint32_t*)binder_proc_transaction;
  for (u32 i = 0; i < 0x70; i++) {
#ifdef CONFIG_DEBUG
    logkm("binder_proc_transaction %x %llx\n", i, binder_proc_transaction_src[i]);
#endif /* CONFIG_DEBUG */
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

  // 获取 task_struct->jobctl
  void (*task_clear_jobctl_trapping)(struct task_struct* t);
  lookup_name(task_clear_jobctl_trapping);

  uint32_t* task_clear_jobctl_trapping_src = (uint32_t*)task_clear_jobctl_trapping;
  for (u32 i = 0; i < 0x10; i++) {
#ifdef CONFIG_DEBUG
    logkm("task_clear_jobctl_trapping %x %llx\n", i, task_clear_jobctl_trapping_src[i]);
#endif /* CONFIG_DEBUG */
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
#ifdef CONFIG_DEBUG
    logkm("binder_transaction %x %llx\n", i, binder_transaction_src[i]);
#endif /* CONFIG_DEBUG */
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
  for (u32 i = 0x10; i < 0x100; i++) {
#ifdef CONFIG_DEBUG
    logkm("binder_free_proc %x %llx\n", i, binder_free_proc_src[i]);
#endif /* CONFIG_DEBUG */
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
#ifdef CONFIG_DEBUG
    logkm("binder_alloc_init %x %llx\n", i, binder_alloc_init_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_ret(binder_alloc_init_src[i])) {
      for (u32 j = 1; j < 0x10; j++) {
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
               && inst_get_str_imm_uint_rn(binder_alloc_init_src[i]) == 0) {
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
  if (struct_offset.binder_alloc_pid <= 0 || struct_offset.task_struct_pid <= 0
      || struct_offset.task_struct_group_leader <= 0)
    return -11;

  // 获取 binder_stats_deleted_addr
  struct binder_stats kvar_def(binder_stats);
  kvar_lookup_name(binder_stats);
  void (*binder_free_transaction)(struct binder_transaction* t);
  lookup_name_continue(binder_free_transaction);
  if (!binder_free_transaction) {
    void* binder_send_failed_reply;
    lookup_name(binder_send_failed_reply);
    binder_free_transaction = binder_send_failed_reply;
  }

  uint32_t* binder_free_transaction_src = (uint32_t*)binder_free_transaction;
  for (u32 i = 0; i < 0x100; i++) {
#ifdef CONFIG_DEBUG
    logkm("binder_free_transaction %x %llx\n", i, binder_free_transaction_src[i]);
#endif /* CONFIG_DEBUG */
    if (inst_is_adrp(binder_free_transaction_src[i])) {
      uint64_t inst_addr = (uint64_t)binder_free_transaction + i * 4;
      uint64_t adrp_offset = inst_get_adrp_label(binder_free_transaction_src[i]);
      uint64_t adrp_addr = (inst_addr + adrp_offset) & 0xFFFFFFFFFFFFF000;
      if (adrp_addr - ((uint64_t)kvar(binder_stats) & 0xFFFFFFFFFFFFF000) <= 0x1000) {
        uint64_t binder_stats_addr = (uint64_t)kvar(binder_stats) & 0xFFF;
        for (u32 j = 0; j < 0x10; j++) {
          if (inst_get_add_imm_sf(binder_free_transaction_src[i + j]) == 1) {
            uint64_t adrl_addr = inst_get_add_imm_imm(binder_free_transaction_src[i + j]);
            uint64_t deleted_offset = (adrl_addr - binder_stats_addr) & 0xFFF;
            if (deleted_offset == 0) {
              for (u32 k = 0; k < 0x10; k++) {
                if (inst_get_add_imm_sf(binder_free_transaction_src[i + j + k]) == 1) {
                  uint64_t offset = inst_get_add_imm_imm(binder_free_transaction_src[i + j + k]);
                  if (offset > 0xC0 && offset < 0xE0) {
                    binder_stats_deleted_addr = adrp_addr + adrl_addr + offset;
                    break;
                  }
                }
              }
            } else if (deleted_offset > 0xC0 && deleted_offset < 0xE0) {
              binder_stats_deleted_addr = adrp_addr + adrl_addr;
              break;
            }
          }
        }
        break;
      }
    }
  }
#ifdef CONFIG_DEBUG
  logkm("binder_stats=0x%llx\n", kvar(binder_stats));
  logkm("binder_stats_deleted_addr=0x%llx\n", binder_stats_deleted_addr);  // binder_stats + 0xCC
#endif                                                                     /* CONFIG_DEBUG */
  if (binder_stats_deleted_addr == UZERO)
    return -11;

  return 0;
}
