/* SPDX-License-Identifier: GPL-2.0-or-later */
struct struct_offset {
  int16_t file_inode_ops;
  int16_t file_mapping;
  int16_t inode_superblock;
  int16_t inode_number;
  int16_t inode_nlink;
  int16_t inode_size;
  int16_t dentry_ops;
  int16_t file_ops_size;
  int16_t inode_ops_size;
  int16_t super_ops_size;
  int16_t dentry_ops_size;
  int16_t key_type_size;
  int16_t inode_private;
  int16_t file_private;
  int16_t file_position;
  int16_t file_flags;
  int16_t file_cred;
  int16_t fop_open;
  int16_t fop_release;
  int16_t fop_mmap;
  int16_t fop_splice_read;
  int16_t inode_file_ops;
  int16_t inode_data;
  int16_t inode_data_size;
  int16_t inode_hash;
  int16_t inode_blocks;
  int16_t iop_getattr;
  int16_t sop_drop_inode;
  int16_t sop_evict_inode;
  int16_t dentry_lock;
  int16_t fop_iterate;
  int16_t fop_iterate_shared;
  int16_t dop_init;
  int16_t dop_release;
  int16_t mutex_size;
  int16_t mutex_no_lockdep;
  int16_t key_callbacks;
  int16_t key_preparse_data;
  int16_t getattr_callback_args;
  int16_t getattr_function_args;
  int16_t kstat_inode_first;
  int16_t name_hash_args;
  int16_t permission_abi;
  int16_t fillattr_abi;
  int16_t getattr_context_kind;
  int16_t dir_actor_abi;
};

volatile struct struct_offset struct_offset __attribute__((section(".data.re_offsets"), used)) = {
    .file_inode_ops = -1,
    .file_mapping = -1,
    .inode_superblock = -1,
    .inode_number = -1,
    .inode_nlink = -1,
    .inode_size = -1,
    .dentry_ops = -1,
    .file_ops_size = -1,
    .inode_ops_size = -1,
    .super_ops_size = -1,
    .dentry_ops_size = -1,
    .key_type_size = -1,
    .inode_private = -1,
    .file_private = -1,
    .file_position = -1,
    .file_flags = -1,
    .file_cred = -1,
    .fop_open = -1,
    .fop_release = -1,
    .fop_mmap = -1,
    .fop_splice_read = -1,
    .inode_file_ops = -1,
    .inode_data = -1,
    .inode_data_size = -1,
    .inode_hash = -1,
    .inode_blocks = -1,
    .iop_getattr = -1,
    .sop_drop_inode = -1,
    .sop_evict_inode = -1,
    .dentry_lock = -1,
    .fop_iterate = -1,
    .fop_iterate_shared = -1,
    .dop_init = -1,
    .dop_release = -1,
    .mutex_size = -1,
    .mutex_no_lockdep = -1,
    .key_callbacks = -1,
    .key_preparse_data = -1,
    .getattr_callback_args = -1,
    .getattr_function_args = -1,
    .kstat_inode_first = -1,
    .name_hash_args = -1,
    .permission_abi = -1,
    .fillattr_abi = -1,
    .getattr_context_kind = -1,
    .dir_actor_abi = -1,
};

// 仅在确认BTF不可用后启用自建清零表容量；精确类型尺寸字段仍保持原语义。
static bool nm_owned_operation_fallback;

static int nm_operation_size(enum nm_ops_kind kind) {
  switch (kind) {
    case NM_FILE_OPS:
      return struct_offset.file_ops_size;
    case NM_INODE_OPS:
      return struct_offset.inode_ops_size;
    case NM_SUPER_OPS:
      return struct_offset.super_ops_size;
    case NM_DENTRY_OPS:
      return struct_offset.dentry_ops_size;
    case NM_KEY_TYPE:
      return struct_offset.key_type_size;
  }
  return -EINVAL;
}

static int nm_owned_operation_size(enum nm_ops_kind kind) {
  int size = nm_operation_size(kind);
  if (size == -1 && nm_owned_operation_fallback
      && (kind == NM_INODE_OPS || kind == NM_DENTRY_OPS || kind == NM_KEY_TYPE))
    return NM_OWNED_OPERATIONS_CAPACITY;
  return size;
}

// int保留原始停止值；bool的true表示继续，错误由原生actor所属对象保存。
static int nm_dir_emit(struct nm_dir_context* context, const char* name, int length, int64_t offset, u64 number,
                       unsigned int type) {
  if (struct_offset.dir_actor_abi == 0)
    return context->actor(context, name, length, offset, number, type);
  if (struct_offset.dir_actor_abi == 1)
    return context->actor_bool(context, name, length, offset, number, type) ? 0 : -ENOSPC;
  return -EOPNOTSUPP;
}

static int nm_name_hash_arguments(void) { return struct_offset.name_hash_args; }

static void nm_set_stat_identity(struct kstat* stat, u64 ino, u32 dev) {
  if (struct_offset.kstat_inode_first == 1) {
    struct nm_kstat_inode_first* attributes = (void*)stat;
    attributes->ino = ino;
    attributes->dev = dev;
  } else {
    struct nm_kstat_prefix* attributes = (void*)stat;
    attributes->ino = ino;
    attributes->dev = dev;
  }
}

static struct nm_key_callbacks* nm_key_callback_table(void* table) {
  return (void*)((uintptr_t)table + struct_offset.key_callbacks);
}
static const struct nm_key_data* nm_key_preparse_input(const struct key_preparsed_payload* prep) {
  return (const void*)((uintptr_t)prep + struct_offset.key_preparse_data);
}

static int nm_validate_control_layout(void) {
  int key_capacity = nm_owned_operation_size(NM_KEY_TYPE);
  if (struct_offset.mutex_size < 0 || struct_offset.mutex_no_lockdep < 0 || struct_offset.key_callbacks < 0
      || struct_offset.key_preparse_data < 0)
    return -ENOENT;
  if (struct_offset.mutex_no_lockdep != 1)
    return -EOPNOTSUPP;  // 含lockdep的mutex还需要原生动态class key注册。
  if (!struct_offset.mutex_size || struct_offset.mutex_size > 4096 || struct_offset.mutex_size % 8 || key_capacity <= 0
      || key_capacity > 4096 || key_capacity % 8 || struct_offset.key_callbacks < sizeof(struct nm_key_type_head)
      || struct_offset.key_callbacks % 8 || struct_offset.key_callbacks + sizeof(struct nm_key_callbacks) > key_capacity
      || struct_offset.key_preparse_data % 8 || struct_offset.key_preparse_data > 4096 - sizeof(struct nm_key_data))
    return -EINVAL;
  return 0;
}

static struct inode* nm_file_inode(const void* file) {
  const struct nm_file_inode_ops* objects = (const void*)((uintptr_t)file + struct_offset.file_inode_ops);
  return objects->f_inode;
}

static const void* nm_file_ops(const void* file) {
  const struct nm_file_inode_ops* objects = (const void*)((uintptr_t)file + struct_offset.file_inode_ops);
  return objects->f_op;
}

static void* nm_file_mapping(const void* file) { return *(void* const*)((uintptr_t)file + struct_offset.file_mapping); }

static struct super_block* nm_inode_superblock(const void* inode) {
  return *(struct super_block* const*)((uintptr_t)inode + struct_offset.inode_superblock);
}

static u64 nm_inode_number(const void* inode) { return *(const u64*)((uintptr_t)inode + struct_offset.inode_number); }

static u32 nm_inode_nlink(const void* inode) { return *(const u32*)((uintptr_t)inode + struct_offset.inode_nlink); }

static int64_t nm_inode_size(const void* inode) {
  return *(const int64_t*)((uintptr_t)inode + struct_offset.inode_size);
}

static const void* nm_dentry_ops(const void* dentry) {
  return *(void* const*)((uintptr_t)dentry + struct_offset.dentry_ops);
}

static struct inode* nm_dentry_inode(const void* dentry) { return ((const struct nm_dentry_head*)dentry)->d_inode; }

static u16 nm_inode_mode(const void* inode) { return ((const struct nm_inode_owner_prefix*)inode)->i_mode; }

static int validate_offsets(void) {
  if (struct_offset.file_inode_ops < 0 || struct_offset.file_mapping < 0 || struct_offset.inode_superblock < 0
      || struct_offset.inode_number < 0 || struct_offset.inode_nlink < 0 || struct_offset.inode_size < 0
      || struct_offset.dentry_ops < 0)
    return -ENOENT;
  if (struct_offset.file_inode_ops % 8 || struct_offset.file_mapping % 8 || struct_offset.inode_superblock % 8
      || struct_offset.inode_number % 8 || struct_offset.inode_nlink % 4 || struct_offset.inode_size % 8
      || struct_offset.dentry_ops % 8)
    return -EINVAL;
  return 0;
}

static void* nm_inode_private(const void* inode) {
  return __atomic_load_n((void* const*)((uintptr_t)inode + struct_offset.inode_private), __ATOMIC_ACQUIRE);
}
static void* nm_file_private(const void* file) { return *(void* const*)((uintptr_t)file + struct_offset.file_private); }
static void nm_set_file_private(void* file, void* value) {
  *(void**)((uintptr_t)file + struct_offset.file_private) = value;
}
static int64_t* nm_file_position(void* file) { return (void*)((uintptr_t)file + struct_offset.file_position); }
static u32 nm_file_flags(const void* file) {
  return ((const struct nm_file_flags_mode*)((uintptr_t)file + struct_offset.file_flags))->f_flags;
}
static const void* nm_file_cred(const void* file) { return *(void* const*)((uintptr_t)file + struct_offset.file_cred); }
static void* nm_fop(const void* file, int offset) {
  const void* ops = nm_file_ops(file);
  return ops ? *(void* const*)((uintptr_t)ops + offset) : NULL;
}
static void nm_set_fop(void* ops, int offset, void* callback) { *(void**)((uintptr_t)ops + offset) = callback; }
static void nm_inode_mmap_ready(void* inode) {
  // S_PRIVATE = 512，目标 fs.h；保留同时更新的其他 flags 位。
  __atomic_fetch_and(&((struct nm_inode_owner_prefix*)inode)->i_flags, ~512U, __ATOMIC_RELAXED);
}

static struct nm_inode_ops_mapping* nm_inode_objects(void* inode) {
  return (void*)((uintptr_t)inode + struct_offset.inode_superblock - offsetof(struct nm_inode_ops_mapping, i_sb));
}
static const void* nm_inode_ops(void* inode) {
  return __atomic_load_n(&nm_inode_objects(inode)->i_op, __ATOMIC_ACQUIRE);
}
static const void* nm_inode_file_ops(void* inode) {
  return __atomic_load_n((const void**)((uintptr_t)inode + struct_offset.inode_file_ops), __ATOMIC_ACQUIRE);
}
static void nm_publish_inode_ops(void* inode, const void* iops, const void* fops) {
  __atomic_store_n((const void**)((uintptr_t)inode + struct_offset.inode_file_ops), fops, __ATOMIC_RELEASE);
  __atomic_store_n(&nm_inode_objects(inode)->i_op, iops, __ATOMIC_RELEASE);
}
static struct nm_dentry_ops_data* nm_dentry_objects(void* dentry) {
  return (void*)((uintptr_t)dentry + struct_offset.dentry_ops);
}
static void* nm_dentry_lock_address(void* dentry) { return (void*)((uintptr_t)dentry + struct_offset.dentry_lock); }
static void nm_publish_dentry_ops(void* dentry, const void* ops, bool owned) {
  struct nm_dentry_head* head = dentry;
  if (owned)
    head->d_flags &= ~(0x1U | 0x2U | 0x8U | 0x10U | 0x04000000U);  // HASH / COMPARE / DELETE / PRUNE / REAL。
  head->d_flags |= 0x4U | 0x800U;                                  // REVALIDATE / WEAK_REVALIDATE。
  __atomic_store_n(&nm_dentry_objects(dentry)->d_op, ops, __ATOMIC_RELEASE);
}
static void* nm_inode_mapping(void* inode) { return nm_inode_objects(inode)->i_mapping; }
static void* nm_inode_data(void* inode) { return (void*)((uintptr_t)inode + struct_offset.inode_data); }
static void nm_reset_inode_mapping(void* inode) { nm_inode_objects(inode)->i_mapping = nm_inode_data(inode); }
static bool nm_inode_unhashed(void* inode) {
  // hlist_node::pprev 是第二个指针；只判断是否入哈希，不遍历原生链表。
  return !*((void**)((uintptr_t)inode + struct_offset.inode_hash) + 1);
}
static const void* nm_super_ops(void* sb) {
  return __atomic_load_n(&((struct nm_super_head*)sb)->s_op, __ATOMIC_ACQUIRE);
}
static bool nm_publish_super_ops(void* sb, const void** expected, const void* table) {
  return __atomic_compare_exchange_n(&((struct nm_super_head*)sb)->s_op, expected, table, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE);
}
static void* nm_operation_callback(const void* table, int offset) {
  return table ? *(void* const*)((uintptr_t)table + offset) : NULL;
}
static void nm_set_operation_callback(void* table, int offset, void* callback) {
  *(void**)((uintptr_t)table + offset) = callback;
}
static void nm_set_inode_private(void* inode, void* private) {
  __atomic_store_n((void**)((uintptr_t)inode + struct_offset.inode_private), private, __ATOMIC_RELEASE);
}
static const struct nm_path* nm_file_path(void* file) {
  return (void*)((uintptr_t)file + struct_offset.file_inode_ops
                 - (int)offsetof(struct nm_file_path_inode_ops, f_inode));
}

// 新建的纯虚拟目录保留原生嵌入映射；时间继承创建时的父目录，权限为 root:root 0755。
static void nm_initialize_directory_inode(void* inode, void* parent, u64 number, const void* iops, const void* fops) {
  struct nm_inode_owner_prefix* owner = inode;
  owner->i_mode = 0040755;
  owner->i_uid = 0;
  owner->i_gid = 0;
  owner->i_opflags |= 0x0004U;
  owner->i_flags |= 512U | 2U | 128U | 4096U;
  *(u64*)((uintptr_t)inode + struct_offset.inode_number) = number;
  struct nm_inode_size_times* times = (void*)((uintptr_t)inode + struct_offset.inode_size);
  *times = *(const struct nm_inode_size_times*)((uintptr_t)parent + struct_offset.inode_size);
  times->i_size = 4096;
  *(u64*)((uintptr_t)inode + struct_offset.inode_blocks) = 8;
  nm_publish_inode_ops(inode, iops, fops);
}
// 新 inode 解锁／发布前使用；原生锁、链表、引用和 i_data 保持原样。
static void nm_copy_backing_inode_attributes(void* inode, void* backing, u64 number) {
  struct nm_inode_owner_prefix* owner = inode;
  const struct nm_inode_owner_prefix* real = backing;
  owner->i_mode = real->i_mode;
  owner->i_uid = real->i_uid;
  owner->i_gid = real->i_gid;
  owner->i_opflags |= 0x0004U;                 // IOP_NOFOLLOW；首轮支持普通文件和目录。
  owner->i_flags |= 512U | 2U | 128U | 4096U;  // S_PRIVATE / NOATIME / NOCMTIME / NOSEC。
  *(u64*)((uintptr_t)inode + struct_offset.inode_number) = number;
  *(struct nm_inode_size_times*)((uintptr_t)inode + struct_offset.inode_size) =
      *(const struct nm_inode_size_times*)((uintptr_t)backing + struct_offset.inode_size);
  *(u64*)((uintptr_t)inode + struct_offset.inode_blocks) =
      *(const u64*)((uintptr_t)backing + struct_offset.inode_blocks);
}

static void nm_initialize_backing_directory_inode(void* inode, void* backing, u64 number, const void* iops,
                                                  const void* fops) {
  nm_copy_backing_inode_attributes(inode, backing, number);
  // 目录使用自己的 i_data；backing路径由info独立的path引用保活。
  nm_publish_inode_ops(inode, iops, fops);
}

static void nm_initialize_file_inode(void* inode, void* backing, u64 number, void* private, const void* iops,
                                     const void* fops) {
  nm_copy_backing_inode_attributes(inode, backing, number);
  nm_inode_objects(inode)->i_op = iops;
  nm_inode_objects(inode)->i_mapping = nm_inode_mapping(backing);
  *(const void**)((uintptr_t)inode + struct_offset.inode_file_ops) = fops;
  nm_set_inode_private(inode, private);
}

static int nm_validate_inode_offsets(const struct struct_offset* offsets) {
  if (offsets->inode_ops_size < 8 || offsets->inode_ops_size > 4096 || offsets->inode_ops_size % 8
      || offsets->super_ops_size < 8 || offsets->super_ops_size > 4096 || offsets->super_ops_size % 8)
    return -EINVAL;
  if (offsets->inode_superblock < 8 || offsets->inode_superblock % 8 || offsets->inode_private < 0
      || offsets->inode_private % 8 || offsets->inode_number < 0 || offsets->inode_number % 8 || offsets->inode_size < 0
      || offsets->inode_size % 8 || offsets->inode_nlink < 0 || offsets->inode_nlink % 4)
    return -EINVAL;
  const int fields[] = {offsets->inode_superblock - 8, offsets->inode_number, offsets->inode_nlink,
                        offsets->inode_size,           offsets->inode_blocks, offsets->inode_hash,
                        offsets->inode_file_ops,       offsets->inode_data,   offsets->inode_private};
  if (offsets->inode_data_size <= 0 || offsets->inode_data_size > 4096 || offsets->inode_data_size % 8)
    return -EINVAL;
  const int widths[] = {sizeof(struct nm_inode_ops_mapping),
                        8,
                        4,
                        sizeof(struct nm_inode_size_times),
                        8,
                        16,
                        8,
                        offsets->inode_data_size,
                        8};
  for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    if (fields[i] < sizeof(struct nm_inode_owner_prefix) || fields[i] % (i == 2 ? 4 : 8))
      return -EINVAL;
    for (unsigned int j = 0; j < i; j++)
      if (fields[i] < fields[j] + widths[j] && fields[j] < fields[i] + widths[i])
        return -EINVAL;
  }
  if (offsets->iop_getattr < 0 || offsets->iop_getattr % 8 || offsets->iop_getattr + 8 > offsets->inode_ops_size
      || offsets->sop_drop_inode < 0 || offsets->sop_drop_inode % 8
      || offsets->sop_drop_inode + 8 > offsets->super_ops_size || offsets->sop_evict_inode < 0
      || offsets->sop_evict_inode % 8 || offsets->sop_evict_inode + 8 > offsets->super_ops_size
      || offsets->sop_drop_inode == offsets->sop_evict_inode)
    return -EINVAL;
  if (offsets->getattr_callback_args < 0 || offsets->getattr_function_args < 0 || offsets->kstat_inode_first < 0
      || offsets->getattr_context_kind < 0)
    return -ENOENT;
  if ((offsets->getattr_callback_args != 3 && offsets->getattr_callback_args != 4
       && offsets->getattr_callback_args != 5)
      || (offsets->getattr_function_args != 2 && offsets->getattr_function_args != 4) || offsets->kstat_inode_first > 1)
    return -EOPNOTSUPP;
  if (offsets->getattr_context_kind > 2
      || (offsets->getattr_callback_args == 5) != (offsets->getattr_context_kind != 0))
    return -EOPNOTSUPP;
  return 0;
}

static int nm_validate_directory_offsets(const struct struct_offset* offsets) {
  if (offsets->dir_actor_abi < 0)
    return -ENOENT;
  if (offsets->dir_actor_abi > 1)
    return -EOPNOTSUPP;
  if (offsets->dentry_ops < sizeof(struct nm_dentry_head) || offsets->dentry_ops % 8
      || offsets->dentry_lock < sizeof(struct nm_dentry_head) || offsets->dentry_lock % 4
      || offsets->dentry_lock >= offsets->dentry_ops
      || offsets->dentry_ops_size < sizeof(struct nm_dentry_control_ops) + 8 || offsets->dentry_ops_size > 4096
      || offsets->dentry_ops_size % 8 || offsets->inode_ops_size < sizeof(struct nm_inode_lookup_ops))
    return -EINVAL;
  const int slots[] = {offsets->fop_iterate, offsets->fop_iterate_shared};
  if (slots[0] < 0 && slots[1] < 0)
    return -ENOENT;
  for (unsigned int i = 0; i < 2; i++) {
    if (slots[i] < -1
        || (slots[i] >= 0
            && (slots[i] < sizeof(struct nm_file_io_ops) || slots[i] % 8 || slots[i] + 8 > offsets->file_ops_size)))
      return -EINVAL;
  }
  if (slots[0] >= 0 && slots[0] == slots[1])
    return -EINVAL;
  if (offsets->dop_release < sizeof(struct nm_dentry_control_ops) || offsets->dop_release % 8
      || offsets->dop_release + 8 > offsets->dentry_ops_size || offsets->dop_init < -1
      || (offsets->dop_init >= 0
          && (offsets->dop_init < sizeof(struct nm_dentry_control_ops) || offsets->dop_init % 8
              || offsets->dop_init + 8 > offsets->dentry_ops_size || offsets->dop_init == offsets->dop_release)))
    return -EINVAL;
  return 0;
}

static int nm_validate_file_offsets(const struct struct_offset* offsets) {
  if (offsets->file_inode_ops < 0 || offsets->file_mapping < 0 || offsets->file_inode_ops % 8
      || offsets->file_mapping % 8)
    return -EINVAL;
  const int fields[] = {offsets->inode_private, offsets->file_private, offsets->file_position, offsets->file_flags,
                        offsets->file_cred};
  for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
    if (fields[i] < 0 || fields[i] % (i == 3 ? 4 : 8))
      return -EINVAL;
  const int file_fields[] = {offsets->file_private, offsets->file_position,  offsets->file_flags,
                             offsets->file_cred,    offsets->file_inode_ops, offsets->file_mapping};
  for (unsigned int i = 0; i < sizeof(file_fields) / sizeof(file_fields[0]); i++) {
    int width = i == 4 ? sizeof(struct nm_file_inode_ops) : 8;
    for (unsigned int j = 0; j < i; j++) {
      int other_width = j == 4 ? sizeof(struct nm_file_inode_ops) : 8;
      if (file_fields[i] < file_fields[j] + other_width && file_fields[j] < file_fields[i] + width)
        return -EINVAL;
    }
  }
  const int slots[] = {offsets->fop_open, offsets->fop_release, offsets->fop_mmap, offsets->fop_splice_read};
  for (unsigned int i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    if (slots[i] < sizeof(struct nm_file_io_ops) || slots[i] % 8 || slots[i] + 8 > offsets->file_ops_size)
      return -EINVAL;
    for (unsigned int j = 0; j < i; j++)
      if (slots[i] == slots[j])
        return -EINVAL;
  }
  return 0;
}

#ifndef CONFIG_KPM_BASELINES
#include "nm_btf.c"

static bool nm_load(uint32_t inst, int size, int rn) {
  return inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1
         && inst_get_ldr_imm_size(inst) == size && inst_get_ldr_imm_rn(inst) == rn && inst_get_ldr_imm_rt(inst) != 31;
}

static bool nm_store(uint32_t inst, int size, int rn) {
  return inst_is_str_imm(inst) && !bit(inst, 26) && inst_get_str_imm_size(inst) == size
         && inst_get_str_imm_rn(inst) == rn;
}

// 本阶段锚点均在入口参数被改写或调用前匹配，不跟踪函数后半部。
// full_name_hash 的入口以名字和长度寄存器区分两参／三参，不按内核版本选择。
static int nm_find_name_hash_arguments(const uint32_t* src) {
  if (inst_is_movz_imm(src[0]) && inst_get_movz_imm_sf(src[0]) && inst_get_movz_imm_rd(src[0]) == 2
      && !inst_get_movz_imm_hw(src[0]) && !inst_get_movz_imm_imm16(src[0]) && inst_is_subs_imm(src[1])
      && !inst_get_subs_imm_sf(src[1]) && inst_get_subs_imm_rn(src[1]) == 1 && inst_get_subs_imm_rd(src[1]) == 31
      && !inst_get_subs_imm_sh(src[1]) && inst_get_subs_imm_imm12(src[1]) == 7 && nm_load(src[2], 3, 0)
      && inst_get_ldr_imm_rt(src[2]) == 3 && !inst_get_ldr_imm_imm(src[2]) && inst_is_b_cond(src[3])
      && inst_get_b_cond_cond(src[3]) == 9 && inst_get_b_cond_imm19(src[3]) > 0)
    return 2;
  if (inst_is_cbz(src[0]) && !inst_get_cbz_sf(src[0]) && inst_get_cbz_rt(src[0]) == 2 && inst_get_cbz_imm19(src[0]) >= 6
      && inst_is_ubfm(src[1]) && !inst_get_ubfm_sf(src[1]) && !inst_get_ubfm_n(src[1]) && inst_get_ubfm_rn(src[1]) == 2
      && inst_get_ubfm_rd(src[1]) == 8 && inst_get_ubfm_immr(src[1]) == 29 && inst_get_ubfm_imms(src[1]) == 28
      && inst_is_mov_reg(src[2]) && inst_get_mov_reg_sf(src[2]) && inst_get_mov_reg_rd(src[2]) == 9
      && inst_get_mov_reg_rm(src[2]) == 31 && nm_load(src[3], 3, 1) && inst_get_ldr_imm_rt(src[3]) == 10
      && !inst_get_ldr_imm_imm(src[3]) && inst_is_subs_imm(src[4]) && !inst_get_subs_imm_sf(src[4])
      && inst_get_subs_imm_rn(src[4]) == 2 && inst_get_subs_imm_rd(src[4]) == 2 && !inst_get_subs_imm_sh(src[4])
      && inst_get_subs_imm_imm12(src[4]) == 8 && inst_is_b_cond(src[5]) && inst_get_b_cond_cond(src[5]) == 3
      && inst_get_b_cond_imm19(src[5]) > 0)
    return 3;
  return -EOPNOTSUPP;
}

// 共同片段无需另算偏移；用原生入口核对 path.mnt/dentry 与 dentry.d_inode。
static bool nm_rule_entry_save(uint32_t inst) {
  return (inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_size(inst) == 2 && inst_get_stp_rn(inst) == 31
          && (inst_get_stp_mode(inst) == 2 || inst_get_stp_mode(inst) == 3))
         || (inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rn(inst) == 31
             && inst_get_add_imm_rd(inst) == 29 && !inst_get_add_imm_imm(inst))
         || (nm_store(inst, 3, 31))
         || (inst_is_str_imm9(inst) && !bit(inst, 26) && inst_get_str_imm9_size(inst) == 3
             && inst_get_str_imm9_rn(inst) == 18 && inst_get_str_imm9_rt(inst) == 30
             && inst_get_str_imm9_mode(inst) == 1 && inst_get_str_imm9_imm9(inst) == 8);
}

static int nm_check_rule_prefixes(const uint32_t* open, const uint32_t* vfs) {
  bool mount = false;
  for (unsigned int i = 0; i < 5; i++) {
    if (nm_load(open[i], 3, 0) && inst_get_ldr_imm_rt(open[i]) != 0
        && inst_get_ldr_imm_imm(open[i]) == offsetof(struct nm_path, mnt)) {
      mount = true;
      break;
    }
    if (!nm_rule_entry_save(open[i]))
      break;
  }
  if (!mount)
    return -EOPNOTSUPP;
  for (unsigned int i = 0; i < 10; i++) {
    if (i + 4 < 10 && inst_is_mov_reg(vfs[i]) && inst_get_mov_reg_sf(vfs[i]) && inst_get_mov_reg_rd(vfs[i]) == 20
        && !inst_get_mov_reg_rm(vfs[i]) && inst_is_mov_reg(vfs[i + 1]) && inst_get_mov_reg_sf(vfs[i + 1])
        && inst_get_mov_reg_rd(vfs[i + 1]) == 19 && inst_get_mov_reg_rm(vfs[i + 1]) == 1 && nm_load(vfs[i + 2], 3, 0)
        && !inst_get_ldr_imm_rt(vfs[i + 2]) && inst_get_ldr_imm_imm(vfs[i + 2]) == offsetof(struct nm_path, dentry)
        && nm_load(vfs[i + 3], 2, 1) && inst_get_ldr_imm_rt(vfs[i + 3]) == 4 && nm_load(vfs[i + 4], 3, 0)
        && inst_get_ldr_imm_rt(vfs[i + 4]) == 1
        && inst_get_ldr_imm_imm(vfs[i + 4]) == offsetof(struct nm_dentry_head, d_inode))
      return 0;
    if (i + 6 < 10 && inst_is_ldp(vfs[i]) && !bit(vfs[i], 26) && inst_get_ldp_size(vfs[i]) == 2
        && !inst_get_ldp_rn(vfs[i]) && inst_get_ldp_rt(vfs[i]) == 10 && inst_get_ldp_rt2(vfs[i]) == 9
        && inst_get_ldp_mode(vfs[i]) == 2 && !inst_get_ldp_imm(vfs[i]) && inst_is_mov_reg(vfs[i + 1])
        && inst_get_mov_reg_sf(vfs[i + 1]) && inst_get_mov_reg_rd(vfs[i + 1]) == 8
        && inst_get_mov_reg_rm(vfs[i + 1]) == 1 && inst_is_mov_reg(vfs[i + 2]) && inst_get_mov_reg_sf(vfs[i + 2])
        && inst_get_mov_reg_rd(vfs[i + 2]) == 2 && inst_get_mov_reg_rm(vfs[i + 2]) == 31 && inst_is_stp(vfs[i + 3])
        && !bit(vfs[i + 3], 26) && inst_get_stp_size(vfs[i + 3]) == 2 && inst_get_stp_rn(vfs[i + 3]) == 1
        && inst_get_stp_mode(vfs[i + 3]) == 2 && inst_get_stp_rt(vfs[i + 3]) == 10 && inst_get_stp_rt2(vfs[i + 3]) == 9
        && inst_get_stp_imm(vfs[i + 3]) == struct_offset.file_inode_ops - sizeof(struct nm_path)
        && nm_load(vfs[i + 4], 3, 0) && inst_get_ldr_imm_rt(vfs[i + 4]) == 9
        && inst_get_ldr_imm_imm(vfs[i + 4]) == offsetof(struct nm_path, dentry) && inst_is_mov_reg(vfs[i + 5])
        && inst_get_mov_reg_sf(vfs[i + 5]) && !inst_get_mov_reg_rd(vfs[i + 5]) && inst_get_mov_reg_rm(vfs[i + 5]) == 8
        && nm_load(vfs[i + 6], 3, 9) && inst_get_ldr_imm_rt(vfs[i + 6]) == 1
        && inst_get_ldr_imm_imm(vfs[i + 6]) == offsetof(struct nm_dentry_head, d_inode))
      return 0;
    if (nm_rule_entry_save(vfs[i])
        || (inst_is_mov_reg(vfs[i]) && inst_get_mov_reg_sf(vfs[i]) && inst_get_mov_reg_rd(vfs[i]) == 3
            && inst_get_mov_reg_rm(vfs[i]) == 2))
      continue;
    break;
  }
  return -EOPNOTSUPP;
}

static int calculate_function_rule_layout(void) {
  const uint32_t* hash = (const void*)kallsyms_lookup_name_by_suffix("full_name_hash");
  if (!hash)
    return -ENOENT;
  int count = nm_find_name_hash_arguments(hash);
  if (count < 0)
    return count;
  const uint32_t* open = (const void*)kallsyms_lookup_name_by_suffix("dentry_open");
  const uint32_t* vfs = (const void*)kallsyms_lookup_name_by_suffix("vfs_open");
  if (!open || !vfs)
    return -ENOENT;
  int rc = nm_check_rule_prefixes(open, vfs);
  if (rc)
    return rc;
  struct_offset.name_hash_args = count;
  nm_log_info("layout: full_name_hash arguments=%d\n", count);
  return 0;
}

// CFI只跟随核心代码区内一条直接B；调用点与表回调共用同一规则。
static bool nm_code_matches(uintptr_t value, uintptr_t target, uintptr_t start, uintptr_t end) {
  if (!target)
    return false;
  if (value == target)
    return true;
  if (!start || end <= start || end - start < 4 || value < start || value > end - 4 || value % 4)
    return false;
  uint32_t inst = *(const uint32_t*)value;
  return inst_is_b(inst) && value + inst_get_b_label(inst) == target;
}

// 仅在已确认的完整原生表范围内找唯一回调；CFI 只跟随核心代码区的一条直接 B。
static int nm_find_file_callback(const uintptr_t* table, int size, uintptr_t target, uintptr_t start, uintptr_t end) {
  if (!table || !target)
    return -ENOENT;
  if (size < sizeof(struct nm_file_io_ops) || size > 4096 || size % 8)
    return -EINVAL;
  int found = -ENOENT;
  for (unsigned int slot = sizeof(struct nm_file_io_ops) / 8; slot < (unsigned int)size / 8; slot++) {
    if (!nm_code_matches(table[slot], target, start, end))
      continue;
    if (found >= 0)
      return -EINVAL;
    found = slot * 8;
  }
  return found;
}

static int calculate_file_callback_offsets(void) {
  const uintptr_t* table = (const void*)kallsyms_lookup_name_by_suffix("def_blk_fops");
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const char* names[] = {"blkdev_open", "blkdev_close", "generic_file_mmap", "generic_file_splice_read"};
  volatile int16_t* slots[] = {&struct_offset.fop_open, &struct_offset.fop_release, &struct_offset.fop_mmap,
                               &struct_offset.fop_splice_read};
  for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    int offset =
        nm_find_file_callback(table, struct_offset.file_ops_size, kallsyms_lookup_name_by_suffix(names[i]), start, end);
    if (offset < 0)
      return offset;
    *slots[i] = offset;
  }
  nm_log_info("layout: file callbacks open=%d release=%d mmap=%d splice_read=%d\n", struct_offset.fop_open,
              struct_offset.fop_release, struct_offset.fop_mmap, struct_offset.fop_splice_read);
  return 0;
}

static bool nm_argument_changed(uint32_t inst, int reg) {
  if (inst_is_bl(inst) || inst_is_blr(inst) || inst_is_br(inst) || inst_is_ret(inst) || inst_is_b(inst))
    return true;
  if (inst_is_ldp(inst))
    return inst_get_ldp_rt(inst) == reg || inst_get_ldp_rt2(inst) == reg
           || ((inst_get_ldp_mode(inst) == 1 || inst_get_ldp_mode(inst) == 3) && inst_get_ldp_rn(inst) == reg);
  if (inst_is_stp(inst))
    return (inst_get_stp_mode(inst) == 1 || inst_get_stp_mode(inst) == 3) && inst_get_stp_rn(inst) == reg;
  if (inst_is_ldr_imm9(inst) && (inst_get_ldr_imm9_mode(inst) & 1) && inst_get_ldr_imm9_rn(inst) == reg)
    return true;
  if (inst_is_str_imm9(inst))
    return (inst_get_str_imm9_mode(inst) & 1) && inst_get_str_imm9_rn(inst) == reg;
  if (inst_is_str_imm(inst) || inst_is_b_cond(inst) || inst_is_cbz(inst) || inst_is_cbnz(inst) || inst_is_tbz(inst)
      || inst_is_tbnz(inst))
    return false;
  return bits32(inst, 4, 0) == reg;
}

// 整对象构造入口的长度；调用者绑定对象语义及固定窗口，遇未知指令失败。
static int nm_find_complete_object_size(const uint32_t* src, unsigned int count, uintptr_t copy, uintptr_t clear,
                                        uintptr_t table, unsigned int minimum) {
  if (!count || count > 8)
    return -EINVAL;
  int size = -1, input_kind = 0;
  uintptr_t input = 0;
  for (unsigned int i = 0; i < count; i++) {
    uint32_t inst = src[i];
    if (inst_is_bl(inst)) {
      uintptr_t target = (uintptr_t)&src[i] + inst_get_bl_label(inst);
      if ((target != copy || !copy || input_kind != 3 || !table || input != table)
          && (target != clear || !clear || input_kind != 1))
        return -EOPNOTSUPP;
      return size >= (int)minimum && size <= 4096 && !(size % 8) ? size : -EINVAL;
    }
    if (inst_is_movz_imm(inst) && inst_get_movz_imm_rd(inst) == 2 && !inst_get_movz_imm_hw(inst)) {
      size = inst_get_movz_imm_imm16(inst);
    } else if (inst_is_movz_imm(inst) && inst_get_movz_imm_rd(inst) == 1 && !inst_get_movz_imm_hw(inst)
               && !inst_get_movz_imm_imm16(inst)) {
      input_kind = 1;  // memset 的零填充值。
    } else if (inst_is_mov_reg(inst) && !inst_get_mov_reg_sf(inst) && inst_get_mov_reg_rd(inst) == 1
               && inst_get_mov_reg_rm(inst) == 31) {
      input_kind = 1;
    } else if (inst_is_adrp(inst) && inst_get_adrp_rd(inst) == 1) {
      input = ((uintptr_t)&src[i] & ~(uintptr_t)4095) + inst_get_adrp_label(inst);
      input_kind = 2;
    } else if (inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rn(inst) == 1
               && inst_get_add_imm_rd(inst) == 1 && input_kind == 2) {
      input += inst_get_add_imm_imm(inst);
      input_kind = 3;
    } else if (inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rn(inst) == 31
               && inst_get_add_imm_rd(inst) == 29 && !inst_get_add_imm_imm(inst)) {
      // 建立 frame pointer。
    } else if (inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_size(inst) == 2 && inst_get_stp_rn(inst) == 31
               && inst_get_stp_rt(inst) == 29 && inst_get_stp_rt2(inst) == 30 && inst_get_stp_mode(inst) == 3) {
      // 保存 FP/LR；不改写参数寄存器。
    } else if (nm_store(inst, 3, 31) && inst_get_str_imm_rt(inst) == 19) {
      // 保存 callee-saved x19。
    } else if (inst_is_mov_reg(inst) && inst_get_mov_reg_sf(inst) && inst_get_mov_reg_rd(inst) == 19
               && !inst_get_mov_reg_rm(inst)) {
      // 把入口参数保存在 x19。
    } else if (inst_is_str_imm9(inst) && !bit(inst, 26) && inst_get_str_imm9_size(inst) == 3
               && inst_get_str_imm9_rn(inst) == 18 && inst_get_str_imm9_rt(inst) == 30
               && inst_get_str_imm9_mode(inst) == 1 && inst_get_str_imm9_imm9(inst) == 8) {
      // 目标 SCS 序言。
    } else {
      // 只接受已核对的序言和参数设置；未知指令可能有隐式目的寄存器。
      return -EOPNOTSUPP;
    }
  }
  return -ENOENT;
}

// tty_default_fops 的首个 BL 仍限定在前7条。
static int nm_find_file_operations_size(const uint32_t* src, uintptr_t copy, uintptr_t clear, uintptr_t table) {
  return nm_find_complete_object_size(src, 7, copy, clear, table, sizeof(struct nm_file_io_ops));
}

static int nm_find_private_fields(const uint32_t* src, struct struct_offset* next) {
  for (unsigned int i = 0; i + 2 < 4; i++) {
    if (nm_load(src[i], 3, 0) && inst_get_ldr_imm_rt(src[i]) != 1 && inst_is_cbz(src[i + 1])
        && inst_get_cbz_sf(src[i + 1]) && inst_get_cbz_imm19(src[i + 1]) == 2
        && inst_get_cbz_rt(src[i + 1]) == inst_get_ldr_imm_rt(src[i]) && nm_store(src[i + 2], 3, 1)
        && inst_get_str_imm_rt(src[i + 2]) == inst_get_ldr_imm_rt(src[i])) {
      int inode = inst_get_ldr_imm_imm(src[i]), file = inst_get_str_imm_imm(src[i + 2]);
      if (inode > 0x7fff || file > 0x7fff)
        return -EINVAL;
      next->inode_private = inode;
      next->file_private = file;
      return 0;
    }
    if (nm_argument_changed(src[i], 0) || nm_argument_changed(src[i], 1))
      break;
  }
  return -ENOENT;
}

static int nm_find_file_cred(const uint32_t* src) {
  for (unsigned int i = 0; i < 8; i++) {
    if (nm_load(src[i], 3, 0) && inst_get_ldr_imm_rt(src[i]) == 0)
      return inst_get_ldr_imm_imm(src[i]);
    if (nm_argument_changed(src[i], 0))
      break;
  }
  // file_ns_capable 的入口 CMP W2,B.LS 跳过无效 capability 的告警块；x0 沿该边保持为 file。
  if (inst_is_stp(src[0]) && !bit(src[0], 26) && inst_get_stp_rn(src[0]) == 31 && inst_get_stp_rt(src[0]) == 29
      && inst_get_stp_rt2(src[0]) == 30 && inst_get_stp_mode(src[0]) == 3 && inst_is_subs_imm(src[1])
      && !inst_get_subs_imm_sf(src[1]) && inst_get_subs_imm_rn(src[1]) == 2 && inst_get_subs_imm_rd(src[1]) == 31
      && !inst_get_subs_imm_sh(src[1]) && inst_get_subs_imm_imm12(src[1]) > 0 && inst_get_subs_imm_imm12(src[1]) < 64
      && inst_is_add_imm(src[2]) && inst_get_add_imm_sf(src[2]) && inst_get_add_imm_rn(src[2]) == 31
      && inst_get_add_imm_rd(src[2]) == 29 && !inst_get_add_imm_imm(src[2]) && inst_is_b_cond(src[3])
      && inst_get_b_cond_cond(src[3]) == 9) {
    int delta = inst_get_b_cond_imm19(src[3]);
    if (delta > 0 && delta < 9 && nm_load(src[3 + delta], 3, 0) && !inst_get_ldr_imm_rt(src[3 + delta]))
      return inst_get_ldr_imm_imm(src[3 + delta]);
  }
  return -ENOENT;
}

static int nm_find_file_flags(const uint32_t* src) {
  for (unsigned int i = 0; i + 2 < 5; i++) {
    unsigned int mask = i + 1;
    bool zero_result =
        (inst_is_mov_reg(src[mask]) && !inst_get_mov_reg_sf(src[mask]) && !inst_get_mov_reg_rd(src[mask])
         && inst_get_mov_reg_rm(src[mask]) == 31)
        || (inst_is_movz_imm(src[mask]) && !inst_get_movz_imm_sf(src[mask]) && !inst_get_movz_imm_rd(src[mask])
            && !inst_get_movz_imm_hw(src[mask]) && !inst_get_movz_imm_imm16(src[mask]));
    if (zero_result && mask + 2 < 5 && inst_get_ldr_imm_rt(src[i]) != 0)
      mask++;
    if (nm_load(src[i], 2, 1) && inst_get_ldr_imm_rt(src[i]) != 1 && mask + 1 < 5 && inst_is_and_imm(src[mask])
        && !inst_get_and_imm_sf(src[mask]) && inst_get_and_imm_rn(src[mask]) == inst_get_ldr_imm_rt(src[i])
        && inst_get_and_imm_rd(src[mask]) == inst_get_ldr_imm_rt(src[i]) && nm_store(src[mask + 1], 2, 1)
        && inst_get_str_imm_rt(src[mask + 1]) == inst_get_ldr_imm_rt(src[i])
        && inst_get_str_imm_imm(src[mask + 1]) == inst_get_ldr_imm_imm(src[i])) {
      int mode = inst_get_ldr_imm_imm(src[i]);
      return mode >= offsetof(struct nm_file_flags_mode, f_mode) ? mode - offsetof(struct nm_file_flags_mode, f_mode)
                                                                 : -EINVAL;
    }
    if (inst_is_b_cond(src[i]) || inst_is_cbz(src[i]) || inst_is_cbnz(src[i]) || inst_is_tbz(src[i])
        || inst_is_tbnz(src[i]) || nm_argument_changed(src[i], 1))
      break;
  }
  return -ENOENT;
}

static int calculate_file_entry_offsets(void) {
  const uint32_t* open = (const void*)kallsyms_lookup_name("simple_open");
  const uint32_t* seek = (const void*)kallsyms_lookup_name("noop_llseek");
  const uint32_t* flags = (const void*)kallsyms_lookup_name("nonseekable_open");
  const uint32_t* cred = (const void*)kallsyms_lookup_name("file_ns_capable");
  if (!open || !seek || !flags || !cred)
    return -ENOENT;
  struct struct_offset next = struct_offset;
  int rc = nm_find_private_fields(open, &next);
  if (rc)
    return rc;
  int position = nm_load(seek[0], 3, 0) && inst_get_ldr_imm_rt(seek[0]) == 0 && inst_is_ret(seek[1])
                     ? inst_get_ldr_imm_imm(seek[0])
                     : -ENOENT;
  int mode = nm_find_file_flags(flags), credentials = nm_find_file_cred(cred);
  if (position < 0 || mode < 0 || credentials < 0 || position > 0x7fff || mode > 0x7fff || credentials > 0x7fff)
    return -EINVAL;
  next.file_position = position;
  next.file_flags = mode;
  next.file_cred = credentials;
  const uint32_t* defaults = (const void*)kallsyms_lookup_name_by_suffix("tty_default_fops");
  if (!defaults)
    return -ENOENT;
  int size = nm_find_file_operations_size(defaults, kallsyms_lookup_name("memcpy"), kallsyms_lookup_name("memset"),
                                          kallsyms_lookup_name_by_suffix("tty_fops"));
  if (size < 0)
    return size;
  next.file_ops_size = size;
  nm_log_info("layout: file_operations size=%d (tty_default_fops)\n", size);
  // 对象字段与完整表尺寸已有入口证据；其余回调位置另行取得。
  struct_offset = next;
  return 0;
}

// generic_fillattr 的参数须保持为 inode/stat；未知指令可能有隐式目的寄存器。
static bool nm_scalar_copy_step(uint32_t inst) {
  if (inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1)
    return inst_get_ldr_imm_rt(inst) != 0 && inst_get_ldr_imm_rt(inst) != 1;
  if (inst_is_str_imm(inst) && !bit(inst, 26))
    return true;
  if (inst_is_ldp(inst) && !bit(inst, 26) && inst_get_ldp_mode(inst) == 2)
    return inst_get_ldp_rt(inst) != 0 && inst_get_ldp_rt(inst) != 1 && inst_get_ldp_rt2(inst) != 0
           && inst_get_ldp_rt2(inst) != 1;
  if (inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_mode(inst) == 2)
    return true;
  if (inst_is_add_imm(inst))
    return inst_get_add_imm_rd(inst) != 0 && inst_get_add_imm_rd(inst) != 1;
  if (inst_is_movz_imm(inst))
    return inst_get_movz_imm_rd(inst) != 0 && inst_get_movz_imm_rd(inst) != 1;
  if (inst_is_lslv(inst))
    return inst_get_lslv_rd(inst) != 0 && inst_get_lslv_rd(inst) != 1;
  return false;
}

static int nm_scalar_copy(const uint32_t* src, unsigned int count, int size, int destination) {
  for (unsigned int i = 0; i + 1 < count; i++) {
    if (nm_load(src[i], size, 0) && nm_store(src[i + 1], size, 1) && inst_get_ldr_imm_rt(src[i]) != 1
        && inst_get_ldr_imm_rt(src[i]) == inst_get_str_imm_rt(src[i + 1])
        && inst_get_str_imm_imm(src[i + 1]) == destination)
      return inst_get_ldr_imm_imm(src[i]);
    if (!nm_scalar_copy_step(src[i]))
      break;
  }
  return -ENOENT;
}

static int nm_find_kstat_prefix(const uint32_t* src) {
  bool first = nm_scalar_copy(src, 18, 1, offsetof(struct nm_kstat_inode_first, mode))
                   == offsetof(struct nm_inode_owner_prefix, i_mode)
               && nm_scalar_copy(src, 18, 2, offsetof(struct nm_kstat_inode_first, uid))
                      == offsetof(struct nm_inode_owner_prefix, i_uid)
               && nm_scalar_copy(src, 18, 2, offsetof(struct nm_kstat_inode_first, gid))
                      == offsetof(struct nm_inode_owner_prefix, i_gid);
  bool mask = nm_scalar_copy(src, 18, 1, offsetof(struct nm_kstat_prefix, mode))
                  == offsetof(struct nm_inode_owner_prefix, i_mode)
              && nm_scalar_copy(src, 18, 2, offsetof(struct nm_kstat_prefix, uid))
                     == offsetof(struct nm_inode_owner_prefix, i_uid)
              && nm_scalar_copy(src, 18, 2, offsetof(struct nm_kstat_prefix, gid))
                     == offsetof(struct nm_inode_owner_prefix, i_gid);
  return first != mask ? first : -EOPNOTSUPP;
}

static int nm_find_file_objects(const uint32_t* src) {
  for (unsigned int i = 0; i + 1 < 16; i++) {
    if (nm_load(src[i], 3, 0) && nm_load(src[i + 1], 3, inst_get_ldr_imm_rt(src[i]))
        && inst_get_ldr_imm_imm(src[i + 1]) == offsetof(struct nm_file_ops_head, llseek)) {
      int offset = inst_get_ldr_imm_imm(src[i]);
      return offset >= offsetof(struct nm_file_inode_ops, f_op) ? offset - offsetof(struct nm_file_inode_ops, f_op)
                                                                : -EINVAL;
    }
    if (nm_argument_changed(src[i], 0))
      break;
  }
  return -ENOENT;
}

static int nm_find_mapping(const uint32_t* src) {
  for (unsigned int i = 0; i + 3 < 8; i++) {
    unsigned int branch = i + 3;
    if (inst_is_movn_imm(src[branch]) && !inst_get_movn_imm_sf(src[branch]) && inst_get_movn_imm_rd(src[branch]) == 2
        && !inst_get_movn_imm_hw(src[branch]) && inst_get_movn_imm_imm16(src[branch]) == 7
        && inst_get_ldr_imm_rt(src[i + 2]) != 2)
      branch++;
    if (branch < 8 && nm_load(src[i], 3, 0) && nm_load(src[i + 1], 3, inst_get_ldr_imm_rt(src[i]))
        && nm_load(src[i + 2], 3, inst_get_ldr_imm_rt(src[i + 1])) && inst_is_cbz(src[branch])
        && inst_get_cbz_sf(src[branch]) && inst_get_cbz_rt(src[branch]) == inst_get_ldr_imm_rt(src[i + 2]))
      return inst_get_ldr_imm_imm(src[i]);
    if (nm_argument_changed(src[i], 0))
      break;
  }
  return -ENOENT;
}

static int nm_find_file_objects_from_iterate(const uint32_t* src) {
  for (unsigned int i = 0; i + 1 < 12; i++) {
    if (inst_is_ldp(src[i]) && inst_get_ldp_size(src[i]) == 2 && inst_get_ldp_mode(src[i]) == 2
        && inst_get_ldp_rn(src[i]) == 0 && inst_get_ldp_rt(src[i]) != 31 && inst_get_ldp_rt2(src[i]) != 31
        && inst_get_ldp_rt(src[i]) != inst_get_ldp_rt2(src[i])) {
      int ops = inst_get_ldp_rt2(src[i]);
      for (unsigned int j = i + 1; j < 12 && j <= i + 4; j++) {
        if (nm_load(src[j], 3, ops))
          return inst_get_ldp_imm(src[i]);
        if (nm_argument_changed(src[j], ops))
          break;
      }
      return -ENOENT;
    }
    // 分开的 f_op／f_inode 加载，中间不得覆盖操作表寄存器。
    if (i + 3 < 12 && nm_load(src[i], 3, 0) && inst_get_ldr_imm_rt(src[i]) != 0 && nm_load(src[i + 1], 3, 0)
        && inst_get_ldr_imm_rt(src[i + 1]) != inst_get_ldr_imm_rt(src[i])
        && inst_get_ldr_imm_imm(src[i]) == inst_get_ldr_imm_imm(src[i + 1]) + offsetof(struct nm_file_inode_ops, f_op)
        && nm_load(src[i + 2], 3, inst_get_ldr_imm_rt(src[i])) && inst_is_cbz(src[i + 3]) && inst_get_cbz_sf(src[i + 3])
        && inst_get_cbz_rt(src[i + 3]) == inst_get_ldr_imm_rt(src[i + 2]))
      return inst_get_ldr_imm_imm(src[i + 1]);
    if (nm_argument_changed(src[i], 0))
      break;
  }
  return -ENOENT;
}

static int nm_find_superblock(const uint32_t* src, int destination) {
  for (unsigned int i = 0; i + 2 < 8; i++) {
    unsigned int field = i + 1;
    if (inst_is_add_imm(src[field]) && inst_get_add_imm_sf(src[field]) && !inst_get_add_imm_rn(src[field])
        && inst_get_add_imm_rd(src[field]) != 0 && inst_get_add_imm_rd(src[field]) != 1
        && inst_get_add_imm_rd(src[field]) != inst_get_ldr_imm_rt(src[i]))
      field++;
    if (field + 1 < 8 && nm_load(src[i], 3, 0) && inst_get_ldr_imm_rt(src[i]) != 0 && inst_get_ldr_imm_rt(src[i]) != 1
        && nm_load(src[field], 2, inst_get_ldr_imm_rt(src[i]))
        && inst_get_ldr_imm_imm(src[field]) == offsetof(struct nm_super_head, s_dev)
        && inst_get_ldr_imm_rt(src[field]) != 1 && nm_store(src[field + 1], 2, 1)
        && inst_get_ldr_imm_rt(src[field]) == inst_get_str_imm_rt(src[field + 1])
        && inst_get_str_imm_imm(src[field + 1]) == destination)
      return inst_get_ldr_imm_imm(src[i]);
    if (!nm_scalar_copy_step(src[i]))
      break;
  }
  return -ENOENT;
}

static int nm_find_nlink(const uint32_t* src, unsigned int count) {
  for (unsigned int i = 0; i < count; i++) {
    if (nm_load(src[i], 2, 0))
      return inst_get_ldr_imm_imm(src[i]);
    if (nm_argument_changed(src[i], 0))
      break;
  }
  // set_nlink 的非零输入分支跳过 clear_nlink 调用；沿该边 x0 保持为入口 inode。
  if (count >= 8 && nm_rule_entry_save(src[0]) && inst_is_mov_reg(src[1]) && inst_get_mov_reg_sf(src[1])
      && inst_get_mov_reg_rd(src[1]) == 2 && !inst_get_mov_reg_rm(src[1]) && inst_is_add_imm(src[2])
      && inst_get_add_imm_sf(src[2]) && inst_get_add_imm_rn(src[2]) == 31 && inst_get_add_imm_rd(src[2]) == 29
      && !inst_get_add_imm_imm(src[2]) && inst_is_cbnz(src[3]) && !inst_get_cbnz_sf(src[3])
      && inst_get_cbnz_rt(src[3]) == 1) {
    unsigned int target = 3 + inst_get_cbnz_imm19(src[3]);
    if (target > 3 && target < count && nm_load(src[target], 2, 0) && !inst_get_ldr_imm_rt(src[target]))
      return inst_get_ldr_imm_imm(src[target]);
  }
  return -ENOENT;
}

static int nm_find_dentry_ops(const uint32_t* src) {
  // WARN_ON_ONCE(dentry->d_op) 的 GCC 入口；不穿越其告警分支。
  if (nm_load(src[0], 3, 0) && inst_get_ldr_imm_rt(src[0]) != 0 && inst_get_ldr_imm_rt(src[0]) != 1
      && inst_is_cbz(src[1]) && inst_get_cbz_sf(src[1]) && inst_get_cbz_rt(src[1]) == inst_get_ldr_imm_rt(src[0])
      && inst_get_cbz_imm19(src[1]) > 0)
    return inst_get_ldr_imm_imm(src[0]);
  for (unsigned int i = 0; i + 1 < 16; i++) {
    if (nm_load(src[i], 3, 0) && inst_is_cbnz(src[i + 1]) && inst_get_cbnz_sf(src[i + 1])
        && inst_get_ldr_imm_rt(src[i]) != 0 && inst_get_ldr_imm_rt(src[i]) != 1
        && inst_get_cbnz_rt(src[i + 1]) == inst_get_ldr_imm_rt(src[i])) {
      int offset = inst_get_ldr_imm_imm(src[i]);
      for (unsigned int j = i + 2; j < 16; j++) {
        if (nm_store(src[j], 3, 0) && inst_get_str_imm_rt(src[j]) == 1 && inst_get_str_imm_imm(src[j]) == offset)
          return offset;
        if (nm_argument_changed(src[j], 0) || nm_argument_changed(src[j], 1))
          break;
      }
      return -ENOENT;
    }
    if (nm_argument_changed(src[i], 0) || nm_argument_changed(src[i], 1))
      break;
  }
  return -ENOENT;
}

static int calculate_function_offsets(void) {
  const uint32_t* seek = (const void*)kallsyms_lookup_name("vfs_llseek");
  const uint32_t* mmap = (const void*)kallsyms_lookup_name("generic_file_mmap");
  const uint32_t* iterate = (const void*)kallsyms_lookup_name("iterate_dir");
  const uint32_t* attr = (const void*)kallsyms_lookup_name("generic_fillattr");
  const uint32_t* set = (const void*)kallsyms_lookup_name("set_nlink");
  const uint32_t* inc = (const void*)kallsyms_lookup_name("inc_nlink");
  const uint32_t* dops = (const void*)kallsyms_lookup_name("d_set_d_op");
  if (!seek || !mmap || !iterate || !attr || !set || !inc || !dops)
    return -ENOENT;
  int objects = nm_find_file_objects(seek), mapping = nm_find_mapping(mmap);
  int pair = nm_find_file_objects_from_iterate(iterate);
  nm_log_info("layout: file objects=%d/%d mapping=%d\n", objects, pair, mapping);
  if (objects < 0 || mapping < 0 || objects != pair || objects > 0x7fff || mapping > 0x7fff)
    return -EINVAL;
  struct_offset.file_inode_ops = objects;
  struct_offset.file_mapping = mapping;
  int first = nm_find_kstat_prefix(attr);
  if (first < 0)
    return first;
  int dev_position = first ? offsetof(struct nm_kstat_inode_first, dev) : offsetof(struct nm_kstat_prefix, dev);
  int ino_position = first ? offsetof(struct nm_kstat_inode_first, ino) : offsetof(struct nm_kstat_prefix, ino);
  int size_position = first ? offsetof(struct nm_kstat_inode_first, size) : offsetof(struct nm_kstat_prefix, size);
  int sb = nm_find_superblock(attr, dev_position);
  int ino = nm_scalar_copy(attr, 18, 3, ino_position);
  int size = nm_scalar_copy(attr, 18, 3, size_position);
  int nlink = nm_find_nlink(set, 8), corroboration = nm_find_nlink(inc, 16);
  nm_log_info("layout: inode sb=%d ino=%d size=%d nlink=%d/%d\n", sb, ino, size, nlink, corroboration);
  if (sb < 0 || ino < 0 || size < 0 || nlink < 0 || nlink != corroboration || sb > 0x7fff || ino > 0x7fff
      || size > 0x7fff || nlink > 0x7fff)
    return -EINVAL;
  struct_offset.kstat_inode_first = first;
  struct_offset.inode_superblock = sb;
  struct_offset.inode_number = ino;
  struct_offset.inode_size = size;
  struct_offset.inode_nlink = nlink;
  int op = nm_find_dentry_ops(dops);
  nm_log_info("layout: dentry ops=%d\n", op);
  if (op < 0 || op > 0x7fff)
    return -EINVAL;
  struct_offset.dentry_ops = op;
  return 0;
}
struct nm_initial_fops_probe {
  uintptr_t open;
  uintptr_t start;
  uintptr_t code_end;
  uintptr_t end;
};

// 初始化器写入i_fop的对象可以没有可查的C局部变量名；核对其已知open槽。
static bool nm_initial_fops_matches(uintptr_t table, const struct nm_initial_fops_probe* probe) {
  int size = struct_offset.file_ops_size, open = struct_offset.fop_open;
  if (!probe || !probe->open || !table || table % sizeof(void*) || size <= 0 || size > 4096 || size % 8 || open < 0
      || open % 8 || open > size - (int)sizeof(void*) || probe->end <= probe->start
      || (unsigned int)size > probe->end - probe->start || table < probe->start
      || table > probe->end - (unsigned int)size)
    return false;
  uintptr_t callback = *(const uintptr_t*)(table + open);
  return nm_code_matches(callback, probe->open, probe->start, probe->code_end);
}

// inode_init_always首21条仍以x1为inode；跟踪ADRP/ADD/STR，并核对原表身份或open回调。
static int nm_probe_inode_storage(const uint32_t* src, uintptr_t no_open, const struct nm_initial_fops_probe* probe,
                                  int* data) {
  if (!no_open && !probe)
    return -ENOENT;
  uintptr_t addresses[32] = {0};
  int mapping = -1;
  for (unsigned int i = 0; i < 21; i++) {
    uint32_t inst = src[i];
    if (nm_rule_entry_save(inst)) {
      if (inst_is_add_imm(inst))
        addresses[29] = 0;
      else if (inst_is_str_imm9(inst))
        addresses[18] = 0;
      continue;
    }
    if (inst_is_adrp(inst) && inst_get_adrp_rd(inst) != 1 && inst_get_adrp_rd(inst) != 31) {
      addresses[inst_get_adrp_rd(inst)] = ((uintptr_t)&src[i] & ~(uintptr_t)4095) + inst_get_adrp_label(inst);
    } else if (inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rd(inst) != 1
               && inst_get_add_imm_rd(inst) != 31) {
      int rd = inst_get_add_imm_rd(inst), rn = inst_get_add_imm_rn(inst), imm = inst_get_add_imm_imm(inst);
      if (rn == 1 && rd >= 19 && rd <= 28) {
        if (mapping >= 0 && mapping != imm)
          return -EINVAL;
        mapping = imm;
      }
      addresses[rd] = addresses[rn] ? addresses[rn] + imm : 0;
    } else if (inst_is_str_imm(inst) && !bit(inst, 26) && inst_get_str_imm_rn(inst) == 1) {
      uintptr_t table = addresses[inst_get_str_imm_rt(inst)];
      int file_ops = inst_get_str_imm_imm(inst);
      if (inst_get_str_imm_size(inst) == 3
          && (no_open ? table == no_open
                      : mapping == file_ops + sizeof(struct nm_inode_file_locks)
                            && nm_initial_fops_matches(table, probe))) {
        if (mapping != file_ops + sizeof(struct nm_inode_file_locks))
          return -EINVAL;
        *data = mapping;
        return file_ops;
      }
    } else if (inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1
               && inst_get_ldr_imm_rt(inst) != 1) {
      addresses[inst_get_ldr_imm_rt(inst)] = 0;
    } else if (inst_is_mov_reg(inst) && inst_get_mov_reg_rd(inst) != 1) {
      addresses[inst_get_mov_reg_rd(inst)] = 0;
    } else if (inst_is_movz_imm(inst) && inst_get_movz_imm_rd(inst) != 1) {
      addresses[inst_get_movz_imm_rd(inst)] = 0;
    } else {
      return -EOPNOTSUPP;
    }
  }
  return -ENOENT;
}

static int nm_find_inode_storage(const uint32_t* src, uintptr_t no_open, int* data) {
  return nm_probe_inode_storage(src, no_open, NULL, data);
}

static int calculate_function_inode_offsets(void) {
  const uint32_t* clear = (const void*)kallsyms_lookup_name_by_suffix("address_space_init_once");
  const uint32_t* init = (const void*)kallsyms_lookup_name_by_suffix("inode_init_always");
  const uint32_t* attr = (const void*)kallsyms_lookup_name_by_suffix("generic_fillattr");
  uintptr_t no_open = kallsyms_lookup_name("inode_init_always.no_open_fops");
  if (!no_open)
    no_open = kallsyms_lookup_name_by_suffix("no_open_fops");
  if (!clear || !init || !attr) {
    nm_log_error("layout: inode storage anchor unavailable\n");
    return -ENOENT;
  }
  int data = -1, file_ops;
  if (no_open) {
    file_ops = nm_find_inode_storage(init, no_open, &data);
  } else {
    struct nm_initial_fops_probe probe = {kallsyms_lookup_name_by_suffix("no_open"), kallsyms_lookup_name("_stext"),
                                          kallsyms_lookup_name("_etext"), kallsyms_lookup_name("_end")};
    if (!probe.end)
      probe.end = kallsyms_lookup_name("__end_rodata");
    if (!probe.open || !probe.start || probe.end <= probe.start) {
      nm_log_error("layout: inode initial file table interval unavailable\n");
      return -ENOENT;
    }
    // 链接器的绝对_etext可能保留链接地址；只采用已重定位的只读段起点作代码上界。
    if (probe.code_end <= probe.start || probe.code_end > probe.end) {
      probe.code_end = kallsyms_lookup_name("__start_rodata");
      if (probe.code_end <= probe.start || probe.code_end > probe.end) {
        nm_log_error("layout: inode code boundary symbol shape unsupported\n");
        return -ENOENT;
      }
    }
    file_ops = nm_probe_inode_storage(init, 0, &probe, &data);
    if (file_ops >= 0)
      nm_log_info("layout: inode initial file table identified by open callback\n");
  }
  if (file_ops < 0) {
    nm_log_error("layout: inode initializer pattern or geometry rejected (%d)\n", file_ops);
    return file_ops;
  }
  int size = nm_find_complete_object_size(clear, 8, 0, kallsyms_lookup_name("memset"), 0, 8);
  int first = nm_find_kstat_prefix(attr);
  if (file_ops < 0 || size < 0 || first < 0)
    return file_ops < 0 ? file_ops : size < 0 ? size : first;
  int destination =
      first ? offsetof(struct nm_kstat_inode_first_blocks, blocks) : offsetof(struct nm_kstat_blocks, blocks);
  int blocks = nm_scalar_copy(attr, 36, 3, destination);
  if (data < 0 || data > 0x7fff || file_ops > 0x7fff || blocks < 0 || blocks > 0x7fff)
    return -EINVAL;
  struct_offset.inode_file_ops = file_ops;
  struct_offset.inode_data = data;
  struct_offset.inode_data_size = size;
  struct_offset.inode_blocks = blocks;
  struct_offset.kstat_inode_first = first;
  nm_log_info("layout: inode fop=%d data=%d/%d blocks=%d kstat_first=%d\n", file_ops, data, size, blocks, first);
  return 0;
}

static bool nm_move(uint32_t inst, int rd, int rm) {
  return inst_is_mov_reg(inst) && inst_get_mov_reg_sf(inst) && inst_get_mov_reg_rd(inst) == rd
         && inst_get_mov_reg_rm(inst) == rm;
}

static bool nm_load_at(uint32_t inst, int rd, int rn, int offset) {
  return nm_load(inst, 3, rn) && inst_get_ldr_imm_rt(inst) == rd && inst_get_ldr_imm_imm(inst) == offset;
}

static bool nm_move32(uint32_t inst, int rd, int rm) {
  return inst_is_mov_reg(inst) && !inst_get_mov_reg_sf(inst) && inst_get_mov_reg_rd(inst) == rd
         && inst_get_mov_reg_rm(inst) == rm;
}

static bool nm_add_at(uint32_t inst, int rd, int rn, int offset) {
  return inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rd(inst) == rd
         && inst_get_add_imm_rn(inst) == rn && inst_get_add_imm_imm(inst) == offset;
}

static bool nm_zero64(uint32_t inst, int rd) {
  return nm_move(inst, rd, 31)
         || (inst_is_movz_imm(inst) && inst_get_movz_imm_sf(inst) && inst_get_movz_imm_rd(inst) == rd
             && !inst_get_movz_imm_hw(inst) && !inst_get_movz_imm_imm16(inst));
}

static bool nm_cfi_gate(const uint32_t* src, int callback, int scratch, int skip_call) {
  return inst_is_adrp(src[0]) && inst_get_adrp_rd(src[0]) == scratch && inst_is_add_imm(src[1])
         && inst_get_add_imm_sf(src[1]) && inst_get_add_imm_rn(src[1]) == scratch
         && inst_get_add_imm_rd(src[1]) == scratch && inst_is_sub_reg(src[2]) && inst_get_sub_reg_sf(src[2])
         && inst_get_sub_reg_rd(src[2]) == scratch && inst_get_sub_reg_rn(src[2]) == callback
         && inst_get_sub_reg_rm(src[2]) == scratch && !inst_get_sub_reg_shift(src[2]) && !inst_get_sub_reg_imm6(src[2])
         && inst_is_extr(src[3]) && inst_get_extr_sf(src[3]) && inst_get_extr_n(src[3])
         && inst_get_extr_rd(src[3]) == scratch && inst_get_extr_rn(src[3]) == scratch
         && inst_get_extr_rm(src[3]) == scratch && inst_get_extr_imm6(src[3]) == 2 && inst_is_subs_imm(src[4])
         && inst_get_subs_imm_sf(src[4]) && inst_get_subs_imm_rd(src[4]) == 31
         && inst_get_subs_imm_rn(src[4]) == scratch && inst_get_subs_imm_imm(src[4]) > 0 && inst_is_b_cond(src[5])
         && inst_get_b_cond_cond(src[5]) == 2 && inst_get_b_cond_label(src[5]) > skip_call;
}

// generic_drop_inode 在两个目标均内联；ext4 回调入口先检查 nlink，再检查 hlist.pprev。
static int nm_find_inode_hash(const uint32_t* src) {
  unsigned int i = 0;
  while (i < 8
         && (nm_rule_entry_save(src[i])
             || (inst_is_movz_imm(src[i]) && !inst_get_movz_imm_sf(src[i]) && inst_get_movz_imm_rd(src[i]) == 21
                 && !inst_get_movz_imm_hw(src[i]) && inst_get_movz_imm_imm16(src[i]) == 1)))
    i++;
  if (i + 3 >= 12 || !nm_load(src[i], 2, 0) || inst_get_ldr_imm_imm(src[i]) != struct_offset.inode_nlink)
    return -EOPNOTSUPP;
  int nlink = inst_get_ldr_imm_rt(src[i++]), base = 0;
  if (nlink == 0 || nlink == 31)
    return -EOPNOTSUPP;
  if (i < 9 && nm_move(src[i], 19, 0)) {
    if (nlink == 19)
      return -EOPNOTSUPP;
    base = 19;
    i++;
  }
  if (!inst_is_cbz(src[i]) || inst_get_cbz_sf(src[i]) || inst_get_cbz_rt(src[i]) != nlink
      || inst_get_cbz_label(src[i]) <= 8)
    return -EOPNOTSUPP;
  i++;
  if (!nm_load(src[i], 3, base))
    return -EOPNOTSUPP;
  int pointer = inst_get_ldr_imm_rt(src[i]), offset = inst_get_ldr_imm_imm(src[i]);
  uint32_t test = src[i + 1];
  bool zero =
      inst_is_cbz(test) && inst_get_cbz_sf(test) && inst_get_cbz_rt(test) == pointer && inst_get_cbz_label(test) > 0;
  bool compare = inst_is_subs_reg(test) && inst_get_subs_reg_sf(test) && inst_get_subs_reg_rd(test) == 31
                 && inst_get_subs_reg_rn(test) == pointer && inst_get_subs_reg_rm(test) == 31
                 && !inst_get_subs_reg_shift(test) && !inst_get_subs_reg_imm6(test);
  if ((!zero && !compare) || pointer == 31 || offset < sizeof(struct nm_hlist_node) || offset % 8 || offset > 0x7fff)
    return -EINVAL;
  return offset - offsetof(struct nm_hlist_node, pprev);
}

// 短 simple_getattr 核对回调参数与 generic_fillattr 的两参数调用，止于首个 BL。
static int nm_check_simple_getattr(const uint32_t* src, uintptr_t fill, bool path) {
  unsigned int i = 0;
  while (i < 4 && nm_rule_entry_save(src[i])) i++;
  if (path) {
    if (i + 4 >= 9 || !nm_load_at(src[i], 8, 0, offsetof(struct nm_path, dentry)) || !nm_move(src[i + 1], 20, 1)
        || !nm_load_at(src[i + 2], 19, 8, offsetof(struct nm_dentry_head, d_inode)))
      return -EOPNOTSUPP;
    i += 3;
  } else {
    if (i + 4 >= 9 || !nm_load_at(src[i], 19, 1, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[i + 1], 1, 2)
        || !nm_store(src[i + 2], 3, 29) || inst_get_str_imm_rt(src[i + 2]) != 2)
      return -EOPNOTSUPP;
    i += 3;
  }
  if (!nm_move(src[i], 0, 19) || !inst_is_bl(src[i + 1])
      || (uintptr_t)&src[i + 1] + inst_get_bl_label(src[i + 1]) != fill)
    return -EOPNOTSUPP;
  return 0;
}

// 只接两种已核对入口：mount/dentry/stat 为12条，path/stat/mask/flags 为29条。
static int nm_find_getattr_layout(const uint32_t* src, const uint32_t* simple, uintptr_t fill) {
  bool path = nm_load_at(src[0], 8, 0, offsetof(struct nm_path, dentry));
  int field;
  if (!path) {
    if (!nm_rule_entry_save(src[0]) || !nm_move(src[1], 5, 0) || !nm_move(src[2], 2, 1) || !nm_rule_entry_save(src[3])
        || !nm_load_at(src[4], 4, 0, offsetof(struct nm_path, dentry))
        || !nm_load_at(src[5], 0, 4, offsetof(struct nm_dentry_head, d_inode))
        || !nm_load_at(src[6], 3, 0, struct_offset.inode_superblock - 8) || !nm_load(src[7], 3, 3)
        || inst_get_ldr_imm_rt(src[7]) != 3 || !inst_is_cbz(src[8]) || !inst_get_cbz_sf(src[8])
        || inst_get_cbz_rt(src[8]) != 3 || inst_get_cbz_label(src[8]) <= 12
        || !nm_load_at(src[9], 0, 5, offsetof(struct nm_path, mnt)) || !nm_move(src[10], 1, 4) || !inst_is_blr(src[11])
        || inst_get_blr_rn(src[11]) != 3)
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[7]);
  } else {
    if (!nm_load_at(src[1], 9, 8, offsetof(struct nm_dentry_head, d_inode)) || !inst_is_movz_imm(src[2])
        || inst_get_movz_imm_sf(src[2]) || inst_get_movz_imm_rd(src[2]) != 8 || inst_get_movz_imm_hw(src[2])
        || inst_get_movz_imm_imm16(src[2]) != 0x7ff)
      return -EOPNOTSUPP;
    for (unsigned int i = 3; i <= 10; i++)
      if (!inst_is_stp(src[i]) || bit(src[i], 26) || inst_get_stp_size(src[i]) != 2 || inst_get_stp_mode(src[i]) != 2
          || inst_get_stp_rn(src[i]) != 1 || inst_get_stp_rt(src[i]) != 31 || inst_get_stp_rt2(src[i]) != 31
          || inst_get_stp_imm(src[i]) != 120 - (i - 3) * 16)
        return -EOPNOTSUPP;
    if (!nm_store(src[11], 3, 1) || inst_get_str_imm_rt(src[11]) != 31 || inst_get_str_imm_imm(src[11])
        || !nm_store(src[12], 2, 1) || inst_get_str_imm_rt(src[12]) != 8 || inst_get_str_imm_imm(src[12])
        || !nm_load_at(src[13], 8, 9, struct_offset.inode_superblock - 8) || !nm_load(src[14], 3, 8)
        || inst_get_ldr_imm_rt(src[14]) != 8 || !inst_is_cbz(src[15]) || !inst_get_cbz_sf(src[15])
        || inst_get_cbz_rt(src[15]) != 8 || inst_get_cbz_label(src[15]) <= 52 || !nm_rule_entry_save(src[16])
        || !inst_is_sub_imm(src[17]) || !inst_get_sub_imm_sf(src[17]) || inst_get_sub_imm_rd(src[17]) != 31
        || inst_get_sub_imm_rn(src[17]) != 31 || inst_get_sub_imm_imm(src[17]) != 48 || !nm_rule_entry_save(src[18])
        || !inst_is_add_imm(src[19]) || !inst_get_add_imm_sf(src[19]) || inst_get_add_imm_rd(src[19]) != 29
        || inst_get_add_imm_rn(src[19]) != 31 || inst_get_add_imm_imm(src[19]) != 32 || !nm_cfi_gate(&src[20], 8, 9, 12)
        || !inst_is_and_imm(src[26]) || inst_get_and_imm_sf(src[26]) || inst_get_and_imm_rd(src[26]) != 2
        || inst_get_and_imm_rn(src[26]) != 2 || inst_get_and_imm_imm(src[26]) != 0xfff || !inst_is_and_imm(src[27])
        || inst_get_and_imm_sf(src[27]) || inst_get_and_imm_rd(src[27]) != 3 || inst_get_and_imm_rn(src[27]) != 3
        || inst_get_and_imm_imm(src[27]) != 0x6000 || !inst_is_blr(src[28]) || inst_get_blr_rn(src[28]) != 8)
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[14]);
  }
  int rc = nm_check_simple_getattr(simple, fill, path);
  if (rc)
    return rc;
  if (field < sizeof(struct nm_inode_lookup_ops) || field > 0x7fff || field % 8)
    return -EINVAL;
  struct_offset.iop_getattr = field;
  struct_offset.getattr_callback_args = path ? 4 : 3;
  struct_offset.getattr_function_args = path ? 4 : 2;
  struct_offset.getattr_context_kind = 0;
  struct_offset.fillattr_abi = 2;
  return 0;
}

static int calculate_function_inode_callbacks(void) {
  const uint32_t* drop = (const void*)kallsyms_lookup_name_by_suffix("ext4_drop_inode");
  const uint32_t* attr = (const void*)kallsyms_lookup_name_by_suffix("vfs_getattr_nosec");
  const uint32_t* simple = (const void*)kallsyms_lookup_name_by_suffix("simple_getattr");
  uintptr_t fill = kallsyms_lookup_name_by_suffix("generic_fillattr");
  if (!drop || !attr || !simple || !fill)
    return -ENOENT;
  int hash = nm_find_inode_hash(drop);
  if (hash < 0)
    return hash;
  int rc = nm_find_getattr_layout(attr, simple, fill);
  if (rc)
    return rc;
  struct_offset.inode_hash = hash;
  nm_log_info("layout: inode hash=%d getattr=%d callback/function=%d/%d context=%d\n", hash, struct_offset.iop_getattr,
              struct_offset.getattr_callback_args, struct_offset.getattr_function_args,
              struct_offset.getattr_context_kind);
  return 0;
}

static bool nm_store_at(uint32_t inst, int size, int rt, int rn, int offset) {
  return nm_store(inst, size, rn) && inst_get_str_imm_rt(inst) == rt && inst_get_str_imm_imm(inst) == offset;
}

// 两种完整初始化最多10条，所有写入及RET均匹配；不从最高写入位置猜sizeof。
static int nm_find_mutex_size(const uint32_t* src) {
  if (inst_is_movz_imm(src[0]) && !inst_get_movz_imm_sf(src[0]) && inst_get_movz_imm_rd(src[0]) == 1
      && !inst_get_movz_imm_hw(src[0]) && inst_get_movz_imm_imm16(src[0]) == 1) {
    if (!nm_store_at(src[1], 2, 1, 0, offsetof(struct nm_mutex_count, count)) || !inst_is_add_imm(src[2])
        || !inst_get_add_imm_sf(src[2]) || inst_get_add_imm_rd(src[2]) != 1 || inst_get_add_imm_rn(src[2]) != 0
        || inst_get_add_imm_imm(src[2]) != offsetof(struct nm_mutex_count, wait_next)
        || !nm_store_at(src[3], 1, 31, 0, offsetof(struct nm_mutex_count, wait_lock))
        || !nm_store_at(src[4], 1, 31, 0, offsetof(struct nm_mutex_count, wait_lock) + 2)
        || !nm_store_at(src[5], 3, 1, 0, offsetof(struct nm_mutex_count, wait_next))
        || !nm_store_at(src[6], 3, 1, 1, sizeof(void*))
        || !nm_store_at(src[7], 3, 31, 0, offsetof(struct nm_mutex_count, owner))
        || !nm_store_at(src[8], 2, 31, 0, offsetof(struct nm_mutex_count, osq)) || !inst_is_ret(src[9])
        || inst_get_ret_rn(src[9]) != 30)
      return -EOPNOTSUPP;
    return sizeof(struct nm_mutex_count);
  }
  if (!inst_is_add_imm(src[0]) || !inst_get_add_imm_sf(src[0]) || inst_get_add_imm_rd(src[0]) != 8
      || inst_get_add_imm_rn(src[0]) != 0 || inst_get_add_imm_imm(src[0]) != offsetof(struct nm_mutex_owner, wait_next)
      || !nm_store_at(src[1], 3, 31, 0, offsetof(struct nm_mutex_owner, owner))
      || !nm_store_at(src[2], 2, 31, 0, offsetof(struct nm_mutex_owner, wait_lock))
      || !nm_store_at(src[3], 3, 8, 0, offsetof(struct nm_mutex_owner, wait_next))
      || !nm_store_at(src[4], 3, 8, 0, offsetof(struct nm_mutex_owner, wait_prev))
      || !nm_store_at(src[5], 2, 31, 0, offsetof(struct nm_mutex_owner, osq)) || !inst_is_ret(src[6])
      || inst_get_ret_rn(src[6]) != 30)
    return -EOPNOTSUPP;
  return sizeof(struct nm_mutex_owner);
}

static bool nm_compare(uint32_t inst, int rn, int rm) {
  return inst_is_subs_reg(inst) && inst_get_subs_reg_sf(inst) && inst_get_subs_reg_rd(inst) == 31
         && inst_get_subs_reg_rn(inst) == rn && inst_get_subs_reg_rm(inst) == rm && !inst_get_subs_reg_shift(inst)
         && !inst_get_subs_reg_imm6(inst);
}

// user_preparse 首11条在任何分配前核对datalen范围、data非空和连续布局。
static int nm_find_key_preparse_data(const uint32_t* src) {
  bool saved_prefix = nm_rule_entry_save(src[0]) && nm_rule_entry_save(src[1]) && nm_rule_entry_save(src[2])
                      && nm_rule_entry_save(src[3]);
  int length, input, data_reg;
  if (saved_prefix) {
    if (!nm_load(src[4], 3, 0) || inst_get_ldr_imm_rt(src[4]) != 19 || !inst_is_movn_imm(src[5])
        || !inst_get_movn_imm_sf(src[5]) || inst_get_movn_imm_rd(src[5]) != 8 || inst_get_movn_imm_hw(src[5])
        || inst_get_movn_imm_imm16(src[5]) != 0x7ffe || !inst_is_sub_imm(src[6]) || !inst_get_sub_imm_sf(src[6])
        || inst_get_sub_imm_rd(src[6]) != 9 || inst_get_sub_imm_rn(src[6]) != 19
        || inst_get_sub_imm_imm(src[6]) != 0x8000 || !nm_compare(src[7], 9, 8))
      return -EOPNOTSUPP;
    length = inst_get_ldr_imm_imm(src[4]);
    data_reg = 8;
  } else {
    if (!nm_rule_entry_save(src[0]) || !inst_is_movz_imm(src[1]) || !inst_get_movz_imm_sf(src[1])
        || inst_get_movz_imm_rd(src[1]) != 4 || inst_get_movz_imm_hw(src[1])
        || inst_get_movz_imm_imm16(src[1]) != 0x7ffe || !inst_is_movn_imm(src[2]) || inst_get_movn_imm_sf(src[2])
        || inst_get_movn_imm_rd(src[2]) != 1 || inst_get_movn_imm_hw(src[2]) || inst_get_movn_imm_imm16(src[2]) != 21
        || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4]) || !nm_load(src[5], 3, 0)
        || inst_get_ldr_imm_rt(src[5]) != 2 || !inst_is_sub_imm(src[6]) || !inst_get_sub_imm_sf(src[6])
        || inst_get_sub_imm_rd(src[6]) != 3 || inst_get_sub_imm_rn(src[6]) != 2 || inst_get_sub_imm_imm(src[6]) != 1
        || !nm_compare(src[7], 3, 4))
      return -EOPNOTSUPP;
    length = inst_get_ldr_imm_imm(src[5]);
    data_reg = 3;
  }
  if (!inst_is_b_cond(src[8]) || inst_get_b_cond_cond(src[8]) != (saved_prefix ? 3 : 8)
      || inst_get_b_cond_label(src[8]) <= 8 || !nm_load(src[9], 3, 0) || inst_get_ldr_imm_rt(src[9]) != data_reg
      || !inst_is_cbz(src[10]) || !inst_get_cbz_sf(src[10]) || inst_get_cbz_rt(src[10]) != data_reg
      || inst_get_cbz_label(src[10]) != inst_get_b_cond_label(src[8]) - 8)
    return -EOPNOTSUPP;
  input = inst_get_ldr_imm_imm(src[9]);
  if (input < 0 || input % 8 || input > 4096 - sizeof(struct nm_key_data)
      || length != input + offsetof(struct nm_key_data, datalen))
    return -EINVAL;
  return input;
}

static int calculate_function_mutex_offsets(void) {
  if (struct_offset.mutex_no_lockdep == 1
      && (struct_offset.mutex_size == sizeof(struct nm_mutex_count)
          || struct_offset.mutex_size == sizeof(struct nm_mutex_owner)))
    return 0;
  const uint32_t* mutex = (const void*)kallsyms_lookup_name_by_suffix("__mutex_init");
  if (!mutex)
    return -ENOENT;
  int size = nm_find_mutex_size(mutex);
  if (size < 0)
    return size;
  struct_offset.mutex_size = size;
  struct_offset.mutex_no_lockdep = 1;
  nm_log_info("layout: control mutex=%d/no_dep_map\n", size);
  return 0;
}

static int calculate_function_control_offsets(void) {
  int rc = calculate_function_mutex_offsets();
  if (rc)
    return rc;
  const uint32_t* prep = (const void*)kallsyms_lookup_name_by_suffix("user_preparse");
  if (!prep)
    return -ENOENT;
  int input = nm_find_key_preparse_data(prep);
  if (input < 0)
    return input;
  struct_offset.key_preparse_data = input;
  nm_log_info("layout: control key_input=%d\n", input);
  return 0;
}

static bool nm_page_address(const uint32_t* src, int rd) {
  return inst_is_adrp(src[0]) && inst_get_adrp_rd(src[0]) == rd && inst_is_add_imm(src[1])
         && inst_get_add_imm_sf(src[1]) && inst_get_add_imm_rd(src[1]) == rd && inst_get_add_imm_rn(src[1]) == rd
         && !inst_get_add_imm_sh(src[1]);
}

static bool nm_load_unscaled(uint32_t inst, int rt, int rn, int offset, int mode) {
  return inst_is_ldr_imm9(inst) && !bit(inst, 26) && inst_get_ldr_imm9_opc(inst) == 1
         && inst_get_ldr_imm9_size(inst) == 3 && inst_get_ldr_imm9_rt(inst) == rt && inst_get_ldr_imm9_rn(inst) == rn
         && inst_get_ldr_imm9_imm9(inst) == offset && inst_get_ldr_imm9_mode(inst) == mode;
}

// register_key_type前18／19条：原始type保存在callee-saved寄存器，name@0传给strcmp。
static int nm_check_key_name(const uint32_t* src, uintptr_t compare) {
  // 另一种GCC保存寄存器分配；原始type与链表容器分别保留到strcmp实参。
  if (nm_move(src[7], 21, 0)) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || !inst_is_adrp(src[3]) || inst_get_adrp_rd(src[3]) != 24 || !nm_rule_entry_save(src[4])
        || !inst_is_add_imm(src[5]) || !inst_get_add_imm_sf(src[5]) || inst_get_add_imm_rd(src[5]) != 19
        || inst_get_add_imm_rn(src[5]) != 24 || inst_get_add_imm_sh(src[5]) || !nm_rule_entry_save(src[6])
        || !nm_add_at(src[8], 0, 19, 48) || !nm_add_at(src[9], 23, 19, 96) || !inst_is_bl(src[10])
        || !nm_load_at(src[11], 22, 19, 96) || !inst_is_sub_imm(src[12]) || !inst_get_sub_imm_sf(src[12])
        || inst_get_sub_imm_rd(src[12]) != 20 || inst_get_sub_imm_rn(src[12]) != 22 || inst_get_sub_imm_sh(src[12])
        || inst_get_sub_imm_imm(src[12]) != 112 || !nm_add_at(src[13], 0, 20, 112) || !nm_compare(src[14], 0, 23)
        || !inst_is_b_cond(src[15]) || inst_get_b_cond_cond(src[15]) || inst_get_b_cond_label(src[15]) <= 12
        || !nm_load_at(src[16], 0, 20, offsetof(struct nm_key_type_head, name))
        || !nm_load_at(src[17], 1, 21, offsetof(struct nm_key_type_head, name)) || !inst_is_bl(src[18])
        || (uintptr_t)&src[18] + inst_get_bl_label(src[18]) != compare)
      return -EOPNOTSUPP;
    return 0;
  }
  bool scs = inst_is_str_imm9(src[0]);
  if (scs) {
    for (unsigned int i = 0; i < 5; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move(src[5], 19, 0) || !nm_page_address(&src[6], 0) || !inst_is_bl(src[8]) || !nm_page_address(&src[9], 20)
        || !nm_move(src[11], 21, 20) || !nm_load_at(src[12], 21, 21, 0) || !nm_compare(src[13], 21, 20)
        || !nm_load_unscaled(src[15], 0, 21, -120, 0)
        || !nm_load_at(src[16], 1, 19, offsetof(struct nm_key_type_head, name)))
      return -EOPNOTSUPP;
  } else {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || !inst_is_adrp(src[3]) || inst_get_adrp_rd(src[3]) != 20 || !nm_rule_entry_save(src[4])
        || !inst_is_add_imm(src[5]) || !inst_get_add_imm_sf(src[5]) || inst_get_add_imm_rd(src[5]) != 19
        || inst_get_add_imm_rn(src[5]) != 20 || inst_get_add_imm_sh(src[5]) || !nm_rule_entry_save(src[6])
        || !nm_move(src[7], 22, 0) || !nm_add_at(src[8], 0, 19, 48) || !inst_is_bl(src[9])
        || !nm_load_unscaled(src[10], 23, 19, 88, 3) || !inst_is_sub_imm(src[11]) || !inst_get_sub_imm_sf(src[11])
        || inst_get_sub_imm_rd(src[11]) != 21 || inst_get_sub_imm_rn(src[11]) != 23
        || inst_get_sub_imm_imm(src[11]) != 112 || !nm_add_at(src[12], 0, 21, 112) || !nm_compare(src[13], 19, 0)
        || !nm_load_at(src[15], 0, 21, offsetof(struct nm_key_type_head, name))
        || !nm_load_at(src[16], 1, 22, offsetof(struct nm_key_type_head, name)))
      return -EOPNOTSUPP;
  }
  if (!inst_is_b_cond(src[14]) || inst_get_b_cond_cond(src[14]) || inst_get_b_cond_label(src[14]) <= 12
      || !inst_is_bl(src[17]) || (uintptr_t)&src[17] + inst_get_bl_label(src[17]) != compare)
    return -EOPNOTSUPP;
  return 0;
}

static bool nm_pair_store_at(uint32_t inst, int rt, int rt2, int rn, int offset) {
  return inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_size(inst) == 2 && inst_get_stp_mode(inst) == 2
         && inst_get_stp_rt(inst) == rt && inst_get_stp_rt2(inst) == rt2 && inst_get_stp_rn(inst) == rn
         && inst_get_stp_imm(inst) == offset;
}

static bool nm_max_signed64(uint32_t inst, int rd) {
  return inst_is_movn_imm(inst) && inst_get_movn_imm_sf(inst) && inst_get_movn_imm_rd(inst) == rd
         && inst_get_movn_imm_hw(inst) == 3 && inst_get_movn_imm_imm16(inst) == 0x8000;
}

// key_instantiate_and_link前22／26条：从key->type核对def_datalen及preparse读取。
static int nm_find_key_callback_slot(const uint32_t* src) {
  int slot;
  if (inst_is_str_imm9(src[0])) {
    if (!nm_rule_entry_save(src[0]) || !inst_is_sub_imm(src[1]) || !inst_get_sub_imm_sf(src[1])
        || inst_get_sub_imm_rd(src[1]) != 31 || inst_get_sub_imm_rn(src[1]) != 31 || inst_get_sub_imm_imm(src[1]) != 160
        || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4])
        || !nm_add_at(src[5], 29, 31, 112) || !inst_is_adrp(src[6]) || inst_get_adrp_rd(src[6]) != 8
        || !nm_move(src[7], 19, 0) || !nm_max_signed64(src[8], 10) || !nm_load(src[9], 3, 8)
        || inst_get_ldr_imm_rt(src[9]) != 8 || !nm_move(src[10], 21, 4) || !nm_move(src[11], 20, 3)
        || !nm_move(src[12], 22, 0) || !inst_is_str_imm9(src[13]) || bit(src[13], 26)
        || inst_get_str_imm9_size(src[13]) != 3 || inst_get_str_imm9_rt(src[13]) != 8
        || inst_get_str_imm9_rn(src[13]) != 29 || inst_get_str_imm9_mode(src[13])
        || inst_get_str_imm9_imm9(src[13]) != -8 || !inst_is_ldr_imm9(src[14])
        || !nm_load_unscaled(src[14], 8, 19, inst_get_ldr_imm9_imm9(src[14]), 3) || inst_get_ldr_imm9_imm9(src[14]) <= 0
        || inst_get_ldr_imm9_imm9(src[14]) % 8 || !nm_pair_store_at(src[15], 31, 31, 31, 40)
        || !nm_pair_store_at(src[16], 31, 31, 31, 56) || !nm_pair_store_at(src[17], 1, 2, 31, 72)
        || !nm_load_at(src[18], 9, 8, offsetof(struct nm_key_type_head, def_datalen))
        || !nm_pair_store_at(src[19], 31, 31, 31, 24) || !nm_pair_store_at(src[20], 9, 10, 31, 88)
        || !nm_load(src[21], 3, 8) || inst_get_ldr_imm_rt(src[21]) != 8)
      return -EOPNOTSUPP;
    slot = inst_get_ldr_imm_imm(src[21]);
  } else {
    if (!nm_rule_entry_save(src[0]) || !inst_is_adrp(src[1]) || inst_get_adrp_rd(src[1]) != 5
        || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4])
        || !nm_move(src[5], 21, 0) || !nm_add_at(src[6], 19, 29, 72) || !nm_load(src[7], 3, 5)
        || inst_get_ldr_imm_rt(src[7]) != 0 || !nm_move(src[8], 22, 3) || !nm_store_at(src[9], 3, 0, 29, 152))
      return -EOPNOTSUPP;
    for (unsigned int i = 10; i <= 13; i++)
      if (!nm_pair_store_at(src[i], 31, 31, 19, (i - 10) * 16))
        return -EOPNOTSUPP;
    if (!nm_load(src[14], 3, 21) || inst_get_ldr_imm_rt(src[14]) != 0 || !inst_get_ldr_imm_imm(src[14])
        || !nm_rule_entry_save(src[15]) || !nm_pair_store_at(src[16], 31, 31, 19, 64)
        || !nm_store_at(src[17], 3, 1, 29, 112) || !nm_move(src[18], 24, 4) || !nm_store_at(src[19], 3, 2, 29, 120)
        || !nm_move(src[20], 23, 5) || !nm_load_at(src[21], 1, 0, offsetof(struct nm_key_type_head, def_datalen))
        || !nm_store_at(src[22], 3, 1, 29, 128) || !nm_max_signed64(src[23], 1) || !nm_store_at(src[24], 3, 1, 29, 136)
        || !nm_load(src[25], 3, 0) || inst_get_ldr_imm_rt(src[25]) != 20)
      return -EOPNOTSUPP;
    slot = inst_get_ldr_imm_imm(src[25]);
  }
  if (slot < sizeof(struct nm_key_type_head) || slot + sizeof(struct nm_key_callbacks) > NM_KEY_TYPE_PROBE_SIZE)
    return -EINVAL;
  return slot;
}

static int calculate_function_key_callbacks(void) {
  const uint32_t* reg = (const void*)kallsyms_lookup_name_by_suffix("register_key_type");
  const uint32_t* init = (const void*)kallsyms_lookup_name_by_suffix("key_instantiate_and_link");
  const uintptr_t* table = (const void*)kallsyms_lookup_name_by_suffix("key_type_user");
  uintptr_t compare = kallsyms_lookup_name_by_suffix("strcmp");
  const char* names[] = {"user_preparse", "user_free_preparse", "generic_key_instantiate"};
  uintptr_t targets[3];
  if (!reg || !init || !table || !compare)
    return -ENOENT;
  int rc = nm_check_key_name(reg, compare);
  if (rc)
    return rc;
  int expected = nm_find_key_callback_slot(init);
  if (expected < 0)
    return expected;
  for (unsigned int i = 0; i < 3; i++) {
    targets[i] = kallsyms_lookup_name_by_suffix(names[i]);
    if (!targets[i])
      return -ENOENT;
  }
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  int found = -ENOENT;
  for (unsigned int at = sizeof(struct nm_key_type_head);
       at + sizeof(struct nm_key_callbacks) <= NM_KEY_TYPE_PROBE_SIZE; at += sizeof(void*)) {
    bool match = true;
    for (unsigned int i = 0; i < 3; i++)
      if (!nm_code_matches(table[at / sizeof(void*) + i], targets[i], start, end)) {
        match = false;
        break;
      }
    if (!match)
      continue;
    if (found >= 0)
      return -EINVAL;
    found = at;
  }
  if (found < 0)
    return found;
  if (found != expected)
    return -EINVAL;
  struct_offset.key_callbacks = found;
  nm_log_info("layout: control key_callbacks=%d\n", found);
  return 0;
}

static int nm_check_directory_iteration(const uint32_t* src, int slot) {
  for (unsigned int i = 0; i < 5; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  bool shared = nm_rule_entry_save(src[5]);
  if (shared) {
    if (slot != offsetof(struct nm_file_iteration_ops, iterate_shared) || !inst_is_ldp(src[6]) || bit(src[6], 26)
        || inst_get_ldp_size(src[6]) != 2 || inst_get_ldp_mode(src[6]) != 2 || inst_get_ldp_rn(src[6]) != 0
        || inst_get_ldp_rt(src[6]) != 22 || inst_get_ldp_rt2(src[6]) != 8
        || inst_get_ldp_imm(src[6]) != struct_offset.file_inode_ops || !nm_move(src[7], 19, 0)
        || !nm_move(src[8], 20, 1) || !nm_load_at(src[9], 23, 8, slot) || !inst_is_cbz(src[10])
        || !inst_get_cbz_sf(src[10]) || inst_get_cbz_rt(src[10]) != 23 || inst_get_cbz_label(src[10]) <= 4
        || !nm_move(src[11], 0, 19))
      return -EOPNOTSUPP;
  } else {
    if (slot != offsetof(struct nm_file_iteration_ops, iterate) || !nm_move(src[5], 19, 0) || !inst_is_movn_imm(src[6])
        || inst_get_movn_imm_sf(src[6]) || inst_get_movn_imm_rd(src[6]) != 20 || inst_get_movn_imm_hw(src[6])
        || inst_get_movn_imm_imm16(src[6]) != 19
        || !nm_load_at(src[7], 2, 0, struct_offset.file_inode_ops + offsetof(struct nm_file_inode_ops, f_op))
        || !nm_load_at(src[8], 22, 0, struct_offset.file_inode_ops) || !nm_load_at(src[9], 2, 2, slot)
        || !inst_is_cbz(src[10]) || !inst_get_cbz_sf(src[10]) || inst_get_cbz_rt(src[10]) != 2
        || inst_get_cbz_label(src[10]) <= 4 || !nm_move(src[11], 21, 1))
      return -EOPNOTSUPP;
  }
  struct_offset.fop_iterate = offsetof(struct nm_file_iteration_ops, iterate);
  struct_offset.fop_iterate_shared = shared ? slot : -1;
  return 0;
}

// __dentry_kill前23／17条核对prune槽与实际调用，原生调用须保留x19。
static int nm_find_dentry_lifecycle(const uint32_t* src, uintptr_t dead, uintptr_t start, uintptr_t end) {
  for (unsigned int i = 0; i < 4; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  bool saved = nm_rule_entry_save(src[4]);
  if (saved) {
    if (!nm_load_at(src[5], 8, 0, offsetof(struct nm_dentry_head, d_parent)) || !nm_move(src[6], 19, 0)
        || !nm_compare(src[7], 0, 8) || !nm_add_at(src[8], 0, 0, struct_offset.dentry_lock) || !inst_is_csel(src[9])
        || !inst_get_csel_sf(src[9]) || inst_get_csel_rd(src[9]) != 21 || inst_get_csel_rn(src[9]) != 31
        || inst_get_csel_rm(src[9]) != 8 || inst_get_csel_cond(src[9]) != 0)
      return -EOPNOTSUPP;
  } else {
    if (!nm_add_at(src[4], 21, 0, struct_offset.dentry_lock) || !nm_move(src[5], 19, 0)
        || !nm_load_at(src[6], 20, 0, offsetof(struct nm_dentry_head, d_parent)) || !nm_compare(src[7], 0, 20)
        || !nm_move(src[8], 0, 21) || !inst_is_csel(src[9]) || !inst_get_csel_sf(src[9])
        || inst_get_csel_rd(src[9]) != 20 || inst_get_csel_rn(src[9]) != 20 || inst_get_csel_rm(src[9]) != 31
        || inst_get_csel_cond(src[9]) != 1)
      return -EOPNOTSUPP;
  }
  int flag = saved ? 8 : 0, ops = saved ? 8 : 0, callback = saved ? 20 : 1;
  if (!inst_is_bl(src[10]) || !nm_code_matches((uintptr_t)&src[10] + inst_get_bl_label(src[10]), dead, start, end)
      || !nm_load(src[11], 2, 19) || inst_get_ldr_imm_rt(src[11]) != flag || inst_get_ldr_imm_imm(src[11])
      || !inst_is_tbz(src[12]) || inst_get_tbz_rt(src[12]) != flag || inst_get_tbz_bit(src[12]) != 4
      || inst_get_tbz_label(src[12]) <= (saved ? 40 : 16) || !nm_load_at(src[13], ops, 19, struct_offset.dentry_ops)
      || !nm_load(src[14], 3, ops) || inst_get_ldr_imm_rt(src[14]) != callback)
    return -EOPNOTSUPP;
  if (saved) {
    if (!nm_cfi_gate(&src[15], 20, 8, 8) || !nm_move(src[21], 0, 19) || !inst_is_blr(src[22])
        || inst_get_blr_rn(src[22]) != 20)
      return -EOPNOTSUPP;
  } else if (!nm_move(src[15], 0, 19) || !inst_is_blr(src[16]) || inst_get_blr_rn(src[16]) != 1) {
    return -EOPNOTSUPP;
  }
  int release = inst_get_ldr_imm_imm(src[14]) - (int)offsetof(struct nm_dentry_release_prune, d_prune);
  if (release != sizeof(struct nm_dentry_control_ops) && release != sizeof(struct nm_dentry_control_ops) + 8)
    return -EOPNOTSUPP;
  struct_offset.dop_release = release;
  struct_offset.dop_init = release == sizeof(struct nm_dentry_control_ops) ? -1 : sizeof(struct nm_dentry_control_ops);
  return 0;
}

// empty_dir_readdir仅枚举点项；止于首个actor返回检查，分别30／20条。
static int nm_find_directory_actor(const uint32_t* src) {
  if (struct_offset.file_inode_ops < (int)sizeof(struct nm_path))
    return -EINVAL;
  int dentry = struct_offset.file_inode_ops - (int)offsetof(struct nm_file_path_inode_ops, f_inode)
               + (int)offsetof(struct nm_file_path_inode_ops, f_path.dentry);
  bool saved = nm_rule_entry_save(src[4]);
  for (unsigned int i = 0; i < 4; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  int call;
  if (saved) {
    if (!nm_rule_entry_save(src[5]) || !nm_load_at(src[6], 8, 1, offsetof(struct nm_dir_context, pos))
        || !nm_move(src[7], 19, 1) || !inst_is_subs_imm(src[8]) || !inst_get_subs_imm_sf(src[8])
        || inst_get_subs_imm_rd(src[8]) != 31 || inst_get_subs_imm_rn(src[8]) != 8 || inst_get_subs_imm_imm(src[8]) != 1
        || !inst_is_b_cond(src[9]) || inst_get_b_cond_cond(src[9]) != 0 || inst_get_b_cond_label(src[9]) <= 80
        || !inst_is_cbnz(src[10]) || !inst_get_cbnz_sf(src[10]) || inst_get_cbnz_rt(src[10]) != 8
        || inst_get_cbnz_label(src[10]) <= 76 || !nm_load_at(src[11], 20, 19, offsetof(struct nm_dir_context, actor))
        || !nm_cfi_gate(&src[12], 20, 8, 44) || !nm_zero64(src[18], 3) || !nm_load_at(src[19], 8, 0, dentry)
        || !inst_is_adrp(src[20]) || inst_get_adrp_rd(src[20]) != 1 || !inst_is_add_imm(src[21])
        || !inst_get_add_imm_sf(src[21]) || inst_get_add_imm_rd(src[21]) != 1 || inst_get_add_imm_rn(src[21]) != 1
        || !nm_move(src[22], 21, 0) || !nm_move(src[23], 0, 19) || !inst_is_movz_imm(src[24])
        || inst_get_movz_imm_sf(src[24]) || inst_get_movz_imm_rd(src[24]) != 2 || inst_get_movz_imm_hw(src[24])
        || inst_get_movz_imm_imm16(src[24]) != 1 || !nm_load_at(src[25], 8, 8, offsetof(struct nm_dentry_head, d_inode))
        || !inst_is_movz_imm(src[26]) || inst_get_movz_imm_sf(src[26]) || inst_get_movz_imm_rd(src[26]) != 5
        || inst_get_movz_imm_hw(src[26]) || inst_get_movz_imm_imm16(src[26]) != 4
        || !nm_load_at(src[27], 4, 8, struct_offset.inode_number) || !inst_is_blr(src[28])
        || inst_get_blr_rn(src[28]) != 20)
      return -EOPNOTSUPP;
    call = 28;
  } else {
    if (!nm_move(src[4], 20, 0) || !nm_move(src[5], 19, 1)
        || !nm_load_at(src[6], 0, 1, offsetof(struct nm_dir_context, pos)) || !inst_is_cbnz(src[7])
        || !inst_get_cbnz_sf(src[7]) || inst_get_cbnz_rt(src[7]) != 0 || inst_get_cbnz_label(src[7]) <= 48
        || !nm_load_at(src[8], 0, 20, dentry) || !inst_is_movz_imm(src[9]) || inst_get_movz_imm_sf(src[9])
        || inst_get_movz_imm_rd(src[9]) != 2 || inst_get_movz_imm_hw(src[9]) || inst_get_movz_imm_imm16(src[9]) != 1
        || !nm_load_at(src[10], 6, 1, offsetof(struct nm_dir_context, actor)) || !nm_zero64(src[11], 3)
        || !inst_is_movz_imm(src[12]) || inst_get_movz_imm_sf(src[12]) || inst_get_movz_imm_rd(src[12]) != 5
        || inst_get_movz_imm_hw(src[12]) || inst_get_movz_imm_imm16(src[12]) != 4
        || !nm_load_at(src[13], 4, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[14], 0, 1)
        || !inst_is_adrp(src[15]) || inst_get_adrp_rd(src[15]) != 1 || !inst_is_add_imm(src[16])
        || !inst_get_add_imm_sf(src[16]) || inst_get_add_imm_rd(src[16]) != 1 || inst_get_add_imm_rn(src[16]) != 1
        || !nm_load_at(src[17], 4, 4, struct_offset.inode_number) || !inst_is_blr(src[18])
        || inst_get_blr_rn(src[18]) != 6)
      return -EOPNOTSUPP;
    call = 18;
  }
  uint32_t result = src[call + 1];
  if (!inst_is_cbnz(result) || inst_get_cbnz_sf(result) || inst_get_cbnz_rt(result) != 0
      || inst_get_cbnz_label(result) <= 0)
    return -EOPNOTSUPP;
  return 0;
}

static int calculate_function_directory_callbacks(void) {
  const uint32_t* kill = (const void*)kallsyms_lookup_name_by_suffix("__dentry_kill");
  const uint32_t* actor = (const void*)kallsyms_lookup_name_by_suffix("empty_dir_readdir");
  uintptr_t dead = kallsyms_lookup_name_by_suffix("lockref_mark_dead");
  if (!kill || !actor || !dead)
    return -ENOENT;
  int rc = nm_find_dentry_lifecycle(kill, dead, kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
  if (rc)
    return rc;
  rc = nm_find_directory_actor(actor);
  if (rc)
    return rc;
  struct_offset.dir_actor_abi = 0;
  nm_log_info("layout: directory init/release=%d/%d actor=%d\n", struct_offset.dop_init, struct_offset.dop_release,
              struct_offset.dir_actor_abi);
  return 0;
}

// inode_permission包装层首7条核对NULL mount及inode/mask传递；原生入口读取x1和w2。
static int calculate_function_permission_abi(void) {
  const uint32_t* src = (const void*)kallsyms_lookup_name_by_suffix("inode_permission");
  const uint32_t* native = (const void*)kallsyms_lookup_name_by_suffix("inode_permission2");
  if (!src || !native)
    return -ENOENT;
  bool saved = nm_rule_entry_save(src[1]);
  if (!nm_rule_entry_save(src[0]))
    return -EOPNOTSUPP;
  if (saved) {
    if (!nm_rule_entry_save(src[2]) || !nm_move32(src[3], 2, 1) || !nm_move(src[4], 1, 0) || !nm_zero64(src[5], 0))
      return -EOPNOTSUPP;
    for (unsigned int i = 0; i < 5; i++)
      if (!nm_rule_entry_save(native[i]))
        return -EOPNOTSUPP;
    if (!nm_move32(native[5], 19, 2) || !nm_move(native[6], 20, 1) || !inst_is_tbnz(native[7])
        || inst_get_tbnz_rt(native[7]) != 2 || inst_get_tbnz_bit(native[7]) != 1 || inst_get_tbnz_label(native[7]) <= 0)
      return -EOPNOTSUPP;
  } else {
    if (!nm_move(src[1], 3, 0) || !nm_move32(src[2], 2, 1) || !nm_rule_entry_save(src[3]) || !nm_move(src[4], 1, 3)
        || !nm_zero64(src[5], 0) || !nm_rule_entry_save(native[0]) || !nm_rule_entry_save(native[1])
        || !nm_load_at(native[2], 3, 1, struct_offset.inode_superblock) || !inst_is_tbz(native[3])
        || inst_get_tbz_rt(native[3]) != 2 || inst_get_tbz_bit(native[3]) != 1 || inst_get_tbz_label(native[3]) <= 0)
      return -EOPNOTSUPP;
  }
  if (!inst_is_bl(src[6])
      || !nm_code_matches((uintptr_t)&src[6] + inst_get_bl_label(src[6]), (uintptr_t)native,
                          kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext")))
    return -EOPNOTSUPP;
  struct_offset.permission_abi = 0;
  nm_log_info("layout: permission ABI=%d\n", struct_offset.permission_abi);
  return 0;
}

// generic_shutdown_super固定35／25条前缀；保存的sb／s_op跨原生BL保持在x19／x20。
static int nm_find_super_lifecycle(const uint32_t* src) {
  bool saved = nm_rule_entry_save(src[0]) && inst_is_sub_imm(src[1]);
  unsigned int at;
  if (saved) {
    if (!inst_get_sub_imm_sf(src[1]) || inst_get_sub_imm_rn(src[1]) != 31 || inst_get_sub_imm_rd(src[1]) != 31
        || inst_get_sub_imm_imm(src[1]) != 48 || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3])
        || !nm_add_at(src[4], 29, 31, 16) || !nm_load(src[5], 3, 0) || inst_get_ldr_imm_rt(src[5]) != 8
        || !nm_move(src[6], 19, 0) || !inst_is_cbz(src[7]) || !inst_get_cbz_sf(src[7]) || inst_get_cbz_rt(src[7]) != 8
        || inst_get_cbz_label(src[7]) <= 108 || !nm_load_at(src[8], 20, 19, offsetof(struct nm_super_head, s_op)))
      return -EOPNOTSUPP;
    at = 9;
  } else {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || !nm_move(src[3], 19, 0) || !nm_load(src[4], 3, 0) || inst_get_ldr_imm_rt(src[4]) != 1
        || !nm_load_at(src[5], 20, 0, offsetof(struct nm_super_head, s_op)) || !inst_is_cbz(src[6])
        || !inst_get_cbz_sf(src[6]) || inst_get_cbz_rt(src[6]) != 1 || inst_get_cbz_label(src[6]) <= 72)
      return -EOPNOTSUPP;
    at = 7;
  }
  unsigned int slot_at = saved ? 25 : 21;
  for (; at < slot_at; at++) {
    uint32_t inst = src[at];
    if (nm_move(inst, 0, 19) || inst_is_bl(inst))
      continue;
    if (nm_load(inst, 3, 19) && (inst_get_ldr_imm_rt(inst) == 0 || inst_get_ldr_imm_rt(inst) == 8))
      continue;
    if (inst_is_and_imm(inst) && inst_get_and_imm_sf(inst)
        && (inst_get_and_imm_rd(inst) == 0 || inst_get_and_imm_rd(inst) == 8)
        && inst_get_and_imm_rn(inst) == inst_get_and_imm_rd(inst))
      continue;
    if (nm_store(inst, 3, 19) && (inst_get_str_imm_rt(inst) == 0 || inst_get_str_imm_rt(inst) == 8))
      continue;
    // security对象为空时，恰好跳过一次释放与对应清零；不越过槽读取。
    if (at > 0 && at + 3 <= slot_at && inst_is_cbz(inst) && inst_get_cbz_sf(inst) && inst_get_cbz_rt(inst) == 0
        && inst_get_cbz_label(inst) == 12 && nm_load(src[at - 1], 3, 19) && inst_get_ldr_imm_rt(src[at - 1]) == 0
        && inst_is_bl(src[at + 1]) && nm_store_at(src[at + 2], 3, 31, 19, inst_get_ldr_imm_imm(src[at - 1]))) {
      at += 2;
      continue;
    }
    return -EOPNOTSUPP;
  }
  int callback = saved ? 8 : 1;
  if (!nm_load(src[at], 3, 20) || inst_get_ldr_imm_rt(src[at]) != callback || !inst_is_cbz(src[at + 1])
      || !inst_get_cbz_sf(src[at + 1]) || inst_get_cbz_rt(src[at + 1]) != callback
      || inst_get_cbz_label(src[at + 1]) <= (saved ? 32 : 8))
    return -EOPNOTSUPP;
  if (saved) {
    if (!nm_cfi_gate(&src[27], 8, 9, 8) || !nm_move(src[33], 0, 19) || !inst_is_blr(src[34])
        || inst_get_blr_rn(src[34]) != 8)
      return -EOPNOTSUPP;
  } else if (!nm_move(src[23], 0, 19) || !inst_is_blr(src[24]) || inst_get_blr_rn(src[24]) != 1) {
    return -EOPNOTSUPP;
  }
  int first = inst_get_ldr_imm_imm(src[at]) - (int)offsetof(struct nm_super_lifecycle_ops, put_super);
  if (first < 0 || first % 8 || first > 0x7fff - sizeof(struct nm_super_lifecycle_ops))
    return -EINVAL;
  struct_offset.sop_drop_inode = first + offsetof(struct nm_super_lifecycle_ops, drop_inode);
  struct_offset.sop_evict_inode = first + offsetof(struct nm_super_lifecycle_ops, evict_inode);
  return 0;
}

static int calculate_function_super_callbacks(void) {
  const uint32_t* src = (const void*)kallsyms_lookup_name_by_suffix("generic_shutdown_super");
  if (!src)
    return -ENOENT;
  int rc = nm_find_super_lifecycle(src);
  if (rc)
    return rc;
  nm_log_info("layout: super drop/evict=%d/%d\n", struct_offset.sop_drop_inode, struct_offset.sop_evict_inode);
  return 0;
}

static int calculate_function_directory_offsets(void) {
  int rc = calculate_function_mutex_offsets();
  if (rc)
    return rc;
  const uint32_t* iter = (const void*)kallsyms_lookup_name_by_suffix("iterate_dir");
  const uintptr_t* table = (const void*)kallsyms_lookup_name_by_suffix("simple_dir_operations");
  if (!iter || !table)
    return -ENOENT;
  int slot = nm_find_file_callback(table, struct_offset.file_ops_size, kallsyms_lookup_name_by_suffix("dcache_readdir"),
                                   kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
  if (slot < 0)
    return slot;
  rc = nm_check_directory_iteration(iter, slot);
  if (rc)
    return rc;
  int lock = struct_offset.dentry_ops - (int)offsetof(struct nm_dentry_lockref_ops, d_op);
  if (lock < (int)sizeof(struct nm_dentry_head) || lock % 4)
    return -EINVAL;
  struct_offset.dentry_lock = lock;
  nm_log_info("layout: directory lock=%d iterate/shared=%d/%d\n", lock, struct_offset.fop_iterate,
              struct_offset.fop_iterate_shared);
  return 0;
}

static bool nm_forward_null(uint32_t inst, int reg) {
  return inst_is_cbz(inst) && inst_get_cbz_sf(inst) && inst_get_cbz_rt(inst) == reg && inst_get_cbz_label(inst) > 4;
}

static int nm_sub_from(uint32_t inst, int rd, int rn) {
  if (!inst_is_sub_imm(inst) || !inst_get_sub_imm_sf(inst) || inst_get_sub_imm_rd(inst) != rd
      || inst_get_sub_imm_rn(inst) != rn || inst_get_sub_imm_imm(inst) <= 0 || inst_get_sub_imm_imm(inst) > 0x7fff)
    return -EOPNOTSUPP;
  return inst_get_sub_imm_imm(inst);
}

// set_posix_acl的11／13条前缀：从原始inode取得i_op，再检查set_acl非空。
static int nm_find_set_acl(const uint32_t* src) {
  unsigned int at;
  int base, callback;
  if (nm_move(src[1], 3, 0)) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3])
        || !nm_rule_entry_save(src[4]) || !nm_load_at(src[5], 0, 0, struct_offset.inode_superblock)
        || !nm_load(src[6], 3, 0) || inst_get_ldr_imm_rt(src[6]) != 4 || !inst_is_movn_imm(src[7])
        || inst_get_movn_imm_sf(src[7]) || inst_get_movn_imm_rd(src[7]) != 0 || inst_get_movn_imm_hw(src[7])
        || inst_get_movn_imm_imm16(src[7]) != 94 || !inst_is_tbz(src[8]) || inst_get_tbz_rt(src[8]) != 4
        || inst_get_tbz_bit(src[8]) != 16 || inst_get_tbz_label(src[8]) <= 16
        || !nm_load_at(src[9], 0, 3, struct_offset.inode_superblock - 8) || src[11] != src[7])
      return -EOPNOTSUPP;
    at = 10;
    base = 0;
    callback = 4;
    if (!nm_forward_null(src[12], callback))
      return -EOPNOTSUPP;
  } else {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4])
        || !nm_load_at(src[5], 8, 0, struct_offset.inode_superblock) || !nm_load(src[6], 0, 8)
        || inst_get_ldr_imm_rt(src[6]) != 8 || !inst_is_tbz(src[7]) || inst_get_tbz_rt(src[7]) != 8
        || inst_get_tbz_bit(src[7]) != 0 || inst_get_tbz_label(src[7]) <= 12
        || !nm_load_at(src[8], 8, 0, struct_offset.inode_superblock - 8) || !nm_forward_null(src[10], 8))
      return -EOPNOTSUPP;
    at = 9;
    base = callback = 8;
  }
  if (!nm_load(src[at], 3, base) || inst_get_ldr_imm_rt(src[at]) != callback)
    return -EOPNOTSUPP;
  return inst_get_ldr_imm_imm(src[at]);
}

// super_cache_count首13／17／21条；由shrinker取得sb，再核对s_op及回调链。
// nr_cached_objects和free_cached_objects连续，后者无需扫描较长的super_cache_scan。
static int nm_find_super_cache(const uint32_t* src) {
  // shrinker入口没有flags前置检查的形态，sb来源及s_op/callback链仍完整核对。
  if (nm_move(src[3], 22, 0) && nm_zero64(src[7], 19)) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || nm_sub_from(src[4], 0, 0) < 0 || !nm_rule_entry_save(src[5]) || !nm_move(src[6], 20, 1)
        || !nm_load_at(src[8], 2, 0, offsetof(struct nm_super_head, s_op)) || !nm_forward_null(src[9], 2)
        || !nm_load(src[10], 3, 2) || inst_get_ldr_imm_rt(src[10]) != 2 || !nm_forward_null(src[11], 2)
        || !inst_is_blr(src[12]) || inst_get_blr_rn(src[12]) != 2)
      return -EOPNOTSUPP;
    return inst_get_ldr_imm_imm(src[10]);
  }
  if (nm_rule_entry_save(src[0])) {
    for (unsigned int i = 0; i < 3; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move(src[3], 21, 0) || nm_sub_from(src[4], 0, 0) < 0 || !nm_rule_entry_save(src[5])
        || !nm_move(src[6], 20, 1) || !nm_load(src[7], 3, 0) || inst_get_ldr_imm_rt(src[7]) != 2
        || !inst_is_and_imm(src[8]) || !inst_get_and_imm_sf(src[8]) || inst_get_and_imm_rd(src[8]) != 19
        || inst_get_and_imm_rn(src[8]) != 2 || inst_get_and_imm_imm(src[8]) != 0x20000000 || !inst_is_tbz(src[9])
        || inst_get_tbz_rt(src[9]) != 2 || inst_get_tbz_bit(src[9]) != 29 || inst_get_tbz_label(src[9]) <= 28
        || !inst_is_dmb_ishld(src[10]) || !nm_load_at(src[11], 2, 0, offsetof(struct nm_super_head, s_op))
        || !nm_zero64(src[12], 19) || !nm_forward_null(src[13], 2) || !nm_load(src[14], 3, 2)
        || inst_get_ldr_imm_rt(src[14]) != 2 || !nm_forward_null(src[15], 2) || !inst_is_blr(src[16])
        || inst_get_blr_rn(src[16]) != 2)
      return -EOPNOTSUPP;
    return inst_get_ldr_imm_imm(src[14]);
  }
  int flag = nm_sub_from(src[0], 8, 0);
  int ops = nm_sub_from(src[11], 8, 0);
  int sb = nm_sub_from(src[20], 22, 19);
  if (flag < 0 || ops < 0 || sb < 0 || sb - ops != offsetof(struct nm_super_head, s_op) || !nm_load(src[1], 0, 8)
      || inst_get_ldr_imm_rt(src[1]) != 8 || inst_get_ldr_imm_imm(src[1]) || !inst_is_tbnz(src[2])
      || inst_get_tbnz_rt(src[2]) != 8 || inst_get_tbnz_bit(src[2]) != 5 || inst_get_tbnz_label(src[2]) != 12
      || !nm_zero64(src[3], 0) || !inst_is_ret(src[4]) || inst_get_ret_rn(src[4]) != 30 || !nm_rule_entry_save(src[5])
      || !nm_rule_entry_save(src[6]) || !nm_rule_entry_save(src[7]) || !nm_rule_entry_save(src[8])
      || !nm_rule_entry_save(src[9]) || !inst_is_dmb_ishld(src[10]) || !nm_move(src[12], 19, 0)
      || !nm_load_at(src[13], 8, 8, 0) || !nm_move(src[14], 20, 1) || !nm_forward_null(src[15], 8)
      || !nm_load(src[16], 3, 8) || inst_get_ldr_imm_rt(src[16]) != 21 || !nm_forward_null(src[17], 21)
      || !inst_is_movz_imm(src[18]) || !inst_get_movz_imm_sf(src[18]) || inst_get_movz_imm_rd(src[18]) != 0
      || !nm_move(src[19], 1, 21))
    return -EOPNOTSUPP;
  return inst_get_ldr_imm_imm(src[16]);
}

static int nm_find_dentry_canonical(const uintptr_t* table, uintptr_t callback, uintptr_t start, uintptr_t end) {
  if (!table || !callback)
    return -ENOENT;
  int found = -ENOENT;
  for (unsigned int slot = 0; slot < NM_DENTRY_TAIL_PROBE_SIZE / sizeof(void*); slot++) {
    if (!nm_code_matches(table[slot], callback, start, end))
      continue;
    if (found >= 0)
      return -EINVAL;
    found = slot * sizeof(void*);
  }
  return found;
}

static int nm_tail_extent(int offset, unsigned int span, unsigned int alignment) {
  if (offset < 0 || offset % 8 || !span || span > 4096 || offset > 4096 - span)
    return -EINVAL;
  unsigned int size = ((unsigned int)offset + span + alignment - 1) & ~(alignment - 1);
  return size <= 4096 ? (int)size : -EINVAL;
}

// 同一表内的成员几何匹配已核对的完整声明契约；片段本身不加64字节强制对齐。
// 未使用的厂商追加尾部不会改变这些访存；其支持边界和AUD-001仍需独立审计。
static int nm_set_operation_extents(int acl, int cache, int canonical) {
  if (struct_offset.sop_evict_inode != struct_offset.sop_drop_inode + 8)
    return -EOPNOTSUPP;
  unsigned int inode_span, super_span, dentry_span;
  if (acl - struct_offset.iop_getattr == offsetof(struct nm_inode_acl_tail, set_acl)
      && cache - struct_offset.sop_drop_inode == offsetof(struct nm_super_context_tail, reporting.cache)
      && canonical - struct_offset.dop_release == offsetof(struct nm_dentry_canonical_tail, canonical_path)
      && struct_offset.dop_init == sizeof(struct nm_dentry_control_ops)
      && struct_offset.dop_release == struct_offset.dop_init + sizeof(void*)) {
    inode_span = sizeof(struct nm_inode_acl_tail);
    super_span = sizeof(struct nm_super_context_tail);
    dentry_span = sizeof(struct nm_dentry_canonical_tail);
  } else if (acl - struct_offset.iop_getattr == offsetof(struct nm_inode_xattr_acl_tail, set_acl)
             && cache - struct_offset.sop_drop_inode == offsetof(struct nm_super_mount_tail, reporting.cache)
             && canonical - struct_offset.dop_release == offsetof(struct nm_dentry_select_tail, canonical_path)
             && struct_offset.dop_init == -1 && struct_offset.dop_release == sizeof(struct nm_dentry_control_ops)) {
    inode_span = sizeof(struct nm_inode_xattr_acl_tail);
    super_span = sizeof(struct nm_super_mount_tail);
    dentry_span = sizeof(struct nm_dentry_select_tail);
  } else {
    return -EOPNOTSUPP;
  }
  int inode = nm_tail_extent(struct_offset.iop_getattr, inode_span, 64);
  int super = nm_tail_extent(struct_offset.sop_drop_inode, super_span, 8);
  int dentry = nm_tail_extent(struct_offset.dop_release, dentry_span, 64);
  if (inode < 0 || super < 0 || dentry < 0)
    return -EINVAL;
  struct_offset.inode_ops_size = inode;
  struct_offset.super_ops_size = super;
  struct_offset.dentry_ops_size = dentry;
  return 0;
}

static int calculate_function_operation_sizes(void) {
  const uint32_t* acl = (const void*)kallsyms_lookup_name_by_suffix("set_posix_acl");
  const uint32_t* count = (const void*)kallsyms_lookup_name_by_suffix("super_cache_count");
  const uintptr_t* dops = (const void*)kallsyms_lookup_name_by_suffix("sdcardfs_ci_dops");
  uintptr_t canonical = kallsyms_lookup_name_by_suffix("sdcardfs_canonical_path");
  if (!acl || !count || !dops || !canonical)
    return -ENOENT;
  // 只调用字段探测，不调用要求完整尺寸的公共校验器，避免准备阶段循环依赖。
  int rc = calculate_function_inode_callbacks();
  if (!rc)
    rc = calculate_function_super_callbacks();
  if (!rc)
    rc = calculate_function_directory_offsets();
  if (!rc)
    rc = calculate_function_directory_callbacks();
  if (rc)
    return rc;
  int last_acl = nm_find_set_acl(acl);
  int last_cache = nm_find_super_cache(count);
  int last_canonical =
      nm_find_dentry_canonical(dops, canonical, kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
  if (last_acl < 0 || last_cache < 0 || last_canonical < 0)
    return last_acl < 0 ? last_acl : last_cache < 0 ? last_cache : last_canonical;
  rc = nm_set_operation_extents(last_acl, last_cache, last_canonical);
  if (!rc)
    nm_log_info("layout: operation extents inode/super/dentry=%d/%d/%d\n", struct_offset.inode_ops_size,
                struct_offset.super_ops_size, struct_offset.dentry_ops_size);
  return rc;
}

#endif

static int calculate_offsets(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_offsets(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving object fields from function anchors\n");
    rc = calculate_function_offsets();
    if (rc)
      nm_log_error("layout: object field derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  return validate_offsets();
}

static int nm_prepare_rule_layout(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_rule_prefixes(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving rule hash ABI from function anchor\n");
    rc = calculate_function_rule_layout();
  }
  if (rc)
    return rc;
#endif
  return struct_offset.name_hash_args == 2 || struct_offset.name_hash_args == 3 ? 0 : -EOPNOTSUPP;
}

static int nm_prepare_file_layout(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_file_offsets(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving file fields from function anchors\n");
    rc = calculate_file_entry_offsets();
    if (!rc)
      rc = calculate_file_callback_offsets();
    if (rc)
      nm_log_error("layout: file field derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  struct struct_offset offsets = struct_offset;
  return nm_validate_file_offsets(&offsets);
}

static int nm_prepare_inode_layout(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_inode_offsets(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving inode storage from function anchors\n");
    rc = calculate_function_inode_offsets();
    if (!rc)
      rc = calculate_function_inode_callbacks();
    if (!rc)
      rc = calculate_function_super_callbacks();
    if (rc)
      nm_log_error("layout: inode field derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  struct struct_offset offsets = struct_offset;
  return nm_validate_inode_offsets(&offsets);
}

static int nm_prepare_directory_layout(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_directory_offsets(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving directory object fields from function anchors\n");
    rc = calculate_function_directory_offsets();
    if (!rc)
      rc = calculate_function_directory_callbacks();
    if (rc)
      nm_log_error("layout: directory field derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  struct struct_offset offsets = struct_offset;
  return nm_validate_directory_offsets(&offsets);
}

static int nm_prepare_control_layout(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_control_layout(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving control object fields from function anchors\n");
    rc = calculate_function_control_offsets();
    if (!rc)
      rc = calculate_function_key_callbacks();
    if (rc)
      nm_log_error("layout: control field derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  return nm_validate_control_layout();
}

static int nm_prepare_permission_abi(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_backing_inode_abi(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_log_info("layout: BTF unavailable; deriving inode permission ABI from function anchors\n");
    rc = calculate_function_permission_abi();
    if (rc)
      nm_log_error("layout: permission ABI derivation failed (%d)\n", rc);
  }
  if (rc)
    return rc;
#endif
  return struct_offset.permission_abi >= 0 && struct_offset.permission_abi <= 3 ? 0 : -EOPNOTSUPP;
}

// 两目标声明中的iget5_locked及test/set、unlock_new_inode、set_nlink、llseek原型一致。
// fillattr确有变化，继续要求前段取得的准确ABI；file/path复用已核对的连续片段。
static int nm_prepare_virtual_directory_abi(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_virtual_directory_abi(&unavailable);
  if (rc != -ENODATA || !unavailable)
    return rc;
  if (struct_offset.fillattr_abi != 2 || struct_offset.getattr_context_kind != 0)
    return -EOPNOTSUPP;
  int path = struct_offset.file_inode_ops - (int)offsetof(struct nm_file_path_inode_ops, f_inode);
  if (path < 0 || path % 8)
    return -EINVAL;
  nm_log_info("layout: BTF unavailable; using common virtual-directory native prototypes\n");
#endif
  return 0;
}

// d_hash_and_lookup／shrink_dcache_parent在两目标使用相同的公共原型。
static int nm_prepare_topology_abi(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_topology_abi(&unavailable);
  if (rc != -ENODATA || !unavailable)
    return rc;
  nm_log_info("layout: BTF unavailable; using common topology native prototypes\n");
#endif
  return 0;
}

// vfs_path_lookup的五参声明及实现一致；实际原生绑定仍检查符号存在。
static int nm_prepare_backing_directory_abi(void) {
#ifndef CONFIG_KPM_BASELINES
  bool unavailable;
  int rc = calculate_btf_backing_directory_abi(&unavailable);
  if (rc != -ENODATA || !unavailable)
    return rc;
  nm_log_info("layout: BTF unavailable; using common backing-path native prototype\n");
#endif
  return 0;
}

// kvfree首14条中的内联is_vmalloc_addr；只接受保留x0并分派到原生vfree/kfree的形态。
// 两种偏移模式共用；地址范围来自运行内核，不进入静态结构体偏移表。
static int nm_find_vmalloc_range(const uint32_t* src, uintptr_t vfree, uintptr_t kfree, uintptr_t range[2]) {
  if (!src || !vfree || !kfree)
    return -ENOENT;
  // SCS保存LR，建立栈帧；三条均保持入口地址x0。
  if (src[0] != 0xf800865eU || src[1] != 0xa9bf7bfdU || src[2] != 0x910003fdU)
    return -EOPNOTSUPP;
  uintptr_t bounds[2];
  for (unsigned int i = 0; i < 2; i++) {
    unsigned int at = i ? 7 : 3;
    uint32_t first = src[at], patch = src[at + 1], compare = src[at + 2], branch = src[at + 3];
    uint64_t value;
    if (inst_is_orr_imm(first) && inst_get_orr_imm_sf(first) && inst_get_orr_imm_rn(first) == 31
        && inst_get_orr_imm_rd(first) == 8) {
      unsigned int encoded = (inst_get_orr_imm_n(first) << 6) | (~inst_get_orr_imm_imms(first) & 63);
      if (!encoded)
        return -EOPNOTSUPP;
      unsigned int levels = (1U << (31 - __builtin_clz(encoded))) - 1;
      if ((inst_get_orr_imm_imms(first) & levels) == levels)
        return -EOPNOTSUPP;
      value = inst_get_orr_imm_imm(first);
    } else if (inst_is_movn_imm(first) && inst_get_movn_imm_sf(first) && inst_get_movn_imm_rd(first) == 8)
      value = ~((uint64_t)inst_get_movn_imm_imm16(first) << (16 * inst_get_movn_imm_hw(first)));
    else
      return -EOPNOTSUPP;
    if (!inst_is_movk_imm(patch) || !inst_get_movk_imm_sf(patch) || inst_get_movk_imm_rd(patch) != 8
        || !inst_is_subs_reg(compare) || !inst_get_subs_reg_sf(compare) || inst_get_subs_reg_rd(compare) != 31
        || inst_get_subs_reg_rn(compare) != 0 || inst_get_subs_reg_rm(compare) != 8 || inst_get_subs_reg_shift(compare)
        || inst_get_subs_reg_imm6(compare) || !inst_is_b_cond(branch) || inst_get_b_cond_cond(branch) != (i ? 8 : 3)
        || inst_get_b_cond_label(branch) != (13 - (int)(at + 3)) * 4)
      return -EOPNOTSUPP;
    unsigned int shift = 16 * inst_get_movk_imm_hw(patch);
    bounds[i] = (value & ~(0xffffULL << shift)) | ((uint64_t)inst_get_movk_imm_imm16(patch) << shift);
  }
  if (!inst_is_bl(src[11]) || (uintptr_t)&src[11] + inst_get_bl_label(src[11]) != vfree || !inst_is_b(src[12])
      || inst_get_b_label(src[12]) != 8 || !inst_is_bl(src[13])
      || (uintptr_t)&src[13] + inst_get_bl_label(src[13]) != kfree || bounds[0] > bounds[1]
      || (bounds[0] >> 48) != 0xffff || (bounds[1] >> 48) != 0xffff)
    return -EOPNOTSUPP;
  range[0] = bounds[0];
  range[1] = bounds[1];
  return 0;
}
