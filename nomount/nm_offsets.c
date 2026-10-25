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
#ifndef CONFIG_KPM_BASELINES
  // 动态自建表的容量门控与原表精确复制分开；已知超界不能退回清零容量。
  if ((kind == NM_INODE_OPS || kind == NM_DENTRY_OPS || kind == NM_KEY_TYPE) && size > NM_OWNED_OPERATIONS_CAPACITY)
    return -E2BIG;
#endif
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
#ifndef CONFIG_KPM_BASELINES
  if (key_capacity == -E2BIG)
    return key_capacity;
#endif
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
  unsigned int flags = head->d_flags;
  if (owned)
    flags &= ~(0x1U | 0x2U | 0x8U | 0x10U | 0x04000000U);  // HASH / COMPARE / DELETE / PRUNE / REAL。
  flags |= 0x4U | 0x800U;                                  // REVALIDATE / WEAK_REVALIDATE。
  // 调用者持 d_lock；先发布操作表，再以 release 一次发布使 VFS 调用它的标志。
  __atomic_store_n(&nm_dentry_objects(dentry)->d_op, ops, __ATOMIC_RELEASE);
  __atomic_store_n(&head->d_flags, flags, __ATOMIC_RELEASE);
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
  owner->i_opflags |= 0x0004U;                 // IOP_NOFOLLOW；链接物化在发布前清除此位。
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
    if (slots[i] < 0 || slots[i] < sizeof(struct nm_file_io_ops) || slots[i] % 8
        || slots[i] + 8 > offsets->file_ops_size)
      return -EINVAL;
    for (unsigned int j = 0; j < i; j++)
      if (slots[i] == slots[j])
        return -EINVAL;
  }
  return 0;
}

#ifndef CONFIG_KPM_BASELINES
#include "nm_btf.c"

static enum nm_operation_anchor nm_operation_anchor;

static bool nm_load(uint32_t inst, int size, int rn) {
  return inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1
         && inst_get_ldr_imm_size(inst) == size && inst_get_ldr_imm_rn(inst) == rn && inst_get_ldr_imm_rt(inst) != 31;
}

static bool nm_store(uint32_t inst, int size, int rn) {
  return inst_is_str_imm(inst) && !bit(inst, 26) && inst_get_str_imm_size(inst) == size
         && inst_get_str_imm_rn(inst) == rn;
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
static bool nm_store_at(uint32_t inst, int size, int rt, int rn, int offset) {
  return nm_store(inst, size, rn) && inst_get_str_imm_rt(inst) == rt && inst_get_str_imm_imm(inst) == offset;
}
static bool nm_compare(uint32_t inst, int rn, int rm) {
  return inst_is_subs_reg(inst) && inst_get_subs_reg_sf(inst) && inst_get_subs_reg_rd(inst) == 31
         && inst_get_subs_reg_rn(inst) == rn && inst_get_subs_reg_rm(inst) == rm && !inst_get_subs_reg_shift(inst)
         && !inst_get_subs_reg_imm6(inst);
}
static bool nm_pair_store_at(uint32_t inst, int rt, int rt2, int rn, int offset) {
  return inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_size(inst) == 2 && inst_get_stp_mode(inst) == 2
         && inst_get_stp_rt(inst) == rt && inst_get_stp_rt2(inst) == rt2 && inst_get_stp_rn(inst) == rn
         && inst_get_stp_imm(inst) == offset;
}

// 本阶段锚点均在入口参数被改写或调用前匹配，不跟踪函数后半部。
// full_name_hash 的入口以名字和长度寄存器区分两参／三参，不按内核版本选择。
static int nm_find_name_hash_arguments(const uint32_t* src) {
  if (inst_is_paciasp(src[0]))
    src++;
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
  // 三参hash：GCC先检查长度；Clang先将哈希清零，入口盐值x0保留到后续混合。
  if (inst_is_cbz(src[0]) && !inst_get_cbz_sf(src[0]) && inst_get_cbz_rt(src[0]) == 2 && inst_get_cbz_label(src[0]) > 20
      && inst_is_subs_imm(src[1]) && !inst_get_subs_imm_sf(src[1]) && inst_get_subs_imm_rd(src[1]) == 31
      && inst_get_subs_imm_rn(src[1]) == 2 && inst_get_subs_imm_imm(src[1]) == 7 && nm_load(src[2], 3, 1)
      && inst_get_ldr_imm_rt(src[2]) == 4 && !inst_get_ldr_imm_imm(src[2]) && inst_is_b_cond(src[3])
      && inst_get_b_cond_cond(src[3]) == 9 && inst_get_b_cond_label(src[3]) > 4)
    return 3;
  if (inst_is_mov_reg(src[0]) && inst_get_mov_reg_sf(src[0]) && inst_get_mov_reg_rd(src[0]) == 8
      && inst_get_mov_reg_rm(src[0]) == 31 && inst_is_cbz(src[1]) && !inst_get_cbz_sf(src[1])
      && inst_get_cbz_rt(src[1]) == 2 && inst_get_cbz_label(src[1]) > 16 && inst_is_ubfm(src[2])
      && !inst_get_ubfm_sf(src[2]) && !inst_get_ubfm_n(src[2]) && inst_get_ubfm_rd(src[2]) == 9
      && inst_get_ubfm_rn(src[2]) == 2 && inst_get_ubfm_immr(src[2]) == 29 && inst_get_ubfm_imms(src[2]) == 28) {
    bool padded = src[3] == 0xd503201fU;
    unsigned int load = padded ? 4 : (nm_load(src[3], 3, 1) ? 3 : 4);
    unsigned int sub = padded ? 6 : (load == 3 ? 4 : 3), branch = padded ? 7 : 5;
    if ((!padded || src[5] == 0xd503201fU) && nm_load(src[load], 3, 1) && inst_get_ldr_imm_rt(src[load]) == 10
        && !inst_get_ldr_imm_imm(src[load]) && inst_is_subs_imm(src[sub]) && !inst_get_subs_imm_sf(src[sub])
        && inst_get_subs_imm_rd(src[sub]) == 2 && inst_get_subs_imm_rn(src[sub]) == 2
        && inst_get_subs_imm_imm(src[sub]) == 8 && inst_is_b_cond(src[branch]) && inst_get_b_cond_cond(src[branch]) == 3
        && inst_get_b_cond_label(src[branch]) > 4)
      return 3;
  }
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
  if (inst_is_paciasp(open[0]))
    open++;
  if (inst_is_paciasp(vfs[0]))
    vfs++;
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
  // 两种旧path_open入口；已验证的分支保持dentry及保存的path/file来源。
  if (nm_rule_entry_save(vfs[0]) && nm_rule_entry_save(vfs[2]) && nm_rule_entry_save(vfs[3])) {
    bool clang = nm_rule_entry_save(vfs[1]) && nm_move(vfs[4], 21, 0)
                 && nm_load_at(vfs[5], 0, 0, offsetof(struct nm_path, dentry)) && nm_move(vfs[6], 19, 2)
                 && nm_move(vfs[7], 20, 1);
    bool gcc = nm_move(vfs[1], 3, 2) && nm_move(vfs[4], 19, 1) && nm_move(vfs[5], 20, 0)
               && nm_load_at(vfs[6], 1, 0, offsetof(struct nm_path, dentry));
    if (clang) {
      // 字节标志与错误指针检查发生在path复制之前，不跨其调用。
      if (!nm_load(vfs[8], 0, 0) || inst_get_ldr_imm_rt(vfs[8]) != 8 || inst_get_ldr_imm_imm(vfs[8]) != 3
          || !inst_is_tbnz(vfs[9]) || inst_get_tbnz_rt(vfs[9]) != 8 || inst_get_tbnz_bit(vfs[9]) != 2
          || inst_get_tbnz_label(vfs[9]) <= 4 || !inst_is_adds_imm(vfs[10]) || !inst_get_adds_imm_sf(vfs[10])
          || inst_get_adds_imm_rd(vfs[10]) != 31 || inst_get_adds_imm_rn(vfs[10]) != 0
          || inst_get_adds_imm_imm(vfs[10]) != 4095 || !inst_is_b_cond(vfs[11]) || inst_get_b_cond_cond(vfs[11]) != 2
          || inst_get_b_cond_label(vfs[11]) <= 4 || !inst_is_ldp(vfs[12]) || bit(vfs[12], 26)
          || inst_get_ldp_size(vfs[12]) != 2 || inst_get_ldp_mode(vfs[12]) != 2 || inst_get_ldp_rn(vfs[12]) != 21
          || inst_get_ldp_rt(vfs[12]) != 9 || inst_get_ldp_rt2(vfs[12]) != 8 || inst_get_ldp_imm(vfs[12])
          || !nm_zero64(vfs[13], 2) || !nm_move(vfs[14], 3, 19)
          || !nm_pair_store_at(vfs[15], 9, 8, 20, struct_offset.file_inode_ops - sizeof(struct nm_path))
          || !nm_load_at(vfs[16], 1, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(vfs[17], 0, 20))
        return -EOPNOTSUPP;
      return 0;
    }
    if (gcc) {
      if (!nm_load(vfs[7], 2, 19) || inst_get_ldr_imm_rt(vfs[7]) != 2 || !nm_load(vfs[8], 2, 1)
          || inst_get_ldr_imm_rt(vfs[8]) || inst_get_ldr_imm_imm(vfs[8]) || !inst_is_tbnz(vfs[9])
          || inst_get_tbnz_rt(vfs[9]) || inst_get_tbnz_bit(vfs[9]) != 26 || inst_get_tbnz_label(vfs[9]) <= 4
          || !inst_is_adds_imm(vfs[10]) || !inst_get_adds_imm_sf(vfs[10]) || inst_get_adds_imm_rd(vfs[10]) != 31
          || inst_get_adds_imm_rn(vfs[10]) != 1 || inst_get_adds_imm_imm(vfs[10]) != 4096 || !nm_move32(vfs[11], 0, 1)
          || !inst_is_b_cond(vfs[12]) || inst_get_b_cond_cond(vfs[12]) != 8 || inst_get_b_cond_label(vfs[12]) <= 4
          || !inst_is_ldp(vfs[13]) || bit(vfs[13], 26) || inst_get_ldp_size(vfs[13]) != 2
          || inst_get_ldp_mode(vfs[13]) != 2 || inst_get_ldp_rn(vfs[13]) != 20 || inst_get_ldp_rt(vfs[13]) != 4
          || inst_get_ldp_rt2(vfs[13]) != 5 || inst_get_ldp_imm(vfs[13])
          || !nm_pair_store_at(vfs[14], 4, 5, 19, struct_offset.file_inode_ops - sizeof(struct nm_path))
          || !nm_move(vfs[15], 0, 19) || !nm_zero64(vfs[16], 2)
          || !nm_load_at(vfs[17], 1, 1, offsetof(struct nm_dentry_head, d_inode)))
        return -EOPNOTSUPP;
      return 0;
    }
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

// CFI只跟随核心代码区内一条直接B，可带一条已确认的BTI C前缀。
static bool nm_code_matches(uintptr_t value, uintptr_t target, uintptr_t start, uintptr_t end) {
  if (!target)
    return false;
  if (value == target)
    return true;
  if (!start || end <= start || end - start < 4 || value < start || value > end - 4 || value % 4)
    return false;
  uint32_t inst = *(const uint32_t*)value;
  if (inst_is_bti_c(inst)) {
    if (end - value < 8)
      return false;
    value += 4;
    inst = *(const uint32_t*)value;
  }
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  // BTI入口：cap检查及全局审计开关分支之前，x0始终为原始file。
  if (inst_is_bti_c(src[0])) {
    if (!inst_is_subs_imm(src[1]) || inst_get_subs_imm_sf(src[1]) || inst_get_subs_imm_rd(src[1]) != 31
        || inst_get_subs_imm_rn(src[1]) != 2 || inst_get_subs_imm_imm(src[1]) != 41 || !inst_is_b_cond(src[2])
        || inst_get_b_cond_cond(src[2]) != 2 || inst_get_b_cond_label(src[2]) <= 44 || !inst_is_paciasp(src[3]))
      return -EOPNOTSUPP;
    for (unsigned int i = 4; i <= 9; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!inst_is_adrp(src[10]) || inst_get_adrp_rd(src[10]) != 8 || !nm_load(src[11], 3, 8)
        || inst_get_ldr_imm_rt(src[11]) != 22 || !inst_is_cbz(src[12]) || !inst_get_cbz_sf(src[12])
        || inst_get_cbz_rt(src[12]) != 22 || inst_get_cbz_label(src[12]) <= 4 || !nm_load(src[13], 3, 0)
        || inst_get_ldr_imm_rt(src[13]) != 21)
      return -EOPNOTSUPP;
    return inst_get_ldr_imm_imm(src[13]);
  }
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(seek[0]))
    seek++;
  int ret_at = inst_is_autiasp(seek[1]) ? 2 : 1;
  int position = nm_load(seek[0], 3, 0) && inst_get_ldr_imm_rt(seek[0]) == 0 && inst_is_ret(seek[ret_at])
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
  unsigned int count = nm_load(src[0], 3, 0) && inst_get_ldr_imm_rt(src[0]) == 7 && inst_is_add_imm(src[1]) ? 20 : 18;
  bool first = nm_scalar_copy(src, count, 1, offsetof(struct nm_kstat_inode_first, mode))
                   == offsetof(struct nm_inode_owner_prefix, i_mode)
               && nm_scalar_copy(src, count, 2, offsetof(struct nm_kstat_inode_first, uid))
                      == offsetof(struct nm_inode_owner_prefix, i_uid)
               && nm_scalar_copy(src, count, 2, offsetof(struct nm_kstat_inode_first, gid))
                      == offsetof(struct nm_inode_owner_prefix, i_gid);
  bool mask = nm_scalar_copy(src, count, 1, offsetof(struct nm_kstat_prefix, mode))
                  == offsetof(struct nm_inode_owner_prefix, i_mode)
              && nm_scalar_copy(src, count, 2, offsetof(struct nm_kstat_prefix, uid))
                     == offsetof(struct nm_inode_owner_prefix, i_uid)
              && nm_scalar_copy(src, count, 2, offsetof(struct nm_kstat_prefix, gid))
                     == offsetof(struct nm_inode_owner_prefix, i_gid);
  return first != mask ? first : -EOPNOTSUPP;
}

static int nm_find_file_objects(const uint32_t* src) {
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
  if (nm_load(src[0], 3, 0) && inst_get_ldr_imm_rt(src[0]) == 7 && nm_add_at(src[1], 6, 0, inst_get_add_imm_imm(src[1]))
      && nm_add_at(src[2], 8, 1, offsetof(struct nm_kstat_inode_first_blocks, atime))
      && nm_add_at(src[3], 5, 0, inst_get_add_imm_imm(src[1]) + sizeof(struct nm_timespec))
      && nm_add_at(src[4], 4, 1, offsetof(struct nm_kstat_inode_first_blocks, mtime))
      && nm_add_at(src[5], 3, 0, inst_get_add_imm_imm(src[1]) + 2 * sizeof(struct nm_timespec)) && nm_load(src[6], 2, 7)
      && inst_get_ldr_imm_rt(src[6]) == 7 && inst_get_ldr_imm_imm(src[6]) == offsetof(struct nm_super_head, s_dev)
      && nm_add_at(src[7], 2, 1, offsetof(struct nm_kstat_inode_first_blocks, ctime))
      && nm_store_at(src[8], 2, 7, 1, destination))
    return inst_get_ldr_imm_imm(src[0]);
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  if (inst_is_paciasp(src[0]))
    src++;
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
  int size =
      nm_scalar_copy(attr, nm_load(attr[0], 3, 0) && inst_get_ldr_imm_rt(attr[0]) == 7 ? 23 : 18, 3, size_position);
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

static bool nm_vfs_frame_save(uint32_t inst) {
  if (nm_rule_entry_save(inst))
    return true;
  if (inst_is_paciasp(inst))
    return true;
  if (inst_is_sub_imm(inst) && inst_get_sub_imm_sf(inst) && inst_get_sub_imm_rn(inst) == 31
      && inst_get_sub_imm_rd(inst) == 31 && inst_get_sub_imm_imm(inst) > 0 && inst_get_sub_imm_imm(inst) <= 160
      && inst_get_sub_imm_imm(inst) % 16 == 0)
    return true;
  return inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rn(inst) == 31
         && inst_get_add_imm_rd(inst) == 29 && inst_get_add_imm_imm(inst) <= 160
         && inst_get_add_imm_imm(inst) % 16 == 0;
}

// 新初始化器先将inode保存到x19，或者先写fop再建立mapping；共用声明中i_data紧随fop/flctx。
// 只在已核对的新前缀中使用该连续片段；旧入口仍保留显式mapping交叉检查。
static int nm_probe_saved_inode_storage(const uint32_t* src, uintptr_t no_open,
                                        const struct nm_initial_fops_probe* probe, int* data) {
  uintptr_t addresses[32] = {0};
  bool inode[32] = {0};
  inode[1] = true;
  unsigned int first = inst_is_paciasp(src[0]) ? 1 : 0;
  for (unsigned int i = first; i < first + 20; i++) {
    uint32_t inst = src[i];
    if (nm_rule_entry_save(inst)) {
      if (inst_is_add_imm(inst)) {
        addresses[29] = 0;
        inode[29] = false;
      } else if (inst_is_str_imm9(inst)) {
        addresses[18] = 0;
        inode[18] = false;
      }
      continue;
    }
    if (inst_is_adrp(inst) && inst_get_adrp_rd(inst) != 31 && !inode[inst_get_adrp_rd(inst)]) {
      addresses[inst_get_adrp_rd(inst)] = ((uintptr_t)&src[i] & ~(uintptr_t)4095) + inst_get_adrp_label(inst);
    } else if (inst_is_mov_reg(inst) && inst_get_mov_reg_sf(inst) && inst_get_mov_reg_rd(inst) != 31) {
      int rd = inst_get_mov_reg_rd(inst), rm = inst_get_mov_reg_rm(inst);
      inode[rd] = inode[rm];
      addresses[rd] = addresses[rm];
    } else if (inst_is_add_imm(inst) && inst_get_add_imm_sf(inst) && inst_get_add_imm_rd(inst) != 31
               && !inode[inst_get_add_imm_rd(inst)]) {
      int rd = inst_get_add_imm_rd(inst), rn = inst_get_add_imm_rn(inst);
      addresses[rd] = addresses[rn] ? addresses[rn] + inst_get_add_imm_imm(inst) : 0;
    } else if (inst_is_str_imm(inst) && !bit(inst, 26) && inode[inst_get_str_imm_rn(inst)]) {
      uintptr_t table = addresses[inst_get_str_imm_rt(inst)];
      int offset = inst_get_str_imm_imm(inst);
      if (table && inst_get_str_imm_size(inst) == 3 && offset >= sizeof(struct nm_inode_file_locks)
          && (no_open ? table == no_open : nm_initial_fops_matches(table, probe))) {
        *data = offset + sizeof(struct nm_inode_file_locks);
        return offset;
      }
    } else if (inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1
               && !inode[inst_get_ldr_imm_rt(inst)] && inst_get_ldr_imm_rt(inst) != 31) {
      addresses[inst_get_ldr_imm_rt(inst)] = 0;
    } else if (inst_is_movz_imm(inst) && inst_get_movz_imm_rd(inst) != 31
               && (!inode[inst_get_movz_imm_rd(inst)] || (inst_get_movz_imm_rd(inst) == 1 && inode[19]))) {
      int rd = inst_get_movz_imm_rd(inst);
      inode[rd] = false;
      addresses[rd] = 0;
    } else
      return -EOPNOTSUPP;
  }
  return -ENOENT;
}

// 原生整对象memset的内联形态：验证连续零覆盖和随后的初始化，不把单个最高成员当sizeof。
static int nm_find_mapping_clear_size(const uint32_t* src) {
  int size = nm_find_complete_object_size(src, 8, 0, kallsyms_lookup_name("memset"), 0, 8);
  if (size >= 0 || size == -EINVAL)
    return size;
  if (inst_is_paciasp(src[0])) {
    for (unsigned i = 1; i <= 4; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move(src[5], 19, 0))
      return -EOPNOTSUPP;
    unsigned int covered = 0;
    for (unsigned i = 6; i <= 19; i++) {
      uint32_t inst = src[i];
      if (inst_is_stp(inst) && !bit(inst, 26) && inst_get_stp_size(inst) == 2 && inst_get_stp_mode(inst) == 2
          && inst_get_stp_rn(inst) == 0 && inst_get_stp_rt(inst) == 31 && inst_get_stp_rt2(inst) == 31) {
        int offset = inst_get_stp_imm(inst);
        if (offset < 0 || offset % 8 || offset > 240)
          return -EINVAL;
        covered |= 3U << (offset / 8);
      } else if (nm_store(inst, 3, 0) && inst_get_str_imm_rt(inst) == 31) {
        int offset = inst_get_str_imm_imm(inst);
        if (offset % 8 || offset > 248)
          return -EINVAL;
        covered |= 1U << (offset / 8);
      } else
        return -EOPNOTSUPP;
    }
    // 0..223完整清零，后续首先保存对象，再初始化内部锁地址。
    if (!nm_move(src[20], 20, 0) || !inst_is_movz_imm(src[21]) || inst_get_movz_imm_sf(src[21])
        || inst_get_movz_imm_hw(src[21]) || inst_get_movz_imm_rd(src[21]) != 8
        || inst_get_movz_imm_imm16(src[21]) != 33)
      return -EOPNOTSUPP;
    for (unsigned i = 22; i <= 23; i++) {
      uint32_t inst = src[i];
      if (!inst_is_str_imm9(inst) || bit(inst, 26) || inst_get_str_imm9_size(inst) != 3
          || inst_get_str_imm9_mode(inst) != 3 || inst_get_str_imm9_rt(inst) != 31
          || inst_get_str_imm9_rn(inst) != (i == 22 ? 0 : 20) || inst_get_str_imm9_imm9(inst) != (i == 22 ? 56 : 168))
        return -EOPNOTSUPP;
      covered |= 1U << (i == 22 ? 7 : 21);
    }
    if (covered != 0x0fffffffU || !nm_store_at(src[24], 2, 8, 19, 12) || !nm_store_at(src[25], 3, 31, 19, 16)
        || !inst_is_bl(src[26])
        || (uintptr_t)&src[26] + inst_get_bl_label(src[26]) != kallsyms_lookup_name("__init_rwsem"))
      return -EINVAL;
    return 28 * sizeof(u64);
  }
  // GCC将160字节memset与首个锁常量构造交错；从入口到首次调用完整匹配。
  if (!nm_rule_entry_save(src[0]) || !inst_is_adrp(src[1]) || inst_get_adrp_rd(src[1]) != 2 || !inst_is_adrp(src[2])
      || inst_get_adrp_rd(src[2]) != 1 || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4])
      || !nm_move(src[5], 19, 0) || !nm_pair_store_at(src[6], 31, 31, 0, 0) || !inst_is_movz_imm(src[7])
      || inst_get_movz_imm_sf(src[7]) || inst_get_movz_imm_rd(src[7]) || inst_get_movz_imm_hw(src[7])
      || inst_get_movz_imm_imm16(src[7]) != 32 || !nm_add_at(src[8], 2, 2, inst_get_add_imm_imm(src[8]))
      || !inst_is_movk_imm(src[9]) || inst_get_movk_imm_sf(src[9]) || inst_get_movk_imm_rd(src[9])
      || inst_get_movk_imm_hw(src[9]) != 1 || inst_get_movk_imm_imm16(src[9]) != 0x218
      || !nm_add_at(src[10], 1, 1, inst_get_add_imm_imm(src[10])) || !nm_store_at(src[11], 2, 0, 19, 8)
      || !nm_add_at(src[12], 2, 2, 264) || !nm_add_at(src[13], 0, 19, 40))
    return -EOPNOTSUPP;
  for (unsigned i = 14; i <= 22; i++)
    if (!nm_pair_store_at(src[i], 31, 31, 19, (i - 13) * 16))
      return -EOPNOTSUPP;
  if (!inst_is_bl(src[23]) || (uintptr_t)&src[23] + inst_get_bl_label(src[23]) != kallsyms_lookup_name("__init_rwsem"))
    return -EOPNOTSUPP;
  return 10 * 2 * sizeof(u64);
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
  bool saved_inode = inst_is_paciasp(init[0]) || nm_move(init[3], 19, 1)
                     || (!inst_is_str_imm9(init[0]) && nm_move(init[6], 19, 1))
                     || (inst_is_str_imm9(init[0]) && inst_is_adrp(init[6]) && inst_get_adrp_rd(init[6]) == 10);
  if (no_open) {
    file_ops = saved_inode ? nm_probe_saved_inode_storage(init, no_open, NULL, &data)
                           : nm_find_inode_storage(init, no_open, &data);
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
    file_ops = saved_inode ? nm_probe_saved_inode_storage(init, 0, &probe, &data)
                           : nm_probe_inode_storage(init, 0, &probe, &data);
    if (file_ops >= 0)
      nm_log_info("layout: inode initial file table identified by open callback\n");
  }
  if (file_ops < 0) {
    nm_log_error("layout: inode initializer pattern or geometry rejected (%d)\n", file_ops);
    return file_ops;
  }
  int size = nm_find_mapping_clear_size(clear);
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

static bool nm_cfi_gate(const uint32_t* src, int callback, int scratch, int skip_call) {
  // CFI 区间检查有两种 SUB 操作数次序；输入仍须恰为回调和区间锚点。
  return inst_is_adrp(src[0]) && inst_get_adrp_rd(src[0]) == scratch && inst_is_add_imm(src[1])
         && inst_get_add_imm_sf(src[1]) && inst_get_add_imm_rn(src[1]) == scratch
         && inst_get_add_imm_rd(src[1]) == scratch && inst_is_sub_reg(src[2]) && inst_get_sub_reg_sf(src[2])
         && inst_get_sub_reg_rd(src[2]) == scratch
         && ((inst_get_sub_reg_rn(src[2]) == callback && inst_get_sub_reg_rm(src[2]) == scratch)
             || (inst_get_sub_reg_rn(src[2]) == scratch && inst_get_sub_reg_rm(src[2]) == callback))
         && !inst_get_sub_reg_shift(src[2]) && !inst_get_sub_reg_imm6(src[2]) && inst_is_extr(src[3])
         && inst_get_extr_sf(src[3]) && inst_get_extr_n(src[3]) && inst_get_extr_rd(src[3]) == scratch
         && inst_get_extr_rn(src[3]) == scratch && inst_get_extr_rm(src[3]) == scratch
         && inst_get_extr_imm6(src[3]) == 2 && inst_is_subs_imm(src[4]) && inst_get_subs_imm_sf(src[4])
         && inst_get_subs_imm_rd(src[4]) == 31 && inst_get_subs_imm_rn(src[4]) == scratch
         && inst_get_subs_imm_imm(src[4]) > 0 && inst_is_b_cond(src[5]) && inst_get_b_cond_cond(src[5]) == 2
         && inst_get_b_cond_label(src[5]) > skip_call;
}

// 这里只归一化已证CFI检查的旋转步长；局部副本只做字段关系检查，不解引用PC相对地址。
static bool nm_cfi_gate_stride(const uint32_t* src, int callback, int scratch, int skip_call) {
  if (!inst_is_extr(src[3]) || (inst_get_extr_imm6(src[3]) != 2 && inst_get_extr_imm6(src[3]) != 3))
    return false;
  uint32_t gate[6];
  for (unsigned i = 0; i < 6; i++) gate[i] = src[i];
  gate[3] = (gate[3] & ~(63U << 10)) | (2U << 10);
  return nm_cfi_gate(gate, callback, scratch, skip_call);
}

static bool nm_movz_value(uint32_t inst, int sf, int rd, unsigned value) {
  return inst_is_movz_imm(inst) && inst_get_movz_imm_sf(inst) == sf && inst_get_movz_imm_rd(inst) == rd
         && !inst_get_movz_imm_hw(inst) && inst_get_movz_imm_imm16(inst) == value;
}

// generic_drop_inode 在两个目标均内联；ext4 回调入口先检查 nlink，再检查 hlist.pprev。
static int nm_find_inode_hash(const uint32_t* src) {
  unsigned int i = 0;
  while (i < 8
         && (nm_vfs_frame_save(src[i])
             || (inst_is_movz_imm(src[i]) && !inst_get_movz_imm_sf(src[i])
                 && (inst_get_movz_imm_rd(src[i]) == 21 || inst_get_movz_imm_rd(src[i]) == 20)
                 && !inst_get_movz_imm_hw(src[i]) && inst_get_movz_imm_imm16(src[i]) == 1)))
    i++;
  if (i + 3 >= 12 || !nm_load(src[i], 2, 0) || inst_get_ldr_imm_imm(src[i]) != struct_offset.inode_nlink)
    return -EOPNOTSUPP;
  int nlink = inst_get_ldr_imm_rt(src[i++]), base = 0;
  if (nlink == 0 || nlink == 31)
    return -EOPNOTSUPP;
  if (i < 9 && (nm_move(src[i], 19, 0) || nm_move(src[i], 20, 0))) {
    base = inst_get_mov_reg_rd(src[i]);
    if (nlink == base)
      return -EOPNOTSUPP;
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
static int nm_find_getattr_layout_legacy(const uint32_t* src, const uint32_t* simple, uintptr_t fill) {
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

// 先保留既有窗口及错误语义；新形态分别止于首个实际getattr调用的11/26条。
static int nm_find_getattr_layout_previous(const uint32_t* src, const uint32_t* simple, uintptr_t fill) {
  int old = nm_find_getattr_layout_legacy(src, simple, fill);
  if (!old || old == -EINVAL)
    return old;
  int field = -1;
  bool path = true;
  if (nm_rule_entry_save(src[0]) && nm_rule_entry_save(src[1])
      && nm_load_at(src[2], 4, 0, offsetof(struct nm_path, dentry))) {
    if (!nm_load_at(src[3], 2, 4, offsetof(struct nm_dentry_head, d_inode))
        || !nm_load_at(src[4], 3, 2, struct_offset.inode_superblock - 8) || !nm_load(src[5], 3, 3)
        || inst_get_ldr_imm_rt(src[5]) != 3 || !inst_is_cbz(src[6]) || !inst_get_cbz_sf(src[6])
        || inst_get_cbz_rt(src[6]) != 3 || inst_get_cbz_label(src[6]) <= 16
        || !nm_load_at(src[7], 0, 0, offsetof(struct nm_path, mnt)) || !nm_move(src[8], 2, 1) || !nm_move(src[9], 1, 4)
        || !inst_is_blr(src[10]) || inst_get_blr_rn(src[10]) != 3)
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[5]);
    path = false;
  } else if (!inst_is_str_imm9(src[0]) && !inst_is_paciasp(src[0])) {
    for (unsigned i = 0; i < 5; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_load_at(src[5], 8, 0, offsetof(struct nm_path, dentry)) || !nm_move32(src[6], 21, 2)
        || !nm_move(src[7], 20, 0) || !nm_move(src[8], 19, 1) || !inst_is_movz_imm(src[9])
        || inst_get_movz_imm_sf(src[9]) || inst_get_movz_imm_rd(src[9]) != 2 || inst_get_movz_imm_hw(src[9])
        || inst_get_movz_imm_imm16(src[9]) != sizeof(struct nm_kstat_blocks) || !nm_move(src[10], 0, 1)
        || !nm_move32(src[11], 1, 31) || !nm_move32(src[12], 22, 3)
        || !nm_load_at(src[13], 23, 8, offsetof(struct nm_dentry_head, d_inode)) || !inst_is_bl(src[14])
        || (uintptr_t)&src[14] + inst_get_bl_label(src[14]) != kallsyms_lookup_name_by_suffix("memset")
        || !nm_load(src[15], 2, 19) || inst_get_ldr_imm_rt(src[15]) != 8 || inst_get_ldr_imm_imm(src[15])
        || !inst_is_orr_imm(src[16]) || inst_get_orr_imm_sf(src[16]) || inst_get_orr_imm_rd(src[16]) != 8
        || inst_get_orr_imm_rn(src[16]) != 8 || inst_get_orr_imm_imm(src[16]) != 0x7ff
        || !nm_store_at(src[17], 2, 8, 19, 0) || !nm_load(src[18], 3, 23)
        || inst_get_ldr_imm_imm(src[18]) != struct_offset.inode_superblock - 8)
      return -EOPNOTSUPP;
    int cb = inst_get_ldr_imm_rt(src[18]);
    if ((cb != 8 && cb != 9) || !nm_load(src[19], 3, cb) || inst_get_ldr_imm_rt(src[19]) != cb || !inst_is_cbz(src[20])
        || !inst_get_cbz_sf(src[20]) || inst_get_cbz_rt(src[20]) != cb || inst_get_cbz_label(src[20]) <= 20
        || !inst_is_and_imm(src[21]) || inst_get_and_imm_sf(src[21]) || inst_get_and_imm_rd(src[21]) != 3
        || inst_get_and_imm_rn(src[21]) != 22 || inst_get_and_imm_imm(src[21]) != 0x6000 || !inst_is_and_imm(src[22])
        || inst_get_and_imm_sf(src[22]) || inst_get_and_imm_rd(src[22]) != 2 || inst_get_and_imm_rn(src[22]) != 21
        || inst_get_and_imm_imm(src[22]) != 0xfff || !nm_move(src[23], 0, 20) || !nm_move(src[24], 1, 19)
        || !inst_is_blr(src[25]) || inst_get_blr_rn(src[25]) != cb)
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[19]);
  } else
    return -EOPNOTSUPP;
  int rc = nm_check_simple_getattr(simple, fill, path);
  if (rc)
    return rc;
  if (field < sizeof(struct nm_inode_lookup_ops) || field % 8 || field > 0x7fff)
    return -EINVAL;
  struct_offset.iop_getattr = field;
  struct_offset.getattr_callback_args = path ? 4 : 3;
  struct_offset.getattr_function_args = path ? 4 : 2;
  struct_offset.getattr_context_kind = 0;
  struct_offset.fillattr_abi = 2;
  return 0;
}

// 内联simple_getattr前11条确认path→inode和stat实参；generic_fillattr本身另证两参字段复制。
static int nm_check_inline_simple_getattr(const uint32_t* src, const uint32_t* fill) {
  if (!inst_is_paciasp(src[0]) || !nm_load_at(src[1], 8, 0, offsetof(struct nm_path, dentry))
      || !nm_move32(src[2], 0, 31) || !nm_load_at(src[3], 8, 8, offsetof(struct nm_dentry_head, d_inode))
      || !nm_load_at(src[4], 9, 8, struct_offset.inode_superblock) || !nm_load(src[5], 2, 9)
      || inst_get_ldr_imm_rt(src[5]) != 9 || inst_get_ldr_imm_imm(src[5]) != offsetof(struct nm_super_head, s_dev)
      || !nm_store_at(src[6], 2, 9, 1, offsetof(struct nm_kstat_prefix, dev))
      || !nm_load_at(src[7], 9, 8, struct_offset.inode_number)
      || !nm_store_at(src[8], 3, 9, 1, offsetof(struct nm_kstat_prefix, ino)) || !nm_load(src[9], 1, 8)
      || inst_get_ldr_imm_rt(src[9]) != 9 || inst_get_ldr_imm_imm(src[9])
      || !nm_store_at(src[10], 1, 9, 1, offsetof(struct nm_kstat_prefix, mode)) || nm_find_kstat_prefix(fill) != 0)
    return -EOPNOTSUPP;
  return 0;
}

// 两个CFI入口的属性处理分别整体核对；不以“任意未写x0”跳过未知指令。
static int nm_find_getattr_layout(const uint32_t* src, const uint32_t* simple, uintptr_t fill) {
  int old = nm_find_getattr_layout_previous(src, simple, fill);
  if (!old || old == -EINVAL)
    return old;
  bool pac = inst_is_paciasp(src[0]);
  int field;
  uint32_t gate[6];
  if (pac) {
    src++;
    for (unsigned i = 0; i < 4; i++)
      if (!nm_vfs_frame_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_load_at(src[4], 8, 0, offsetof(struct nm_path, dentry)) || !nm_movz_value(src[5], 0, 10, 0x7ff)
        || !nm_load_at(src[6], 9, 8, offsetof(struct nm_dentry_head, d_inode)))
      return -EOPNOTSUPP;
    for (unsigned i = 7; i <= 15; i++)
      if (!nm_pair_store_at(src[i], 31, 31, 1, 128 - (i - 7) * 16))
        return -EOPNOTSUPP;
    if (!nm_store_at(src[16], 2, 10, 1, 0) || !nm_load_at(src[17], 8, 9, struct_offset.inode_superblock)
        || !nm_load_at(src[18], 8, 8, offsetof(struct nm_super_head, s_flags)) || !inst_is_tst_imm(src[19])
        || !inst_get_tst_imm_sf(src[19]) || inst_get_tst_imm_rn(src[19]) != 8 || inst_get_tst_imm_imm(src[19]) != 0x400
        || !nm_movz_value(src[20], 0, 8, 0x7df) || !inst_is_csel(src[21]) || inst_get_csel_sf(src[21])
        || inst_get_csel_rd(src[21]) != 8 || inst_get_csel_rn(src[21]) != 10 || inst_get_csel_rm(src[21]) != 8
        || inst_get_csel_cond(src[21]) || !nm_store_at(src[22], 2, 8, 1, 0) || !nm_load(src[23], 0, 9)
        || inst_get_ldr_imm_rt(src[23]) != 8
        || inst_get_ldr_imm_imm(src[23]) != offsetof(struct nm_inode_owner_prefix, i_flags) + 1 || !inst_is_tbz(src[24])
        || inst_get_tbz_rt(src[24]) != 8 || inst_get_tbz_bit(src[24]) != 3 || inst_get_tbz_label(src[24]) != 12
        || !nm_movz_value(src[25], 0, 8, 0x1000) || !nm_store_at(src[26], 3, 8, 1, 16)
        || !nm_movz_value(src[27], 0, 8, 0x1000) || !inst_is_movk_imm(src[28]) || inst_get_movk_imm_sf(src[28])
        || inst_get_movk_imm_rd(src[28]) != 8 || inst_get_movk_imm_hw(src[28]) != 1
        || inst_get_movk_imm_imm16(src[28]) != 32 || !nm_store_at(src[29], 3, 8, 1, 24)
        || !nm_load_at(src[30], 8, 9, struct_offset.inode_superblock - 8) || !nm_load(src[31], 3, 8)
        || inst_get_ldr_imm_rt(src[31]) != 8 || !inst_is_cbz(src[32]) || !inst_get_cbz_sf(src[32])
        || inst_get_cbz_rt(src[32]) != 8 || inst_get_cbz_label(src[32]) <= 32 || !inst_is_and_imm(src[38])
        || inst_get_and_imm_sf(src[38]) || inst_get_and_imm_rd(src[38]) != 3 || inst_get_and_imm_rn(src[38]) != 3
        || inst_get_and_imm_imm(src[38]) != 0x6000 || !inst_is_blr(src[40]) || inst_get_blr_rn(src[40]) != 8)
      return -EOPNOTSUPP;
    for (unsigned i = 0; i < 5; i++) gate[i] = src[33 + i];
    gate[5] = src[39];
    if (!nm_cfi_gate_stride(gate, 8, 9, 4) || nm_check_inline_simple_getattr(simple, (const void*)fill))
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[31]);
  } else {
    for (unsigned i = 0; i < 6; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_load_at(src[6], 8, 0, offsetof(struct nm_path, dentry)) || !nm_move32(src[7], 22, 2)
        || !nm_move(src[8], 20, 0) || !nm_move(src[9], 19, 1)
        || !nm_load_at(src[10], 23, 8, offsetof(struct nm_dentry_head, d_inode))
        || !nm_movz_value(src[11], 0, 2, sizeof(struct nm_kstat_blocks)) || !nm_move(src[12], 0, 1)
        || !nm_move32(src[13], 1, 31) || !nm_move32(src[14], 21, 3) || !inst_is_bl(src[15])
        || (uintptr_t)&src[15] + inst_get_bl_label(src[15]) != kallsyms_lookup_name_by_suffix("memset")
        || !nm_load(src[16], 2, 19) || inst_get_ldr_imm_rt(src[16]) != 8 || inst_get_ldr_imm_imm(src[16])
        || !nm_movz_value(src[17], 0, 10, 0x401) || !inst_is_orr_imm(src[18]) || inst_get_orr_imm_sf(src[18])
        || inst_get_orr_imm_rd(src[18]) != 8 || inst_get_orr_imm_rn(src[18]) != 8
        || inst_get_orr_imm_imm(src[18]) != 0x7ff || !nm_store_at(src[19], 2, 8, 19, 0)
        || !nm_load_at(src[20], 9, 23, struct_offset.inode_superblock) || !nm_load(src[21], 1, 9)
        || inst_get_ldr_imm_rt(src[21]) != 9 || inst_get_ldr_imm_imm(src[21]) != offsetof(struct nm_super_head, s_flags)
        || !inst_is_ands_reg(src[22]) || inst_get_ands_reg_sf(src[22]) || inst_get_ands_reg_rd(src[22]) != 31
        || inst_get_ands_reg_rn(src[22]) != 9 || inst_get_ands_reg_rm(src[22]) != 10 || inst_get_ands_reg_shift(src[22])
        || inst_get_ands_reg_imm6(src[22]) || !inst_is_b_cond(src[23]) || inst_get_b_cond_cond(src[23])
        || inst_get_b_cond_label(src[23]) != 12 || !inst_is_and_imm(src[24]) || inst_get_and_imm_sf(src[24])
        || inst_get_and_imm_rd(src[24]) != 8 || inst_get_and_imm_rn(src[24]) != 8
        || inst_get_and_imm_imm(src[24]) != 0xffffffdf || !nm_store_at(src[25], 2, 8, 19, 0) || !nm_load(src[26], 0, 23)
        || inst_get_ldr_imm_rt(src[26]) != 8
        || inst_get_ldr_imm_imm(src[26]) != offsetof(struct nm_inode_owner_prefix, i_flags) + 1 || !inst_is_tbz(src[27])
        || inst_get_tbz_rt(src[27]) != 8 || inst_get_tbz_bit(src[27]) != 3 || inst_get_tbz_label(src[27]) != 16
        || !nm_load_at(src[28], 8, 19, 16) || !inst_is_orr_imm(src[29]) || !inst_get_orr_imm_sf(src[29])
        || inst_get_orr_imm_rd(src[29]) != 8 || inst_get_orr_imm_rn(src[29]) != 8
        || inst_get_orr_imm_imm(src[29]) != 0x1000 || !nm_store_at(src[30], 3, 8, 19, 16)
        || !nm_load_at(src[31], 8, 23, struct_offset.inode_superblock - 8) || !nm_load(src[32], 3, 8)
        || inst_get_ldr_imm_rt(src[32]) != 8 || !inst_is_cbz(src[33]) || !inst_get_cbz_sf(src[33])
        || inst_get_cbz_rt(src[33]) != 8 || inst_get_cbz_label(src[33]) <= 52 || !inst_is_and_imm(src[38])
        || inst_get_and_imm_sf(src[38]) || inst_get_and_imm_rd(src[38]) != 22 || inst_get_and_imm_rn(src[38]) != 22
        || inst_get_and_imm_imm(src[38]) != 0xfff || !inst_is_and_imm(src[40]) || inst_get_and_imm_sf(src[40])
        || inst_get_and_imm_rd(src[40]) != 21 || inst_get_and_imm_rn(src[40]) != 21
        || inst_get_and_imm_imm(src[40]) != 0x6000 || !nm_move(src[42], 0, 20) || !nm_move(src[43], 1, 19)
        || !nm_move32(src[44], 2, 22) || !nm_move32(src[45], 3, 21) || !inst_is_blr(src[46])
        || inst_get_blr_rn(src[46]) != 8)
      return -EOPNOTSUPP;
    for (unsigned i = 0; i < 4; i++) gate[i] = src[34 + i];
    gate[4] = src[39];
    gate[5] = src[41];
    if (!nm_cfi_gate_stride(gate, 8, 9, 20) || nm_check_simple_getattr(simple, fill, true))
      return -EOPNOTSUPP;
    field = inst_get_ldr_imm_imm(src[32]);
  }
  if (field < sizeof(struct nm_inode_lookup_ops) || field % 8 || field > 0x7fff)
    return -EINVAL;
  struct_offset.iop_getattr = field;
  struct_offset.getattr_callback_args = 4;
  struct_offset.getattr_function_args = 4;
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

// 已核对完整初始化最多10条，所有写入及RET均匹配；不从最高写入位置猜sizeof。
static int nm_find_mutex_size(const uint32_t* src) {
  if (inst_is_paciasp(src[0])) {
    if (!nm_add_at(src[1], 8, 0, offsetof(struct nm_mutex_owner, wait_next))
        || !nm_store_at(src[2], 3, 31, 0, offsetof(struct nm_mutex_owner, owner))
        || !nm_store_at(src[3], 2, 31, 0, offsetof(struct nm_mutex_owner, wait_lock))
        || !nm_store_at(src[4], 3, 8, 0, offsetof(struct nm_mutex_owner, wait_next)) || !inst_is_stp(src[5])
        || bit(src[5], 26) || inst_get_stp_size(src[5]) != 2 || inst_get_stp_mode(src[5]) != 2
        || inst_get_stp_rt(src[5]) != 8 || inst_get_stp_rt2(src[5]) != 31 || inst_get_stp_rn(src[5]) != 0
        || inst_get_stp_imm(src[5]) != offsetof(struct nm_mutex_owner, wait_prev)
        || !nm_store_at(src[6], 2, 31, 0, offsetof(struct nm_mutex_owner, osq))
        || !nm_store_at(src[7], 3, 31, 0, offsetof(struct nm_mutex_owner_oem, oem[1])) || !inst_is_autiasp(src[8])
        || !inst_is_ret(src[9]) || inst_get_ret_rn(src[9]) != 30)
      return -EOPNOTSUPP;
    return sizeof(struct nm_mutex_owner_oem);
  }
  // GCC将同一完整count型初始化重排；全部字段与RET仍须匹配。
  if (nm_add_at(src[0], 1, 0, offsetof(struct nm_mutex_count, wait_next))) {
    if (!inst_is_movz_imm(src[1]) || inst_get_movz_imm_sf(src[1]) || inst_get_movz_imm_rd(src[1]) != 2
        || inst_get_movz_imm_hw(src[1]) || inst_get_movz_imm_imm16(src[1]) != 1
        || !nm_store_at(src[2], 2, 2, 0, offsetof(struct nm_mutex_count, count))
        || !nm_store_at(src[3], 3, 1, 0, offsetof(struct nm_mutex_count, wait_next))
        || !nm_store_at(src[4], 1, 31, 0, offsetof(struct nm_mutex_count, wait_lock))
        || !nm_store_at(src[5], 1, 31, 0, offsetof(struct nm_mutex_count, wait_lock) + 2)
        || !nm_store_at(src[6], 3, 1, 1, sizeof(void*))
        || !nm_store_at(src[7], 3, 31, 0, offsetof(struct nm_mutex_count, owner))
        || !nm_store_at(src[8], 2, 31, 0, offsetof(struct nm_mutex_count, osq)) || !inst_is_ret(src[9])
        || inst_get_ret_rn(src[9]) != 30)
      return -EOPNOTSUPP;
    return sizeof(struct nm_mutex_count);
  }
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

// user_preparse 首11条在任何分配前核对datalen范围、data非空和连续布局。
static int nm_find_key_preparse_data_legacy(const uint32_t* src) {
  bool saved_prefix = nm_rule_entry_save(src[0]) && nm_rule_entry_save(src[1]) && nm_rule_entry_save(src[2])
                      && nm_rule_entry_save(src[3]);
  int length, input, data_reg;
  // SUB/CMN 实现 0 < datalen < 32768；分支和 NULL data 共用错误出口，窗口止于第10条。
  if (saved_prefix && inst_is_sub_imm(src[5])) {
    if (!nm_load(src[4], 3, 0) || inst_get_ldr_imm_rt(src[4]) != 19 || !inst_get_sub_imm_sf(src[5])
        || inst_get_sub_imm_rd(src[5]) != 8 || inst_get_sub_imm_rn(src[5]) != 19
        || inst_get_sub_imm_imm(src[5]) != 0x8000 || !inst_is_adds_imm(src[6]) || !inst_get_adds_imm_sf(src[6])
        || inst_get_adds_imm_rd(src[6]) != 31 || inst_get_adds_imm_rn(src[6]) != 8
        || inst_get_adds_imm_imm(src[6]) != 0x8000 || !inst_is_b_cond(src[7]) || inst_get_b_cond_cond(src[7]) != 9
        || inst_get_b_cond_label(src[7]) <= 8 || !nm_load(src[8], 3, 0) || inst_get_ldr_imm_rt(src[8]) != 8
        || !inst_is_cbz(src[9]) || !inst_get_cbz_sf(src[9]) || inst_get_cbz_rt(src[9]) != 8
        || inst_get_cbz_label(src[9]) != inst_get_b_cond_label(src[7]) - 8)
      return -EOPNOTSUPP;
    length = inst_get_ldr_imm_imm(src[4]);
    input = inst_get_ldr_imm_imm(src[8]);
    if (input < 0 || input % 8 || input > 4096 - sizeof(struct nm_key_data)
        || length != input + offsetof(struct nm_key_data, datalen))
      return -EINVAL;
    return input;
  }
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

static int nm_find_key_preparse_data(const uint32_t* src) {
  int old = nm_find_key_preparse_data_legacy(src);
  if (old >= 0 || old == -EINVAL)
    return old;
  if (inst_is_paciasp(src[0]))
    src++;
  unsigned int length_at, limit_at, sub_at, cmp_at, branch_at, data_at, null_at;
  int length_reg, limit_reg, difference, data_reg;
  bool scs = inst_is_str_imm9(src[0]);
  bool gcc = inst_is_movz_imm(src[1]) && inst_get_movz_imm_sf(src[1]);
  if (scs) {
    if (!inst_is_movz_imm(src[5]))
      return -EOPNOTSUPP;
    for (unsigned int i = 0; i < 4; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    length_at = 4;
    limit_at = 5;
    sub_at = 6;
    cmp_at = 7;
    branch_at = 8;
    data_at = 9;
    null_at = 11;
    length_reg = 19;
    limit_reg = 9;
    difference = 8;
    data_reg = 8;
    if (!nm_move(src[10], 20, 0))
      return -EOPNOTSUPP;
  } else if (gcc) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3]))
      return -EOPNOTSUPP;
    length_at = 4;
    limit_at = 1;
    sub_at = 5;
    cmp_at = 6;
    branch_at = 7;
    data_at = 8;
    null_at = 9;
    length_reg = 20;
    limit_reg = 1;
    difference = 2;
    data_reg = 1;
  } else {
    for (unsigned int i = 0; i < 3; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    length_at = 3;
    limit_at = 4;
    sub_at = 5;
    cmp_at = 6;
    branch_at = 7;
    data_at = 8;
    null_at = 10;
    length_reg = 19;
    limit_reg = 8;
    difference = 9;
    data_reg = 8;
    if (!nm_move(src[9], 20, 0))
      return -EOPNOTSUPP;
  }
  if (!nm_load(src[length_at], 3, 0) || inst_get_ldr_imm_rt(src[length_at]) != length_reg
      || !inst_is_movz_imm(src[limit_at]) || inst_get_movz_imm_sf(src[limit_at]) != gcc
      || inst_get_movz_imm_rd(src[limit_at]) != limit_reg || inst_get_movz_imm_hw(src[limit_at])
      || inst_get_movz_imm_imm16(src[limit_at]) != 0x7ffe || !inst_is_sub_imm(src[sub_at])
      || !inst_get_sub_imm_sf(src[sub_at]) || inst_get_sub_imm_rd(src[sub_at]) != difference
      || inst_get_sub_imm_rn(src[sub_at]) != length_reg || inst_get_sub_imm_imm(src[sub_at]) != 1
      || !nm_compare(src[cmp_at], difference, limit_reg) || !inst_is_b_cond(src[branch_at])
      || inst_get_b_cond_cond(src[branch_at]) != 8 || inst_get_b_cond_label(src[branch_at]) <= 8
      || !nm_load(src[data_at], 3, 0) || inst_get_ldr_imm_rt(src[data_at]) != data_reg || !inst_is_cbz(src[null_at])
      || !inst_get_cbz_sf(src[null_at]) || inst_get_cbz_rt(src[null_at]) != data_reg
      || inst_get_cbz_label(src[null_at]) != inst_get_b_cond_label(src[branch_at]) - (int)(null_at - branch_at) * 4)
    return -EOPNOTSUPP;
  int input = inst_get_ldr_imm_imm(src[data_at]);
  return input >= 0 && input % 8 == 0 && input <= 4096 - sizeof(struct nm_key_data)
                 && inst_get_ldr_imm_imm(src[length_at]) == input + offsetof(struct nm_key_data, datalen)
             ? input
             : -EINVAL;
}

static int calculate_function_mutex_offsets(void) {
  if (struct_offset.mutex_no_lockdep == 1
      && (struct_offset.mutex_size == sizeof(struct nm_mutex_count)
          || struct_offset.mutex_size == sizeof(struct nm_mutex_owner)
          || struct_offset.mutex_size == sizeof(struct nm_mutex_owner_oem)))
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
static int nm_check_key_name_legacy(const uint32_t* src, uintptr_t compare) {
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

// 返回注册遍历中的link起点，并标出首次锁调用、可见的class清零调用及其对象内起点。
// 旧入口仍执行原判据；新入口分别限23/21条，不把未知指令当作无关prologue。
static int nm_find_key_registration(const uint32_t* src, uintptr_t compare, int* lock_call, int* class_call,
                                    int* class_offset) {
  *class_call = *class_offset = -1;
  if (!nm_check_key_name_legacy(src, compare)) {
    if (nm_move(src[7], 21, 0)) {
      *lock_call = 10;
      return inst_get_sub_imm_imm(src[12]);
    }
    if (inst_is_str_imm9(src[0])) {
      *lock_call = 8;
      return -inst_get_ldr_imm9_imm9(src[15]);
    }
    *lock_call = 9;
    return inst_get_sub_imm_imm(src[11]);
  }
  // GCC：原始type在x24，name暂存在x21；链表容器x19的两次换算必须一致。
  if (inst_is_adrp(src[3]) && inst_get_adrp_rd(src[3]) == 22 && nm_move(src[7], 24, 0)) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[1]) || !nm_rule_entry_save(src[2])
        || !nm_rule_entry_save(src[4]) || !nm_rule_entry_save(src[6]) || !inst_is_add_imm(src[5])
        || !inst_get_add_imm_sf(src[5]) || inst_get_add_imm_rd(src[5]) != 20 || inst_get_add_imm_rn(src[5]) != 22
        || inst_get_add_imm_sh(src[5]) || !nm_add_at(src[8], 0, 20, 48) || !inst_is_bl(src[9])
        || !nm_load_unscaled(src[10], 23, 20, 96, 3) || !nm_compare(src[11], 23, 20) || !inst_is_sub_imm(src[12])
        || !inst_get_sub_imm_sf(src[12]) || inst_get_sub_imm_rd(src[12]) != 19 || inst_get_sub_imm_rn(src[12]) != 23
        || inst_get_sub_imm_sh(src[12]) || !inst_is_b_cond(src[13]) || inst_get_b_cond_cond(src[13])
        || inst_get_b_cond_label(src[13]) <= 12 || !nm_load_at(src[14], 21, 24, 0) || !inst_is_b(src[15])
        || inst_get_b_label(src[15]) != 20)
      return -EOPNOTSUPP;
    int link = inst_get_sub_imm_imm(src[12]);
    if (!nm_load_at(src[16], 19, 19, link) || !nm_compare(src[17], 19, 20) || !inst_is_sub_imm(src[18])
        || !inst_get_sub_imm_sf(src[18]) || inst_get_sub_imm_rd(src[18]) != 19 || inst_get_sub_imm_rn(src[18]) != 19
        || inst_get_sub_imm_sh(src[18]) || inst_get_sub_imm_imm(src[18]) != link || !inst_is_b_cond(src[19])
        || inst_get_b_cond_cond(src[19]) || inst_get_b_cond_label(src[19]) <= 12 || !nm_load_at(src[20], 0, 19, 0)
        || !nm_move(src[21], 1, 21) || !inst_is_bl(src[22])
        || (uintptr_t)&src[22] + inst_get_bl_label(src[22]) != compare)
      return -EOPNOTSUPP;
    *lock_call = 9;
    return link;
  }
  unsigned int name, branch, head;
  if (inst_is_paciasp(src[0])) {
    for (unsigned int i = 1; i <= 6; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move(src[7], 20, 0) || !nm_page_address(&src[8], 0) || !inst_is_bl(src[10])
        || !nm_page_address(&src[11], 22) || !nm_load_at(src[13], 19, 22, 0) || !nm_compare(src[14], 19, 22)
        || !nm_load_at(src[16], 21, 20, 0) || !nm_move(src[17], 23, 19) || !nm_move(src[19], 1, 21))
      return -EOPNOTSUPP;
    *lock_call = 10;
    name = 18;
    branch = 15;
    head = 23;
  } else {
    bool wide = nm_move(src[5], 19, 0) && nm_add_at(src[2], 29, 31, 0);
    unsigned int saved = wide ? 5 : (inst_is_str_imm9(src[0]) ? 5 : 4);
    // 只有class目标地址构造可触发长窗口，旧入口的截短保护页不向后扩读。
    if (!nm_move(src[saved], 19, 0) || !inst_is_add_imm(src[saved + 1]) || !inst_get_add_imm_sf(src[saved + 1])
        || inst_get_add_imm_rd(src[saved + 1]) || inst_get_add_imm_rn(src[saved + 1])
        || inst_get_add_imm_sh(src[saved + 1]))
      return -EOPNOTSUPP;
    for (unsigned int i = 0; i < saved; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move32(src[saved + 2], 1, 31) || !nm_zero64(src[saved + 3], 2) || !inst_is_bl(src[saved + 4])
        || !nm_page_address(&src[saved + 5], 0) || !inst_is_bl(src[saved + 7])
        || !nm_page_address(&src[saved + 8], wide ? 22 : 21) || !nm_load_at(src[saved + 10], 20, wide ? 22 : 21, 0)
        || !nm_compare(src[saved + 11], 20, wide ? 22 : 21))
      return -EOPNOTSUPP;
    *class_offset = inst_get_add_imm_imm(src[saved + 1]);
    *class_call = saved + 4;
    *lock_call = saved + 7;
    branch = saved + 12;
    if (wide) {
      if (!nm_load_at(src[18], 21, 19, 0) || !nm_move(src[19], 23, 20) || !nm_move(src[21], 1, 21))
        return -EOPNOTSUPP;
      name = 20;
      head = 23;
    } else {
      name = saved + 13;
      head = 20;
      if (!nm_load_at(src[name + 1], 1, 19, 0))
        return -EOPNOTSUPP;
    }
  }
  if (!inst_is_b_cond(src[branch]) || inst_get_b_cond_cond(src[branch]) || inst_get_b_cond_label(src[branch]) <= 12
      || !inst_is_ldr_imm9(src[name]) || !nm_load_unscaled(src[name], 0, head, inst_get_ldr_imm9_imm9(src[name]), 0)
      || !inst_is_bl(src[name + 2]) || (uintptr_t)&src[name + 2] + inst_get_bl_label(src[name + 2]) != compare)
    return -EOPNOTSUPP;
  int link = -inst_get_ldr_imm9_imm9(src[name]);
  return link >= NM_KEY_TYPE_PROBE_SIZE && link % 8 == 0 ? link : -EINVAL;
}

static int nm_check_key_name(const uint32_t* src, uintptr_t compare) {
  int lock_call, class_call, class_offset;
  int link = nm_find_key_registration(src, compare, &lock_call, &class_call, &class_offset);
#ifndef CONFIG_KPM_BASELINES
  // 即使完整尾部尚未覆盖，已识别的注册链表写入也必须落在自建容量内。
  if (link >= 0 && link > NM_OWNED_OPERATIONS_CAPACITY - sizeof(struct nm_key_type_tail))
    return -E2BIG;
#endif
  return link < 0 ? link : 0;
}

static bool nm_max_signed64(uint32_t inst, int rd) {
  return inst_is_movn_imm(inst) && inst_get_movn_imm_sf(inst) && inst_get_movn_imm_rd(inst) == rd
         && inst_get_movn_imm_hw(inst) == 3 && inst_get_movn_imm_imm16(inst) == 0x8000;
}

// key_instantiate_and_link前22／26条：从key->type核对def_datalen及preparse读取。
static int nm_find_key_callback_slot_legacy(const uint32_t* src) {
  int slot;
  if (inst_is_str_imm9(src[0])) {
    bool reordered = nm_move(src[10], 20, 4);
    if (!nm_rule_entry_save(src[0]) || !inst_is_sub_imm(src[1]) || !inst_get_sub_imm_sf(src[1])
        || inst_get_sub_imm_rd(src[1]) != 31 || inst_get_sub_imm_rn(src[1]) != 31 || inst_get_sub_imm_imm(src[1]) != 160
        || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4])
        || !nm_add_at(src[5], 29, 31, 112) || !inst_is_adrp(src[6]) || inst_get_adrp_rd(src[6]) != 8
        || !nm_move(src[7], 19, 0) || !nm_max_signed64(src[8], 10) || !nm_load(src[9], 3, 8)
        || inst_get_ldr_imm_rt(src[9]) != 8
        || !(reordered ? (nm_move(src[11], 21, 0) && nm_move(src[12], 22, 3))
                       : (nm_move(src[10], 21, 4) && nm_move(src[11], 20, 3) && nm_move(src[12], 22, 0)))
        || !inst_is_str_imm9(src[13]) || bit(src[13], 26) || inst_get_str_imm9_size(src[13]) != 3
        || inst_get_str_imm9_rt(src[13]) != 8 || inst_get_str_imm9_rn(src[13]) != 29 || inst_get_str_imm9_mode(src[13])
        || inst_get_str_imm9_imm9(src[13]) != -8 || !inst_is_ldr_imm9(src[14])
        || !nm_load_unscaled(src[14], 8, 19, inst_get_ldr_imm9_imm9(src[14]), 3) || inst_get_ldr_imm9_imm9(src[14]) <= 0
        || inst_get_ldr_imm9_imm9(src[14]) % 8 || !nm_pair_store_at(src[reordered ? 16 : 15], 31, 31, 31, 40)
        || !nm_pair_store_at(src[reordered ? 17 : 16], 31, 31, 31, 56)
        || !nm_pair_store_at(src[reordered ? 18 : 17], 1, 2, 31, 72)
        || !nm_load_at(src[reordered ? 19 : 18], 9, 8, offsetof(struct nm_key_type_head, def_datalen))
        || !nm_pair_store_at(src[reordered ? 15 : 19], 31, 31, 31, 24) || !nm_pair_store_at(src[20], 9, 10, 31, 88)
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

// 新入口从key实参一直核对到type->def_datalen与preparse；最多30条，旧窗口不扩大。
static int nm_find_key_callback_slot(const uint32_t* src) {
  int slot = nm_find_key_callback_slot_legacy(src);
  if (slot >= 0 || slot == -EINVAL)
    return slot;
  bool pac = inst_is_paciasp(src[0]);
  bool sub = inst_is_sub_imm(src[pac ? 1 : 0]);
  if (!sub) {
    // GCC count型目标：key保存在x20，type读入x0，前24条内没有调用。
    if (!nm_rule_entry_save(src[0]) || !nm_add_at(src[1], 29, 31, 0))
      return -EOPNOTSUPP;
    for (unsigned int i = 2; i <= 4; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_pair_store_at(src[5], 31, 31, 29, 128) || !nm_pair_store_at(src[6], 31, 31, 29, 112)
        || !nm_move(src[7], 20, 0) || !nm_load(src[8], 3, 0) || inst_get_ldr_imm_rt(src[8]) != 0
        || !inst_get_ldr_imm_imm(src[8]) || inst_get_ldr_imm_imm(src[8]) % 8 || !nm_store_at(src[9], 3, 31, 29, 144)
        || !inst_is_adrp(src[10]) || inst_get_adrp_rd(src[10]) != 22 || !nm_store_at(src[11], 3, 1, 29, 120)
        || !nm_move(src[12], 21, 3) || !nm_pair_store_at(src[13], 31, 31, 29, 80)
        || !nm_pair_store_at(src[14], 31, 31, 29, 96) || !nm_store_at(src[15], 3, 2, 29, 128)
        || !nm_move(src[16], 23, 4) || !nm_load(src[17], 3, 22) || inst_get_ldr_imm_rt(src[17]) != 1
        || !nm_load_at(src[18], 2, 0, 8) || !nm_store_at(src[19], 3, 2, 29, 136) || !nm_max_signed64(src[20], 2)
        || !nm_store_at(src[21], 3, 2, 29, 144) || !nm_store_at(src[22], 3, 1, 29, 152) || !nm_load(src[23], 3, 0)
        || inst_get_ldr_imm_rt(src[23]) != 1)
      return -EOPNOTSUPP;
    slot = inst_get_ldr_imm_imm(src[23]);
  } else {
    unsigned int frame = pac ? 1 : 0;
    if (!inst_get_sub_imm_sf(src[frame]) || inst_get_sub_imm_rd(src[frame]) != 31
        || inst_get_sub_imm_rn(src[frame]) != 31 || inst_get_sub_imm_imm(src[frame]) != 160)
      return -EOPNOTSUPP;
    if (pac) {
      for (unsigned int i = 2; i <= 6; i++)
        if (!nm_rule_entry_save(src[i]))
          return -EOPNOTSUPP;
      if (!nm_add_at(src[7], 29, 31, 96) || !inst_is_adrp(src[8]) || inst_get_adrp_rd(src[8]) != 8
          || !nm_load(src[9], 3, 8) || inst_get_ldr_imm_rt(src[9]) != 8 || !nm_max_signed64(src[10], 10)
          || !nm_move(src[11], 20, 4) || !nm_move(src[12], 19, 0) || !nm_pair_store_at(src[14], 31, 31, 31, 8)
          || !nm_pair_store_at(src[15], 31, 31, 31, 24) || !nm_pair_store_at(src[16], 31, 31, 31, 40)
          || !nm_pair_store_at(src[17], 31, 31, 31, 72) || !nm_pair_store_at(src[18], 1, 2, 31, 56)
          || !nm_load(src[19], 3, 0) || inst_get_ldr_imm_rt(src[19]) != 8 || !inst_get_ldr_imm_imm(src[19])
          || inst_get_ldr_imm_imm(src[19]) % 8 || !nm_move(src[20], 21, 3) || !nm_load_at(src[21], 9, 8, 8)
          || !nm_pair_store_at(src[22], 9, 10, 31, 72) || !nm_load(src[23], 3, 8) || inst_get_ldr_imm_rt(src[23]) != 22)
        return -EOPNOTSUPP;
      uint32_t save = src[13];
      if (!inst_is_str_imm9(save) || bit(save, 26) || inst_get_str_imm9_size(save) != 3
          || inst_get_str_imm9_rt(save) != 8 || inst_get_str_imm9_rn(save) != 29 || inst_get_str_imm9_mode(save)
          || inst_get_str_imm9_imm9(save) != -8)
        return -EOPNOTSUPP;
      slot = inst_get_ldr_imm_imm(src[23]);
    } else {
      bool scs = inst_is_str_imm9(src[1]);
      unsigned int fp = scs ? 6 : 2, page = scs ? 7 : 6;
      for (unsigned int i = 1; i < page; i++)
        if (i != fp && !nm_rule_entry_save(src[i]))
          return -EOPNOTSUPP;
      if (!nm_add_at(src[fp], 29, 31, 96) || !inst_is_adrp(src[page]) || inst_get_adrp_rd(src[page]) != 8)
        return -EOPNOTSUPP;
      unsigned int save, call, type, callback;
      if (scs) {
        if (!nm_load(src[8], 3, 8) || inst_get_ldr_imm_rt(src[8]) != 8 || !nm_move(src[9], 22, 2)
            || !nm_move(src[10], 23, 1) || !nm_move(src[11], 19, 0) || !nm_add_at(src[12], 0, 31, 16)
            || !inst_is_movz_imm(src[13]) || inst_get_movz_imm_sf(src[13]) || inst_get_movz_imm_rd(src[13]) != 2
            || inst_get_movz_imm_hw(src[13]) || inst_get_movz_imm_imm16(src[13]) != 72 || !nm_move32(src[14], 1, 31)
            || !nm_move(src[15], 21, 4) || !nm_move(src[16], 20, 3))
          return -EOPNOTSUPP;
        for (unsigned int i = 18; i <= 22; i++)
          if (!nm_pair_store_at(src[i], 31, 31, 31, 72 - (i - 18) * 16))
            return -EOPNOTSUPP;
        if (!nm_pair_store_at(src[24], 23, 22, 31, 56) || !nm_load(src[25], 3, 19) || inst_get_ldr_imm_rt(src[25]) != 8
            || !inst_get_ldr_imm_imm(src[25]) || inst_get_ldr_imm_imm(src[25]) % 8 || !nm_max_signed64(src[26], 10))
          return -EOPNOTSUPP;
        save = 17;
        call = 23;
        type = 25;
        callback = 29;
      } else {
        if (!nm_move(src[7], 23, 2) || !nm_move(src[8], 24, 1) || !nm_move(src[9], 22, 0) || !inst_is_movz_imm(src[10])
            || inst_get_movz_imm_sf(src[10]) || inst_get_movz_imm_rd(src[10]) != 2 || inst_get_movz_imm_hw(src[10])
            || inst_get_movz_imm_imm16(src[10]) != 72 || !nm_add_at(src[11], 0, 31, 16) || !nm_load(src[12], 3, 8)
            || inst_get_ldr_imm_rt(src[12]) != 8 || !nm_move32(src[13], 1, 31) || !nm_move(src[14], 21, 4)
            || !nm_move(src[15], 20, 3) || !nm_move(src[18], 19, 22) || !nm_pair_store_at(src[19], 24, 23, 31, 56)
            || !nm_max_signed64(src[20], 10) || !inst_is_ldr_imm9(src[21])
            || !nm_load_unscaled(src[21], 8, 19, inst_get_ldr_imm9_imm9(src[21]), 3)
            || inst_get_ldr_imm9_imm9(src[21]) <= 0 || inst_get_ldr_imm9_imm9(src[21]) % 8)
          return -EOPNOTSUPP;
        save = 16;
        call = 17;
        type = 21;
        callback = 24;
      }
      uint32_t canary = src[save];
      uintptr_t clear = kallsyms_lookup_name_by_suffix("memset");
      if (!inst_is_str_imm9(canary) || bit(canary, 26) || inst_get_str_imm9_size(canary) != 3
          || inst_get_str_imm9_rt(canary) != 8 || inst_get_str_imm9_rn(canary) != 29 || inst_get_str_imm9_mode(canary)
          || inst_get_str_imm9_imm9(canary) != -8 || !clear || !inst_is_bl(src[call])
          || (uintptr_t)&src[call] + inst_get_bl_label(src[call]) != clear)
        return -EOPNOTSUPP;
      if (scs && !nm_load_at(src[type + 2], 9, 8, offsetof(struct nm_key_type_head, def_datalen)))
        return -EOPNOTSUPP;
      if (!scs && !nm_load_at(src[22], 9, 8, 8))
        return -EOPNOTSUPP;
      unsigned int pair = scs ? 28 : 23;
      if (!nm_pair_store_at(src[pair], 9, 10, 31, 72) || !nm_load(src[callback], 3, 8)
          || inst_get_ldr_imm_rt(src[callback]) != (scs ? 22 : 8))
        return -EOPNOTSUPP;
      slot = inst_get_ldr_imm_imm(src[callback]);
    }
  }
  return slot >= sizeof(struct nm_key_type_head) && slot + sizeof(struct nm_key_callbacks) <= NM_KEY_TYPE_PROBE_SIZE
             ? slot
             : -EINVAL;
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

// unregister_key_type前17条：入口type保存在x19，list_del_init写回link的两个自指针。
// 固定形态逐条核对，BL只允许已确认的down_write和链表校验器，不跨未知clobber。
static int nm_find_key_type_link_legacy(const uint32_t* src, uintptr_t down_write, uintptr_t list_valid) {
  if (!src || !down_write || !list_valid)
    return -ENOENT;
  if (src[0] != 0xf800865eU || src[1] != 0xa9be7bfdU || src[2] != 0xa9014ff4U || src[3] != 0x910003fdU
      || !nm_move(src[4], 19, 0) || !nm_page_address(&src[5], 0) || !inst_is_bl(src[7])
      || (uintptr_t)&src[7] + inst_get_bl_label(src[7]) != down_write || !inst_is_add_imm(src[8])
      || !inst_get_add_imm_sf(src[8]) || inst_get_add_imm_rd(src[8]) != 20 || inst_get_add_imm_rn(src[8]) != 19
      || inst_get_add_imm_sh(src[8]) || !nm_move(src[9], 0, 20) || !inst_is_bl(src[10])
      || (uintptr_t)&src[10] + inst_get_bl_label(src[10]) != list_valid || !inst_is_tbz(src[11])
      || inst_get_tbz_rt(src[11]) || inst_get_tbz_bit(src[11]) || inst_get_tbz_label(src[11]) != 16)
    return -EOPNOTSUPP;
  int link = inst_get_add_imm_imm(src[8]);
  if (link < NM_KEY_TYPE_PROBE_SIZE || link > 4096 - sizeof(struct nm_key_type_tail) || link % 8)
    return -EINVAL;
  uint32_t pair = src[12];
  if (!inst_is_ldp(pair) || bit(pair, 26) || inst_get_ldp_size(pair) != 2 || inst_get_ldp_mode(pair) != 2
      || inst_get_ldp_rt(pair) != 9 || inst_get_ldp_rt2(pair) != 8 || inst_get_ldp_rn(pair) != 19
      || inst_get_ldp_imm(pair) != link || !nm_store_at(src[13], 3, 8, 9, 8) || !nm_store_at(src[14], 3, 9, 8, 0)
      || !nm_store_at(src[15], 3, 20, 19, link) || !nm_store_at(src[16], 3, 20, 19, link + 8))
    return -EINVAL;
  return link;
}

static int nm_find_key_type_link(const uint32_t* src, uintptr_t down_write, uintptr_t list_valid) {
  if (!src || !down_write)
    return -ENOENT;
  int legacy = nm_find_key_type_link_legacy(src, down_write, list_valid);
  if (legacy >= 0 || legacy == -EINVAL)
    return legacy;
  // GCC内联list_del_init，不要求并不存在的独立校验器；原type始终保存在x20。
  if (inst_is_adrp(src[3]) && inst_get_adrp_rd(src[3]) == 19 && nm_move(src[4], 20, 0)) {
    for (unsigned int i = 0; i < 3; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!inst_is_add_imm(src[5]) || !inst_get_add_imm_sf(src[5]) || inst_get_add_imm_rd(src[5]) != 19
        || inst_get_add_imm_rn(src[5]) != 19 || inst_get_add_imm_sh(src[5]) || !nm_add_at(src[6], 19, 19, 48)
        || !nm_move(src[7], 0, 19) || !inst_is_bl(src[8])
        || (uintptr_t)&src[8] + inst_get_bl_label(src[8]) != down_write || !nm_load(src[9], 3, 20)
        || !inst_is_add_imm(src[10]) || !inst_get_add_imm_sf(src[10]) || inst_get_add_imm_rn(src[10]) != 20
        || inst_get_add_imm_sh(src[10]) || !nm_load(src[11], 3, 20))
      return -EOPNOTSUPP;
    int link = inst_get_add_imm_imm(src[10]);
    int next = inst_get_ldr_imm_rt(src[9]), prev = inst_get_ldr_imm_rt(src[11]);
    int node = inst_get_add_imm_rd(src[10]);
    bool reordered = nm_move(src[12], 0, 19);
    unsigned int at = reordered ? 13 : 12;
    if (link < NM_KEY_TYPE_PROBE_SIZE || link > 4096 - sizeof(struct nm_key_type_tail) || link % 8
        || (reordered ? (next != 3 || prev != 2 || node != 1) : (next != 2 || prev != 1 || node != 0))
        || inst_get_ldr_imm_imm(src[9]) != link || inst_get_ldr_imm_imm(src[11]) != link + 8
        || !nm_store_at(src[at], 3, prev, next, 8) || !nm_store_at(src[at + 1], 3, next, prev, 0)
        || !nm_store_at(src[at + 2], 3, node, 20, link) || !nm_store_at(src[at + 3], 3, node, 20, link + 8))
      return -EINVAL;
    return link;
  }
  if (!list_valid)
    return -ENOENT;
  bool pac = inst_is_paciasp(src[0]);
  unsigned int call, pair, store;
  int node;
  if (pac) {
    for (unsigned int i = 1; i <= 5; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_page_address(&src[6], 20) || !nm_move(src[8], 19, 0) || !nm_move(src[9], 0, 20))
      return -EOPNOTSUPP;
    call = 10;
    pair = 14;
    store = 18;
    node = 21;
  } else {
    for (unsigned int i = 0; i < 3; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move(src[3], 19, 0) || !nm_page_address(&src[4], 0))
      return -EOPNOTSUPP;
    call = 6;
    pair = 11;
    store = 14;
    node = 20;
  }
  if (!inst_is_bl(src[call]) || (uintptr_t)&src[call] + inst_get_bl_label(src[call]) != down_write
      || !inst_is_add_imm(src[call + 1]) || !inst_get_add_imm_sf(src[call + 1])
      || inst_get_add_imm_rd(src[call + 1]) != node || inst_get_add_imm_rn(src[call + 1]) != 19
      || inst_get_add_imm_sh(src[call + 1]) || !nm_move(src[call + 2], 0, node) || !inst_is_bl(src[call + 3])
      || (uintptr_t)&src[call + 3] + inst_get_bl_label(src[call + 3]) != list_valid)
    return -EOPNOTSUPP;
  int link = inst_get_add_imm_imm(src[call + 1]);
  if (link < NM_KEY_TYPE_PROBE_SIZE || link > 4096 - sizeof(struct nm_key_type_tail) || link % 8)
    return -EINVAL;
  if (pac ? !nm_move(src[15], 0, 20)
          : (!inst_is_tbz(src[10]) || inst_get_tbz_rt(src[10]) || inst_get_tbz_bit(src[10])
             || inst_get_tbz_label(src[10]) != 16))
    return -EOPNOTSUPP;
  uint32_t load = src[pair];
  if (!inst_is_ldp(load) || bit(load, 26) || inst_get_ldp_size(load) != 2 || inst_get_ldp_mode(load) != 2
      || inst_get_ldp_rt(load) != 9 || inst_get_ldp_rt2(load) != 8 || inst_get_ldp_rn(load) != 19
      || inst_get_ldp_imm(load) != link || !nm_store_at(src[pac ? 16 : 12], 3, 8, 9, 8)
      || !nm_store_at(src[pac ? 17 : 13], 3, 9, 8, 0) || !nm_store_at(src[store], 3, node, 19, link)
      || !nm_store_at(src[store + 1], 3, node, 19, link + 8))
    return -EINVAL;
  return link;
}

static int calculate_function_key_type_size(void) {
  // key_type自己的注册入口验证class清零（或已核对的消除形态），不从mutex推断全局LOCKDEP。
  // 尾部契约仍为link + 空lock_class，无额外槽或强制对齐；不可见的厂商追加字段不在证明内。
  if (struct_offset.mutex_no_lockdep != 1 || (struct_offset.key_callbacks != 24 && struct_offset.key_callbacks != 32))
    return -EOPNOTSUPP;
  const uint32_t* reg = (const void*)kallsyms_lookup_name_by_suffix("register_key_type");
  const uint32_t* unreg = (const void*)kallsyms_lookup_name_by_suffix("unregister_key_type");
  uintptr_t compare = kallsyms_lookup_name_by_suffix("strcmp");
  uintptr_t down_write = kallsyms_lookup_name_by_suffix("down_write");
  uintptr_t list_valid = kallsyms_lookup_name_by_suffix("__list_del_entry_valid");
  const uint32_t* init = (const void*)kallsyms_lookup_name_by_suffix("key_instantiate_and_link");
  if (!reg || !unreg || !compare || !down_write || !init)
    return -ENOENT;
  if (nm_find_key_callback_slot(init) != struct_offset.key_callbacks)
    return -EOPNOTSUPP;
  int lock_call, class_call, class_offset;
  int registered = nm_find_key_registration(reg, compare, &lock_call, &class_call, &class_offset);
  if (registered < 0)
    return registered;
  if ((uintptr_t)&reg[lock_call] + inst_get_bl_label(reg[lock_call]) != down_write)
    return -EINVAL;
  int link = nm_find_key_type_link(unreg, down_write, list_valid);
  if (link < 0)
    return link;
  if (link != registered)
    return -EINVAL;
  if (class_call >= 0) {
    uintptr_t clear = kallsyms_lookup_name_by_suffix("memset");
    if (!clear)
      return -ENOENT;
    if ((uintptr_t)&reg[class_call] + inst_get_bl_label(reg[class_call]) != clear
        || class_offset != link + sizeof(struct nm_key_type_tail))
      return -EINVAL;
  }
  struct_offset.key_type_size = link + sizeof(struct nm_key_type_tail);
  nm_log_info("layout: key_type=%d (link=%d, verified no-lockdep tail contract)\n", struct_offset.key_type_size, link);
  return 0;
}

static int nm_check_directory_iteration_legacy(const uint32_t* src, int slot) {
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

// 只核对读取iterate槽之前的参数保存与f_inode/f_op共同片段；后续执行仍交原生iterate_dir。
static int nm_check_directory_iteration(const uint32_t* src, int slot) {
  int rc = nm_check_directory_iteration_legacy(src, slot);
  if (!rc || rc == -EINVAL)
    return rc;
  if (inst_is_paciasp(src[0]))
    src++;
  bool scs = inst_is_str_imm9(src[0]);
  unsigned int pair = scs ? 7 : 6;
  for (unsigned i = 0; i < pair; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  bool gcc = nm_move(src[6], 22, 1) && nm_move(src[7], 19, 0);
  if (gcc) {
    if (!nm_load_at(src[8], 1, 0, struct_offset.file_inode_ops + offsetof(struct nm_file_inode_ops, f_op))
        || !nm_load_at(src[9], 21, 0, struct_offset.file_inode_ops) || !nm_load_at(src[10], 2, 1, slot)
        || !inst_is_cbz(src[11]) || !inst_get_cbz_sf(src[11]) || inst_get_cbz_rt(src[11]) != 2
        || inst_get_cbz_label(src[11]) <= 4)
      return -EOPNOTSUPP;
  } else {
    uint32_t load = src[pair];
    int callback = inst_get_ldr_imm_rt(src[pair + 3]);
    if (!inst_is_ldp(load) || bit(load, 26) || inst_get_ldp_size(load) != 2 || inst_get_ldp_mode(load) != 2
        || inst_get_ldp_rt(load) != 23 || inst_get_ldp_rt2(load) != 8 || inst_get_ldp_rn(load) != 0
        || inst_get_ldp_imm(load) != struct_offset.file_inode_ops || !nm_move(src[pair + 1], 19, 0)
        || !(nm_move(src[pair + 2], 22, 1) || nm_move(src[pair + 2], 21, 1) || nm_move(src[pair + 2], 20, 1))
        || (callback != 9 && callback != 22) || !nm_load_at(src[pair + 3], callback, 8, slot)
        || !inst_is_cbz(src[pair + 4]) || !inst_get_cbz_sf(src[pair + 4]) || inst_get_cbz_rt(src[pair + 4]) != callback
        || inst_get_cbz_label(src[pair + 4]) <= 4)
      return -EOPNOTSUPP;
  }
  if (slot != offsetof(struct nm_file_iteration_ops, iterate_shared)
      && slot != offsetof(struct nm_file_iopoll_iteration_ops, iterate_shared))
    return -EINVAL;
  struct_offset.fop_iterate = slot - sizeof(void*);
  struct_offset.fop_iterate_shared = slot;
  return 0;
}

// __dentry_kill前23／17条核对prune槽与实际调用，原生调用须保留x19。
static int nm_find_dentry_lifecycle_legacy(const uint32_t* src, uintptr_t dead, uintptr_t start, uintptr_t end) {
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
static int nm_find_directory_actor_legacy(const uint32_t* src) {
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

// prune以DCACHE_OP_PRUNE位4和实际dentry实参锚定，release/init来自已核对的连续片段。
static int nm_dentry_prune_slot(int slot) {
  int release = slot - (int)offsetof(struct nm_dentry_release_prune, d_prune);
  if (release != sizeof(struct nm_dentry_control_ops) && release != sizeof(struct nm_dentry_control_ops) + 8)
    return -EOPNOTSUPP;
  struct_offset.dop_release = release;
  struct_offset.dop_init = release == sizeof(struct nm_dentry_control_ops) ? -1 : sizeof(struct nm_dentry_control_ops);
  return 0;
}

static int nm_find_dentry_lifecycle(const uint32_t* src, uintptr_t dead, uintptr_t start, uintptr_t end) {
  int old = nm_find_dentry_lifecycle_legacy(src, dead, start, end);
  if (!old || old == -EINVAL)
    return old;
  bool pac = inst_is_paciasp(src[0]);
  if (pac)
    src++;
  // GCC把prune块放在前向TBNZ目标处；只读入口13条和目标6条，不扫描中间函数体。
  if (nm_move(src[3], 19, 0)) {
    for (unsigned i = 0; i < 3; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_store_at(src[4], 3, 21, 31, 32) || !nm_add_at(src[5], 21, 0, struct_offset.dentry_lock)
        || !nm_move(src[6], 0, 21) || !nm_load_at(src[7], 20, 19, offsetof(struct nm_dentry_head, d_parent))
        || !nm_compare(src[8], 20, 19) || !inst_is_csel(src[9]) || !inst_get_csel_sf(src[9])
        || inst_get_csel_rd(src[9]) != 20 || inst_get_csel_rn(src[9]) != 20 || inst_get_csel_rm(src[9]) != 31
        || inst_get_csel_cond(src[9]) != 1 || !inst_is_bl(src[10])
        || !nm_code_matches((uintptr_t)&src[10] + inst_get_bl_label(src[10]), dead, start, end)
        || !nm_load(src[11], 2, 19) || inst_get_ldr_imm_rt(src[11]) || inst_get_ldr_imm_imm(src[11])
        || !inst_is_tbnz(src[12]) || inst_get_tbnz_rt(src[12]) || inst_get_tbnz_bit(src[12]) != 4)
      return -EOPNOTSUPP;
    long delta = inst_get_tbnz_label(src[12]);
    uintptr_t target = (uintptr_t)&src[12] + delta;
    if (delta < 4 || delta > 384 || target < start || target > end || end - target < 24)
      return -EOPNOTSUPP;
    const uint32_t* block = (const void*)target;
    if (!nm_load_at(block[0], 1, 19, struct_offset.dentry_ops) || !nm_move(block[1], 0, 19) || !nm_load(block[2], 3, 1)
        || inst_get_ldr_imm_rt(block[2]) != 1 || !inst_is_blr(block[3]) || inst_get_blr_rn(block[3]) != 1
        || !nm_load(block[4], 2, 19) || inst_get_ldr_imm_rt(block[4]) || inst_get_ldr_imm_imm(block[4])
        || !inst_is_b(block[5]) || (uintptr_t)&block[5] + inst_get_b_label(block[5]) != (uintptr_t)&src[13])
      return -EOPNOTSUPP;
    return nm_dentry_prune_slot(inst_get_ldr_imm_imm(block[2]));
  }
  bool scs = inst_is_str_imm9(src[0]);
  unsigned p = scs ? 5 : 4;
  for (unsigned i = 0; i < p; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[p], 8, 0, offsetof(struct nm_dentry_head, d_parent))
      || !nm_add_at(src[p + 1], 20, 0, struct_offset.dentry_lock))
    return -EOPNOTSUPP;
  unsigned flag;
  if (pac) {
    if (!inst_is_ldar(src[p + 2]) || inst_get_ldar_size(src[p + 2]) != 2 || inst_get_ldar_rn(src[p + 2]) != 20
        || inst_get_ldar_rt(src[p + 2]) != 9 || !nm_compare(src[p + 3], 8, 0) || !inst_is_csel(src[p + 4])
        || !inst_get_csel_sf(src[p + 4]) || inst_get_csel_rd(src[p + 4]) != 22 || inst_get_csel_rn(src[p + 4]) != 31
        || inst_get_csel_rm(src[p + 4]) != 8 || inst_get_csel_cond(src[p + 4]) || !inst_is_cbz(src[p + 5])
        || inst_get_cbz_sf(src[p + 5]) || inst_get_cbz_rt(src[p + 5]) != 9 || inst_get_cbz_label(src[p + 5]) <= 64
        || !nm_load(src[p + 6], 2, 0) || inst_get_ldr_imm_rt(src[p + 6]) != 8 || inst_get_ldr_imm_imm(src[p + 6])
        || !nm_move(src[p + 7], 19, 0) || !inst_is_movn_imm(src[p + 8]) || inst_get_movn_imm_sf(src[p + 8])
        || inst_get_movn_imm_rd(src[p + 8]) != 9 || inst_get_movn_imm_hw(src[p + 8])
        || inst_get_movn_imm_imm16(src[p + 8]) != 127
        || !nm_store_at(src[p + 9], 2, 9, 0, struct_offset.dentry_lock + 4))
      return -EOPNOTSUPP;
    flag = p + 10;
  } else {
    if (!nm_move(src[p + 2], 19, 0) || !nm_compare(src[p + 3], 8, 0) || !nm_move(src[p + 4], 0, 20)
        || !inst_is_csel(src[p + 5]) || !inst_get_csel_sf(src[p + 5]) || inst_get_csel_rd(src[p + 5]) != 22
        || inst_get_csel_rn(src[p + 5]) != 31 || inst_get_csel_rm(src[p + 5]) != 8 || inst_get_csel_cond(src[p + 5])
        || !inst_is_bl(src[p + 6])
        || !nm_code_matches((uintptr_t)&src[p + 6] + inst_get_bl_label(src[p + 6]), dead, start, end)
        || !nm_load(src[p + 7], 2, 19) || inst_get_ldr_imm_rt(src[p + 7]) != 8 || inst_get_ldr_imm_imm(src[p + 7]))
      return -EOPNOTSUPP;
    flag = p + 8;
  }
  if (!inst_is_tbz(src[flag]) || inst_get_tbz_rt(src[flag]) != 8 || inst_get_tbz_bit(src[flag]) != 4
      || !nm_load_at(src[flag + 1], 8, 19, struct_offset.dentry_ops))
    return -EOPNOTSUPP;
  unsigned load = flag + 2, call;
  int cb = scs ? 21 : 8;
  if (scs) {
    if (!nm_load(src[load], 3, 8) || inst_get_ldr_imm_rt(src[load]) != cb
        || !nm_cfi_gate_stride(&src[load + 1], cb, 8, 8) || !nm_move(src[load + 7], 0, 19))
      return -EOPNOTSUPP;
    call = load + 8;
  } else {
    if (!nm_move(src[load], 0, 19) || !nm_load(src[++load], 3, 8) || inst_get_ldr_imm_rt(src[load]) != cb)
      return -EOPNOTSUPP;
    call = load + 1;
  }
  if (inst_get_tbz_label(src[flag]) <= (int)(call - flag) * 4 || !inst_is_blr(src[call])
      || inst_get_blr_rn(src[call]) != cb)
    return -EOPNOTSUPP;
  return nm_dentry_prune_slot(inst_get_ldr_imm_imm(src[load]));
}

static int nm_find_directory_actor(const uint32_t* src) {
  int old = nm_find_directory_actor_legacy(src);
  if (!old || old == -EINVAL)
    return old;
  if (inst_is_paciasp(src[0]))
    src++;
  int dentry = struct_offset.file_inode_ops - (int)offsetof(struct nm_file_path_inode_ops, f_inode)
               + (int)offsetof(struct nm_file_path_inode_ops, f_path.dentry);
  bool gcc = nm_move(src[4], 20, 0);
  unsigned p = inst_is_str_imm9(src[0]) ? 6 : 4, a, call;
  for (unsigned i = 0; i < p; i++)
    if (!nm_rule_entry_save(src[i]))
      return -EOPNOTSUPP;
  if (gcc) {
    if (!nm_move(src[5], 19, 1) || !nm_load_at(src[6], 0, 1, offsetof(struct nm_dir_context, pos))
        || !inst_is_cbz(src[7]) || !inst_get_cbz_sf(src[7]) || inst_get_cbz_rt(src[7])
        || inst_get_cbz_label(src[7]) != 32)
      return -EOPNOTSUPP;
    a = 15;
    if (!nm_load_at(src[a], 3, 20, dentry) || !nm_move(src[a + 1], 0, 1)
        || !nm_load_at(src[a + 2], 6, 1, offsetof(struct nm_dir_context, actor)) || !inst_is_adrp(src[a + 3])
        || inst_get_adrp_rd(src[a + 3]) != 1 || !inst_is_add_imm(src[a + 4]) || !inst_get_add_imm_sf(src[a + 4])
        || inst_get_add_imm_rd(src[a + 4]) != 1 || inst_get_add_imm_rn(src[a + 4]) != 1
        || !nm_movz_value(src[a + 5], 0, 2, 1)
        || !nm_load_at(src[a + 6], 4, 3, offsetof(struct nm_dentry_head, d_inode))
        || !nm_movz_value(src[a + 7], 0, 5, 4) || !nm_zero64(src[a + 8], 3)
        || !nm_load_at(src[a + 9], 4, 4, struct_offset.inode_number) || !inst_is_blr(src[a + 10])
        || inst_get_blr_rn(src[a + 10]) != 6)
      return -EOPNOTSUPP;
    call = a + 10;
  } else {
    int file = p == 4 ? 20 : inst_get_mov_reg_rd(src[p + 2]);
    if (!nm_load_at(src[p], 8, 1, offsetof(struct nm_dir_context, pos)) || !nm_move(src[p + 1], 19, 1)
        || (file != 20 && file != 22) || !nm_move(src[p + 2], file, 0) || !inst_is_subs_imm(src[p + 3])
        || !inst_get_subs_imm_sf(src[p + 3]) || inst_get_subs_imm_rd(src[p + 3]) != 31
        || inst_get_subs_imm_rn(src[p + 3]) != 8 || inst_get_subs_imm_imm(src[p + 3]) != 1
        || !inst_is_b_cond(src[p + 4]) || inst_get_b_cond_cond(src[p + 4]) || inst_get_b_cond_label(src[p + 4]) <= 48
        || !inst_is_cbnz(src[p + 5]) || !inst_get_cbnz_sf(src[p + 5]) || inst_get_cbnz_rt(src[p + 5]) != 8
        || inst_get_cbnz_label(src[p + 5]) <= 48)
      return -EOPNOTSUPP;
    a = p + 6;
    if (p == 4) {
      if (!nm_load_at(src[a], 8, file, dentry) || !inst_is_adrp(src[a + 1]) || inst_get_adrp_rd(src[a + 1]) != 1
          || !nm_load_at(src[a + 2], 9, 19, offsetof(struct nm_dir_context, actor)) || !inst_is_add_imm(src[a + 3])
          || !inst_get_add_imm_sf(src[a + 3]) || inst_get_add_imm_rd(src[a + 3]) != 1
          || inst_get_add_imm_rn(src[a + 3]) != 1 || !nm_move(src[a + 4], 0, 19) || !nm_movz_value(src[a + 5], 0, 2, 1)
          || !nm_zero64(src[a + 6], 3) || !nm_movz_value(src[a + 7], 0, 5, 4)
          || !nm_load_at(src[a + 8], 8, 8, offsetof(struct nm_dentry_head, d_inode))
          || !nm_load_at(src[a + 9], 4, 8, struct_offset.inode_number) || !inst_is_blr(src[a + 10])
          || inst_get_blr_rn(src[a + 10]) != 9)
        return -EOPNOTSUPP;
      call = a + 10;
    } else {
      int cb = file == 20 ? 21 : 20;
      if (!nm_load_at(src[a], cb, 19, offsetof(struct nm_dir_context, actor))
          || !nm_cfi_gate_stride(&src[a + 1], cb, 8, 44) || !nm_zero64(src[a + 7], 3)
          || !nm_load_at(src[a + 8], 8, file, dentry) || !inst_is_adrp(src[a + 9]) || inst_get_adrp_rd(src[a + 9]) != 1
          || !inst_is_add_imm(src[a + 10]) || !inst_get_add_imm_sf(src[a + 10]) || inst_get_add_imm_rd(src[a + 10]) != 1
          || inst_get_add_imm_rn(src[a + 10]) != 1 || !nm_movz_value(src[a + 11], 0, 2, 1)
          || !nm_load_at(src[a + 12], 8, 8, offsetof(struct nm_dentry_head, d_inode))
          || !nm_movz_value(src[a + 13], 0, 5, 4) || !nm_move(src[a + 14], 0, 19)
          || !nm_load_at(src[a + 15], 4, 8, struct_offset.inode_number) || !inst_is_blr(src[a + 16])
          || inst_get_blr_rn(src[a + 16]) != cb)
        return -EOPNOTSUPP;
      call = a + 16;
    }
    if (inst_get_b_cond_label(src[p + 4]) <= (int)(call - p - 4) * 4
        || inst_get_cbnz_label(src[p + 5]) <= (int)(call - p - 5) * 4)
      return -EOPNOTSUPP;
  }
  if (!inst_is_cbnz(src[call + 1]) || inst_get_cbnz_sf(src[call + 1]) || inst_get_cbnz_rt(src[call + 1]) != 0)
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
static int calculate_function_permission_abi_legacy(void) {
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

// 区分原生两参入口与NULL mount的三参包装；按实参来源匹配，不按内核版本选ABI。
static int calculate_function_permission_abi(void) {
  int old = calculate_function_permission_abi_legacy();
  if (!old || old == -EINVAL)
    return old;
  const uint32_t* src = (const void*)kallsyms_lookup_name_by_suffix("inode_permission");
  const uint32_t* native = (const void*)kallsyms_lookup_name_by_suffix("inode_permission2");
  if (!src)
    return -ENOENT;
  if (!native) {
    unsigned int i = 0;
    while (i < 8 && nm_vfs_frame_save(src[i])) i++;
    if (i == 8 || !nm_move32(src[i], 19, 1) || !nm_move(src[i + 1], 20, 0) || !inst_is_tbnz(src[i + 2])
        || inst_get_tbnz_rt(src[i + 2]) != 1 || inst_get_tbnz_bit(src[i + 2]) != 1
        || inst_get_tbnz_label(src[i + 2]) <= 4 || !nm_load(src[i + 3], 0, 20) || inst_get_ldr_imm_rt(src[i + 3]) != 8
        || inst_get_ldr_imm_imm(src[i + 3]) != offsetof(struct nm_inode_owner_prefix, i_opflags)
        || !inst_is_tbz(src[i + 4]) || inst_get_tbz_rt(src[i + 4]) != 8 || inst_get_tbz_bit(src[i + 4])
        || inst_get_tbz_label(src[i + 4]) <= 4 || !nm_move(src[i + 5], 0, 20) || !nm_move32(src[i + 6], 1, 19)
        || !inst_is_bl(src[i + 7]))
      return old;
    uintptr_t target = kallsyms_lookup_name_by_suffix("generic_permission");
    if (!target || (uintptr_t)&src[i + 7] + inst_get_bl_label(src[i + 7]) != target)
      return -EOPNOTSUPP;
    struct_offset.permission_abi = 1;
    return 0;
  }
  unsigned int call;
  uintptr_t call_target = (uintptr_t)native;
  if (nm_rule_entry_save(src[0]) && nm_rule_entry_save(src[1]) && nm_move32(src[2], 2, 1) && nm_move(src[3], 1, 0)
      && nm_zero64(src[4], 0) && inst_is_bl(src[5])) {
    call = 5;
    // 新三参入口：最短两条序言后检查mask，或先保存mount/inode/mask后检查。
    if (!nm_rule_entry_save(native[0]) || !nm_rule_entry_save(native[1]))
      return -EOPNOTSUPP;
    bool compact = inst_is_tbnz(native[2]) && inst_get_tbnz_rt(native[2]) == 2 && inst_get_tbnz_bit(native[2]) == 1
                   && inst_get_tbnz_label(native[2]) > 4;
    bool saved = nm_rule_entry_save(native[2]) && nm_rule_entry_save(native[3]) && nm_move32(native[4], 19, 2)
                 && nm_move(native[5], 20, 1) && nm_move(native[6], 8, 0) && inst_is_tbnz(native[7])
                 && inst_get_tbnz_rt(native[7]) == 2 && inst_get_tbnz_bit(native[7]) == 1
                 && inst_get_tbnz_label(native[7]) > 4;
    if (!compact && !saved)
      return -EOPNOTSUPP;
  } else if (nm_rule_entry_save(src[0]) && nm_move32(src[1], 2, 1) && nm_move(src[2], 3, 0)
             && nm_rule_entry_save(src[3]) && nm_load_at(src[4], 0, 0, struct_offset.inode_superblock)
             && inst_is_tbnz(src[5]) && inst_get_tbnz_rt(src[5]) == 2 && inst_get_tbnz_bit(src[5]) == 1
             && inst_get_tbnz_label(src[5]) > 4 && nm_zero64(src[6], 0) && nm_move(src[7], 1, 3) && inst_is_bl(src[8])
             && nm_rule_entry_save(native[0]) && nm_rule_entry_save(native[1])
             && nm_load_at(native[2], 3, 1, struct_offset.inode_superblock) && inst_is_tbnz(native[3])
             && inst_get_tbnz_rt(native[3]) == 2 && inst_get_tbnz_bit(native[3]) == 1) {
    call = 8;
    call_target = kallsyms_lookup_name_by_suffix("__inode_permission2");
    if (!call_target)
      return -ENOENT;
  } else
    return -EOPNOTSUPP;
  if (!nm_code_matches((uintptr_t)&src[call] + inst_get_bl_label(src[call]), call_target,
                       kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext")))
    return -EOPNOTSUPP;
  struct_offset.permission_abi = 0;
  return 0;
}

// generic_shutdown_super固定35／25条前缀；保存的sb／s_op跨原生BL保持在x19／x20。
static int nm_find_super_lifecycle_legacy(const uint32_t* src) {
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

// 新GCC/Clang入口：先证实sb/s_op的保存，再只接受不改写x19/x20的已核对前缀。
// 最长到PAC目标的第45条；不在整个函数内搜索回调加载。
static int nm_find_super_lifecycle(const uint32_t* src) {
  int old = nm_find_super_lifecycle_legacy(src);
  if (!old || old == -EINVAL)
    return old;
  unsigned int i = 0;
  while (i < 6 && nm_vfs_frame_save(src[i])) i++;
  int root;
  unsigned int root_branch;
  if (i == 3 && nm_move(src[i], 19, 0)) {
    if (!nm_load(src[i + 1], 3, 0) || inst_get_ldr_imm_rt(src[i + 1]) != 1
        || !nm_load_at(src[i + 2], 20, 0, offsetof(struct nm_super_head, s_op)))
      return -EOPNOTSUPP;
    root = 1;
    i += 3;
    if (!inst_is_cbz(src[i]) || !inst_get_cbz_sf(src[i]) || inst_get_cbz_rt(src[i]) != root
        || inst_get_cbz_label(src[i]) <= 72)
      return -EOPNOTSUPP;
    root_branch = i++;
  } else {
    if ((i != 3 && i != 5 && i != 6) || !nm_load(src[i], 3, 0) || inst_get_ldr_imm_rt(src[i]) != 8
        || !nm_move(src[i + 1], 19, 0) || !inst_is_cbz(src[i + 2]) || !inst_get_cbz_sf(src[i + 2])
        || inst_get_cbz_rt(src[i + 2]) != 8 || inst_get_cbz_label(src[i + 2]) <= 80
        || !nm_load_at(src[i + 3], 20, 19, offsetof(struct nm_super_head, s_op)))
      return -EOPNOTSUPP;
    root = 8;
    root_branch = i + 2;
    i += 4;
  }
  for (; i < 36; i++) {
    uint32_t inst = src[i];
    if (nm_load(inst, 3, 20)) {
      int cb = inst_get_ldr_imm_rt(inst);
      if ((cb != 1 && cb != 8) || !inst_is_cbz(src[i + 1]) || !inst_get_cbz_sf(src[i + 1])
          || inst_get_cbz_rt(src[i + 1]) != cb)
        return -EOPNOTSUPP;
      unsigned int call = i + 2;
      if (inst_is_adrp(src[call])) {
        // CFI仅扩展为目标实际使用的2/3位旋转，其余关系与旧门禁逐项相同。
        const uint32_t* gate = &src[call];
        uint32_t rotate = gate[3];
        int bits = inst_is_extr(rotate) ? inst_get_extr_imm6(rotate) : -1;
        uint32_t normalized[6];
        for (unsigned j = 0; j < 6; j++) normalized[j] = gate[j];
        normalized[3] = (rotate & ~(63U << 10)) | (2U << 10);
        if ((bits != 2 && bits != 3) || !nm_cfi_gate(normalized, cb, 9, 8))
          return -EOPNOTSUPP;
        call += 6;
      }
      if (call + 1 >= 45 || (int)root_branch * 4 + inst_get_cbz_label(src[root_branch]) <= (int)(call + 1) * 4
          || inst_get_cbz_label(src[i + 1]) <= (int)(call - i) * 4 || !nm_move(src[call], 0, 19)
          || !inst_is_blr(src[call + 1]) || inst_get_blr_rn(src[call + 1]) != cb)
        return -EOPNOTSUPP;
      int first = inst_get_ldr_imm_imm(inst) - (int)offsetof(struct nm_super_lifecycle_ops, put_super);
      if (first < 0 || first % 8 || first > 0x7fff - sizeof(struct nm_super_lifecycle_ops))
        return -EINVAL;
      struct_offset.sop_drop_inode = first + offsetof(struct nm_super_lifecycle_ops, drop_inode);
      struct_offset.sop_evict_inode = first + offsetof(struct nm_super_lifecycle_ops, evict_inode);
      return 0;
    }
    if (nm_move(inst, 0, 19) || inst_is_bl(inst))
      continue;
    if (nm_load(inst, 3, 19) && (inst_get_ldr_imm_rt(inst) == 0 || inst_get_ldr_imm_rt(inst) == root))
      continue;
    if (inst_is_and_imm(inst) && inst_get_and_imm_sf(inst) && inst_get_and_imm_rd(inst) == root
        && inst_get_and_imm_rn(inst) == root && inst_get_and_imm_imm(inst) == 0xffffffffbfffffffULL)
      continue;
    if (nm_store(inst, 3, 19) && inst_get_str_imm_rt(inst) == root)
      continue;
    if (i + 2 < 36 && inst_is_cbz(inst) && inst_get_cbz_sf(inst) && inst_get_cbz_rt(inst) == 0
        && inst_get_cbz_label(inst) == 12 && nm_load(src[i - 1], 3, 19) && inst_get_ldr_imm_rt(src[i - 1]) == 0
        && inst_is_bl(src[i + 1]) && nm_store_at(src[i + 2], 3, 31, 19, inst_get_ldr_imm_imm(src[i - 1]))) {
      i += 2;
      continue;
    }
    // Android静态键的两条条件调用：分支恰好跳过整个全局访问，不改动已保存对象。
    if (i + 7 < 36 && inst_is_adrp(inst) && inst_get_adrp_rd(inst) == 8 && inst_is_add_imm(src[i + 1])
        && inst_get_add_imm_sf(src[i + 1]) && inst_get_add_imm_rd(src[i + 1]) == 8
        && inst_get_add_imm_rn(src[i + 1]) == 8 && inst_is_ldar(src[i + 2]) && inst_get_ldar_size(src[i + 2]) == 2
        && inst_get_ldar_rt(src[i + 2]) == 8 && inst_get_ldar_rn(src[i + 2]) == 8 && inst_is_cbz(src[i + 3])
        && !inst_get_cbz_sf(src[i + 3]) && inst_get_cbz_rt(src[i + 3]) == 8 && inst_get_cbz_label(src[i + 3]) == 20
        && inst_is_bl(src[i + 4]) && inst_is_adrp(src[i + 5]) && inst_get_adrp_rd(src[i + 5]) == 8
        && nm_load(src[i + 6], 3, 8) && inst_get_ldr_imm_rt(src[i + 6]) == 0 && inst_is_bl(src[i + 7])) {
      i += 7;
      continue;
    }
    return -EOPNOTSUPP;
  }
  return -EOPNOTSUPP;
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

// 旧形态最坏读取27条（含CFI slowpath）；13／17／21仅是特定成功分支的消费长度。
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
  // 不匹配旧SUB入口时立即拒绝，不能为了判别旧CFI形态预读第21／25条。
  if (flag < 0)
    return -EOPNOTSUPP;
  int ops = nm_sub_from(src[11], 8, 0);
  if (ops < 0)
    return -EOPNOTSUPP;
  bool slowpath = inst_is_movk_imm(src[20]);
  int sb = slowpath ? nm_sub_from(src[24], 0, 19) : nm_sub_from(src[20], 22, 19);
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
  if (slowpath) {
    if (inst_get_movz_imm_hw(src[18]))
      return -EOPNOTSUPP;
    for (unsigned int i = 20; i < 23; i++) {
      if (!inst_is_movk_imm(src[i]) || !inst_get_movk_imm_sf(src[i]) || inst_get_movk_imm_rd(src[i]) != 0
          || inst_get_movk_imm_hw(src[i]) != i - 19)
        return -EOPNOTSUPP;
    }
    uintptr_t cfi = kallsyms_lookup_name_by_suffix("__cfi_slowpath");
    if (!cfi || !inst_is_bl(src[23]) || (uintptr_t)&src[23] + inst_get_bl_label(src[23]) != cfi
        || !nm_move(src[25], 1, 20) || !inst_is_blr(src[26]) || inst_get_blr_rn(src[26]) != 21)
      return -EOPNOTSUPP;
  }
  return inst_get_ldr_imm_imm(src[16]);
}

static int nm_find_set_acl_vfs(const uint32_t* src) {
  int old = nm_find_set_acl(src);
  if (old >= 0 || old == -EINVAL)
    return old;
  unsigned p = 0;
  while (p < 9 && nm_vfs_frame_save(src[p])) p++;
  int reg = inst_get_ldr_imm_rt(src[p]);
  bool gcc = reg == 3;
  if ((p != 4 && p != 5 && p != 9) || (reg != 3 && reg != 8)
      || !nm_load_at(src[p], reg, 0, struct_offset.inode_superblock) || !nm_load(src[p + 1], gcc ? 3 : 0, reg)
      || inst_get_ldr_imm_rt(src[p + 1]) != reg
      || inst_get_ldr_imm_imm(src[p + 1]) != (offsetof(struct nm_super_head, s_flags) + (gcc ? 0 : 2))
      || !inst_is_tbz(src[p + 2]) || inst_get_tbz_rt(src[p + 2]) != reg
      || inst_get_tbz_bit(src[p + 2]) != (gcc ? 16 : 0) || inst_get_tbz_label(src[p + 2]) <= 16
      || !nm_load_at(src[p + 3], reg, 0, struct_offset.inode_superblock - 8))
    return -EOPNOTSUPP;
  unsigned load = p + 4;
  if (!gcc) {
    if (!nm_move(src[load], 20, 0))
      return -EOPNOTSUPP;
    load++;
  }
  if (!nm_load(src[load], 3, reg) || inst_get_ldr_imm_rt(src[load]) != reg || !nm_forward_null(src[load + 1], reg))
    return -EOPNOTSUPP;
  return inst_get_ldr_imm_imm(src[load]);
}

static int nm_find_super_cache_vfs(const uint32_t* src) {
  int old = nm_find_super_cache(src);
  if (old >= 0 || old == -EINVAL)
    return old;
  if (inst_is_paciasp(src[0]))
    src++;
  if (nm_sub_from(src[1], 4, 0) > 0) {
    if (!nm_rule_entry_save(src[0]) || !nm_rule_entry_save(src[2]) || !nm_rule_entry_save(src[3])
        || !nm_rule_entry_save(src[4]) || !nm_move(src[5], 20, 1)
        || !nm_load_at(src[6], 3, 4, offsetof(struct nm_super_head, s_flags)) || !inst_is_and_imm(src[7])
        || !inst_get_and_imm_sf(src[7]) || inst_get_and_imm_rd(src[7]) != 2 || inst_get_and_imm_rn(src[7]) != 3
        || inst_get_and_imm_imm(src[7]) != 0x20000000 || !inst_is_tbz(src[8]) || inst_get_tbz_rt(src[8]) != 3
        || inst_get_tbz_bit(src[8]) != 29 || inst_get_tbz_label(src[8]) <= 32 || !nm_move(src[9], 21, 0)
        || !inst_is_dmb_ishld(src[10]) || !nm_load_at(src[11], 0, 4, offsetof(struct nm_super_head, s_op))
        || !nm_forward_null(src[12], 0) || !nm_load(src[13], 3, 0) || inst_get_ldr_imm_rt(src[13]) != 2
        || !nm_forward_null(src[14], 2) || !nm_move(src[15], 0, 4) || !inst_is_blr(src[16])
        || inst_get_blr_rn(src[16]) != 2)
      return -EOPNOTSUPP;
    return inst_get_ldr_imm_imm(src[13]);
  }
  unsigned p = 0;
  while (p < 5 && nm_vfs_frame_save(src[p])) p++;
  int flag = nm_sub_from(src[p], 8, 0), sb = nm_sub_from(src[p + 5], 20, 0);
  if ((p != 4 && p != 5) || flag <= 0 || sb - flag != offsetof(struct nm_super_head, s_flags) + 3
      || !nm_load(src[p + 1], 0, 8) || inst_get_ldr_imm_rt(src[p + 1]) != 8 || inst_get_ldr_imm_imm(src[p + 1])
      || !inst_is_tbnz(src[p + 2]) || inst_get_tbnz_rt(src[p + 2]) != 8 || inst_get_tbnz_bit(src[p + 2]) != 5
      || inst_get_tbnz_label(src[p + 2]) != 12 || !nm_zero64(src[p + 3], 0) || !inst_is_b(src[p + 4])
      || inst_get_b_label(src[p + 4]) <= 64 || !inst_is_dmb_ishld(src[p + 6]))
    return -EOPNOTSUPP;
  bool moved = nm_move(src[p + 7], 19, 1);
  if (moved ? !nm_load_at(src[p + 8], 8, 20, offsetof(struct nm_super_head, s_op))
            : (!nm_load_at(src[p + 7], 8, 20, offsetof(struct nm_super_head, s_op)) || !nm_move(src[p + 8], 19, 1)))
    return -EOPNOTSUPP;
  int cb = inst_get_ldr_imm_rt(src[p + 10]);
  if (!nm_forward_null(src[p + 9], 8) || !nm_load(src[p + 10], 3, 8) || (cb != 8 && cb != 21)
      || !nm_forward_null(src[p + 11], cb))
    return -EOPNOTSUPP;
  unsigned call = p + 12;
  if (cb == 21) {
    if (!inst_is_movz_imm(src[call]) || !inst_get_movz_imm_sf(src[call]) || inst_get_movz_imm_rd(src[call])
        || inst_get_movz_imm_hw(src[call]))
      return -EOPNOTSUPP;
    for (unsigned j = 1; j < 4; j++)
      if (!inst_is_movk_imm(src[call + j]) || !inst_get_movk_imm_sf(src[call + j])
          || inst_get_movk_imm_rd(src[call + j]) || inst_get_movk_imm_hw(src[call + j]) != j)
        return -EOPNOTSUPP;
    if (!nm_move(src[call + 4], 1, 21) || !inst_is_bl(src[call + 5])
        || (uintptr_t)&src[call + 5] + inst_get_bl_label(src[call + 5])
               != kallsyms_lookup_name_by_suffix("__cfi_slowpath"))
      return -EOPNOTSUPP;
    call += 6;
  } else if (inst_is_adrp(src[call])) {
    if (!nm_cfi_gate_stride(&src[call], 8, 9, 12))
      return -EOPNOTSUPP;
    call += 6;
  }
  if (!nm_move(src[call], 0, 20) || !nm_move(src[call + 1], 1, 19) || !inst_is_blr(src[call + 2])
      || inst_get_blr_rn(src[call + 2]) != cb || inst_get_cbz_label(src[p + 9]) <= (int)(call + 2 - p - 9) * 4
      || inst_get_cbz_label(src[p + 11]) <= (int)(call + 2 - p - 11) * 4)
    return -EOPNOTSUPP;
  return inst_get_ldr_imm_imm(src[p + 10]);
}

// list_lru_count_node在首5条（PAC为7条）按真正的node数组步长取最后nr_items。
// 已核对node的自然尾部止于48字节，唯一额外对齐来自SMP_CACHE_BYTES；只接64/128。
static int nm_find_operation_alignment(const uint32_t* src) {
  bool pac = inst_is_paciasp(src[0]);
  if (pac)
    src++;
  int shift, base;
  if (nm_load_at(src[0], 0, 0, 0)) {
    if (!inst_is_sbfm(src[1]) || !inst_get_sbfm_sf(src[1]) || !inst_get_sbfm_n(src[1]) || inst_get_sbfm_rd(src[1]) != 1
        || inst_get_sbfm_rn(src[1]) != 1 || inst_get_sbfm_imms(src[1]) != 31 || !inst_is_add_reg(src[2])
        || !inst_get_add_reg_sf(src[2]) || inst_get_add_reg_rd(src[2]) != 1 || inst_get_add_reg_rn(src[2])
        || inst_get_add_reg_rm(src[2]) != 1 || inst_get_add_reg_shift(src[2]) || inst_get_add_reg_imm6(src[2]))
      return -EOPNOTSUPP;
    shift = 64 - inst_get_sbfm_immr(src[1]);
    base = 1;
  } else {
    if (!nm_load_at(src[0], 8, 0, 0) || !inst_is_sbfm(src[1]) || !inst_get_sbfm_sf(src[1]) || !inst_get_sbfm_n(src[1])
        || inst_get_sbfm_rd(src[1]) != 9 || inst_get_sbfm_rn(src[1]) != 1 || inst_get_sbfm_immr(src[1])
        || inst_get_sbfm_imms(src[1]) != 31 || !inst_is_add_reg(src[2]) || !inst_get_add_reg_sf(src[2])
        || inst_get_add_reg_rd(src[2]) != 8 || inst_get_add_reg_rn(src[2]) != 8 || inst_get_add_reg_rm(src[2]) != 9
        || inst_get_add_reg_shift(src[2]))
      return -EOPNOTSUPP;
    shift = inst_get_add_reg_imm6(src[2]);
    base = 8;
  }
  if ((shift != 6 && shift != 7) || !nm_load_at(src[3], 0, base, offsetof(struct nm_list_lru_node_members, nr_items))
      || (pac && !inst_is_autiasp(src[4])) || !inst_is_ret(src[pac ? 5 : 4]) || inst_get_ret_rn(src[pac ? 5 : 4]) != 30)
    return -EOPNOTSUPP;
  return 1U << shift;
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

// d_set_d_op逐项确认所有前置DCACHE_OP标志，再取DCACHE_OP_REAL的加载槽；最长47条。
static int nm_find_dentry_real(const uint32_t* src) {
  bool pac = inst_is_paciasp(src[0]);
  if (pac)
    src++;
  bool gcc = nm_load_at(src[0], 2, 0, struct_offset.dentry_ops);
  int flag = gcc ? 2 : 8, mask = gcc ? 3 : 9;
  if (!nm_load_at(src[0], flag, 0, struct_offset.dentry_ops) || !inst_is_cbnz(src[1]) || !inst_get_cbnz_sf(src[1])
      || inst_get_cbnz_rt(src[1]) != flag || inst_get_cbnz_label(src[1]) <= 160 || !nm_load(src[2], 2, 0)
      || inst_get_ldr_imm_rt(src[2]) != flag || inst_get_ldr_imm_imm(src[2]) || !nm_movz_value(src[3], 0, mask, 0x80f)
      || !inst_is_movk_imm(src[4]) || inst_get_movk_imm_sf(src[4]) || inst_get_movk_imm_rd(src[4]) != mask
      || inst_get_movk_imm_hw(src[4]) != 1 || inst_get_movk_imm_imm16(src[4]) != 0x400 || !inst_is_ands_reg(src[5])
      || inst_get_ands_reg_sf(src[5]) || inst_get_ands_reg_rd(src[5]) != 31 || inst_get_ands_reg_rn(src[5]) != flag
      || inst_get_ands_reg_rm(src[5]) != mask || inst_get_ands_reg_shift(src[5]) || inst_get_ands_reg_imm6(src[5])
      || !inst_is_b_cond(src[6]) || inst_get_b_cond_cond(src[6]) != 1 || inst_get_b_cond_label(src[6]) <= 144
      || !nm_store_at(src[7], 3, 1, 0, struct_offset.dentry_ops) || !nm_forward_null(src[8], 1))
    return -EOPNOTSUPP;
  const int slots[] = {
      offsetof(struct nm_dentry_control_ops, d_hash),       offsetof(struct nm_dentry_control_ops, d_compare),
      offsetof(struct nm_dentry_control_ops, d_revalidate), offsetof(struct nm_dentry_control_ops, d_weak_revalidate),
      offsetof(struct nm_dentry_control_ops, d_delete),     -1};
  const unsigned flags[] = {1, 2, 4, 0x800, 8, 0x10, 0x4000000};
  unsigned at = 9;
  int real = -1;
  for (unsigned j = 0; j < 7; j++) {
    if (!nm_load(src[at], 3, 1))
      return -EOPNOTSUPP;
    int cb = inst_get_ldr_imm_rt(src[at]), slot = inst_get_ldr_imm_imm(src[at]);
    if (j < 6
        && slot
               != (j == 5 ? struct_offset.dop_release + (int)offsetof(struct nm_dentry_release_prune, d_prune)
                          : slots[j]))
      return -EOPNOTSUPP;
    if (j == 6)
      real = slot;
    if (!nm_forward_null(src[at + 1], cb))
      return -EOPNOTSUPP;
    unsigned branch = at + 1;
    at += 2;
    if (!(gcc && j == 0)) {
      if (!nm_load(src[at], 2, 0) || inst_get_ldr_imm_imm(src[at]))
        return -EOPNOTSUPP;
      flag = inst_get_ldr_imm_rt(src[at++]);
    }
    if (!inst_is_orr_imm(src[at]) || inst_get_orr_imm_sf(src[at]) || inst_get_orr_imm_rd(src[at]) != flag
        || inst_get_orr_imm_rn(src[at]) != flag || inst_get_orr_imm_imm(src[at]) != flags[j]
        || !nm_store_at(src[at + 1], 2, flag, 0, 0))
      return -EOPNOTSUPP;
    at += 2;
    if (inst_get_cbz_label(src[branch]) != (int)(at - branch) * 4)
      return -EOPNOTSUPP;
  }
  if (inst_get_cbz_label(src[8]) != (int)(at - 8) * 4 || (pac && !inst_is_autiasp(src[at]))
      || !inst_is_ret(src[at + pac]) || inst_get_ret_rn(src[at + pac]) != 30 || real < 0 || real % 8)
    return -EOPNOTSUPP;
  return real;
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

// d_real只用于无sdcardfs路径。整套契约与原canonical路径分开，禁止跨声明拼接。
// 该几何只覆盖已离线核对的声明，不能证明未知厂商没有额外尾部（AUD-001）。
static int nm_set_operation_extents_real(int acl, int cache, int real) {
  struct nm_operation_geometry {
    int acl_from_getattr;
    int cache_from_drop;
    int real_from_release;
    int init;
    int release;
    int evict_from_drop;
  } actual = {acl - struct_offset.iop_getattr,  cache - struct_offset.sop_drop_inode,
              real - struct_offset.dop_release, struct_offset.dop_init,
              struct_offset.dop_release,        struct_offset.sop_evict_inode - struct_offset.sop_drop_inode},
    expected = {offsetof(struct nm_inode_acl_tail, set_acl),
                offsetof(struct nm_super_context_no_umount_end_tail, reporting.cache),
                offsetof(struct nm_dentry_real_reserved_tail, real),
                sizeof(struct nm_dentry_control_ops),
                sizeof(struct nm_dentry_control_ops) + sizeof(void*),
                sizeof(void*)};
  if (acl < 0 || cache < 0 || real < 0 || actual.acl_from_getattr != expected.acl_from_getattr
      || actual.cache_from_drop != expected.cache_from_drop || actual.real_from_release != expected.real_from_release
      || actual.init != expected.init || actual.release != expected.release
      || actual.evict_from_drop != expected.evict_from_drop)
    return -EOPNOTSUPP;
  int inode = nm_tail_extent(struct_offset.iop_getattr, sizeof(struct nm_inode_acl_tail), 64);
  int super = nm_tail_extent(struct_offset.sop_drop_inode, sizeof(struct nm_super_context_no_umount_end_tail), 8);
  int dentry = nm_tail_extent(struct_offset.dop_release, sizeof(struct nm_dentry_real_reserved_tail), 64);
  if (inode < 0 || super < 0 || dentry < 0)
    return -EINVAL;
  struct_offset.inode_ops_size = inode;
  struct_offset.super_ops_size = super;
  struct_offset.dentry_ops_size = dentry;
  return 0;
}

static int calculate_function_operation_sizes(void) {
  nm_operation_anchor = NM_OPERATION_ANCHOR_NONE;
  const uint32_t* acl = (const void*)kallsyms_lookup_name_by_suffix("set_posix_acl");
  const uint32_t* count = (const void*)kallsyms_lookup_name_by_suffix("super_cache_count");
  const uintptr_t* dops = (const void*)kallsyms_lookup_name_by_suffix("sdcardfs_ci_dops");
  uintptr_t canonical = kallsyms_lookup_name_by_suffix("sdcardfs_canonical_path");
  if (!acl || !count || (!!dops != !!canonical))
    return -ENOENT;
  const uint32_t* real = NULL;
  if (!dops && !canonical) {
    real = (const void*)kallsyms_lookup_name_by_suffix("d_set_d_op");
    if (!real)
      return -ENOENT;
  }
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
  int last_acl = nm_find_set_acl_vfs(acl);
  int last_cache = nm_find_super_cache_vfs(count);
  if (last_acl < 0 || last_cache < 0)
    return last_acl < 0 ? last_acl : last_cache;
  // 新VFS形态还需原生node步长确认64字节类型对齐，不能将128字节目标套入旧尾部。
  // 旧识别器已支持的声明保持原入口契约，不增加新的符号前提。
  if (nm_find_set_acl(acl) < 0 || nm_find_super_cache(count) < 0) {
    const uint32_t* alignment = (const void*)kallsyms_lookup_name_by_suffix("list_lru_count_node");
    if (!alignment)
      return -ENOENT;
    if (nm_find_operation_alignment(alignment) != 64)
      return -EOPNOTSUPP;
  }
  if (dops) {
    nm_operation_anchor = NM_OPERATION_ANCHOR_SDCARDFS;
    nm_log_info("layout: operation anchor=sdcardfs\n");
    int last_canonical =
        nm_find_dentry_canonical(dops, canonical, kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
    if (last_canonical < 0)
      return last_canonical;
    rc = nm_set_operation_extents(last_acl, last_cache, last_canonical);
  } else {
    nm_operation_anchor = NM_OPERATION_ANCHOR_D_REAL;
    nm_log_info("layout: operation anchor=d_set_d_op\n");
    int last_real = nm_find_dentry_real(real);
    if (last_real < 0)
      return last_real;
    rc = nm_set_operation_extents_real(last_acl, last_cache, last_real);
  }
  if (!rc)
    nm_log_info("layout: operation extents inode/super/dentry=%d/%d/%d\n", struct_offset.inode_ops_size,
                struct_offset.super_ops_size, struct_offset.dentry_ops_size);
  return rc;
}

// 源锁锚点：固定前缀内证明 entry dentry→inode→ADD→成对helper。
// 只处理前向分支；合流取来源交集，未知写寄存器指令和回边均拒绝。
struct nm_inode_lock_flow {
  uint32_t dentry, inode;
  int phase;
  bool reached, branch;
};

static int nm_inode_lock_merge(struct nm_inode_lock_flow* to, struct nm_inode_lock_flow from, bool branch) {
  if (to->reached) {
    if (to->phase != from.phase)
      return -EINVAL;
    to->dentry &= from.dentry;
    to->inode &= from.inode;
  } else {
    to->dentry = from.dentry;
    to->inode = from.inode;
    to->phase = from.phase;
    to->reached = true;
  }
  to->branch |= branch;
  return 0;
}

// 仅归一化核心代码区内的 BTI C + 单条直接B；不追未知veneer。
static uintptr_t nm_inode_lock_body(uintptr_t at, uintptr_t start, uintptr_t end) {
  if (!at || at % 4 || !start || end <= start || end - start < 8 || at < start || at > end - 8)
    return 0;
  const uint32_t* src = (const void*)at;
  unsigned int i = inst_is_bti_c(src[0]) ? 1 : 0;
  if (inst_is_b(src[i])) {
    at += i * 4 + inst_get_b_label(src[i]);
    if (at % 4 || at < start || at > end - 8)
      return 0;
    const uint32_t* body = (const void*)at;
    if (inst_is_b(body[0]) || (inst_is_bti_c(body[0]) && inst_is_b(body[1])))
      return 0;
  }
  return at;
}

static int nm_find_inode_lock(const uint32_t* src, unsigned int count, int dentry_arg, const uintptr_t helpers[4],
                              uintptr_t start, uintptr_t end, int* kind) {
  if (!src || !count || count > 43 || dentry_arg < 0 || dentry_arg > 1)
    return -EINVAL;
  struct nm_inode_lock_flow flow[44];
  memset(flow, 0, sizeof(flow));
  flow[0] = (struct nm_inode_lock_flow){.dentry = 1U << dentry_arg, .reached = true};
  int offset = -1, selected = -1, calls = 0;
  for (unsigned int i = 0; i < count; i++) {
    if (!flow[i].reached)
      continue;
    struct nm_inode_lock_flow next = flow[i];
    uint32_t inst = src[i], written = 0, dent = 0, inode = 0;
    int rd = -1, delta = 0;
    bool branch = true, conditional = true;
    if (inst_is_b(inst)) {
      delta = inst_get_b_label(inst);
      conditional = false;
    } else if (inst_is_b_cond(inst))
      delta = inst_get_b_cond_label(inst);
    else if (inst_is_cbz(inst))
      delta = inst_get_cbz_label(inst);
    else if (inst_is_cbnz(inst))
      delta = inst_get_cbnz_label(inst);
    else if (inst_is_tbz(inst))
      delta = inst_get_tbz_label(inst);
    else if (inst_is_tbnz(inst))
      delta = inst_get_tbnz_label(inst);
    else
      branch = false;
    if (branch) {
      if (delta <= 0 || delta % 4)
        return -EOPNOTSUPP;
      unsigned int target = i + delta / 4;
      if (target < count && nm_inode_lock_merge(&flow[target], next, true))
        return -EINVAL;
      if (!conditional)
        continue;
    } else if (inst_is_bl(inst)) {
      uintptr_t target = nm_inode_lock_body((uintptr_t)&src[i] + inst_get_bl_label(inst), start, end);
      if (!target)
        return -EOPNOTSUPP;
      for (int h = 0; h < 4; h++) {
        if (!helpers[h] || target != helpers[h])
          continue;
        // 入参只接受紧邻ADD；跳入BL会绕过定义，必须拒绝。
        if (!i || flow[i].branch || !inst_is_add_imm(src[i - 1]) || !inst_get_add_imm_sf(src[i - 1])
            || inst_get_add_imm_sh(src[i - 1]) || inst_get_add_imm_rd(src[i - 1]) != 0
            || !(flow[i - 1].inode & (1U << inst_get_add_imm_rn(src[i - 1]))))
          return -EOPNOTSUPP;
        int value = inst_get_add_imm_imm(src[i - 1]);
        if (value < 0 || value > 0x7fff || value % 8 || (offset >= 0 && offset != value)
            || (selected >= 0 && selected != h / 2) || next.phase != (h % 2))
          return -EINVAL;
        offset = value;
        selected = h / 2;
        next.phase++;
        calls++;
      }
      written = 0x4007ffffU;  // AAPCS64：x0..x18、LR不跨调用保留。
    } else if (inst_is_mov_reg(inst)) {
      rd = inst_get_mov_reg_rd(inst);
      int rm = inst_get_mov_reg_rm(inst);
      if (inst_get_mov_reg_sf(inst) && rm != 31) {
        dent = (next.dentry >> rm) & 1U;
        inode = (next.inode >> rm) & 1U;
      }
    } else if (inst_is_ldr_imm(inst) && !bit(inst, 26) && inst_get_ldr_imm_opc(inst) == 1) {
      rd = inst_get_ldr_imm_rt(inst);
      int rn = inst_get_ldr_imm_rn(inst);
      inode = inst_get_ldr_imm_size(inst) == 3 && rn != 31 && (next.dentry & (1U << rn))
              && inst_get_ldr_imm_imm(inst) == offsetof(struct nm_dentry_head, d_inode);
    } else if (inst_is_str_imm(inst)) {
      // 无写回，不改变GP来源。
    } else if (inst_is_str_imm9(inst)) {
      if (inst_get_str_imm9_mode(inst) & 1)
        written = 1U << inst_get_str_imm9_rn(inst);
    } else if (inst_is_stp(inst)) {
      if (inst_get_stp_mode(inst) == 1 || inst_get_stp_mode(inst) == 3)
        written = 1U << inst_get_stp_rn(inst);
    } else if (inst_is_add_imm(inst) || inst_is_sub_imm(inst) || inst_is_orr_imm(inst) || inst_is_adrp(inst)
               || inst_is_movz_imm(inst) || inst_is_orr_reg(inst)) {
      // 这些指令的目的寄存器均在低5位；只MOV保留对象来源。
      rd = bits32(inst, 4, 0);
    } else if (inst_is_paciasp(inst) || inst_is_bti_c(inst)) {
      written = 1U << 30;
    } else {
      return -EOPNOTSUPP;
    }
    if (rd >= 0) {
      written |= 1U << rd;
      next.dentry = (next.dentry & ~written) | (dent << rd);
      next.inode = (next.inode & ~written) | (inode << rd);
    } else {
      next.dentry &= ~written;
      next.inode &= ~written;
    }
    next.dentry &= 0x7fffffffU;
    next.inode &= 0x7fffffffU;
    if (nm_inode_lock_merge(&flow[i + 1], next, false))
      return -EINVAL;
  }
  if (calls != 2 || selected < 0)
    return -ENOENT;
  *kind = selected + 1;
  return offset;
}

static int calculate_function_setattr(struct nm_setattr_layout* layout, int slot) {
  // 当前前缀只确认plain/Android dentry入口；mapped接口由BTF确认。
  if (struct_offset.getattr_context_kind || (struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const char* names[] = {"down_write", "up_write", "mutex_lock", "mutex_unlock"};
  uintptr_t helpers[4];
  for (unsigned int i = 0; i < 4; i++)
    helpers[i] = nm_inode_lock_body(kallsyms_lookup_name_by_suffix(names[i]), start, end);
  for (unsigned int i = 0; i < 4; i++)
    for (unsigned int j = i + 1; j < 4; j++)
      if (helpers[i] && helpers[i] == helpers[j])
        return -EINVAL;
  const char* sources[] = {"vfs_setxattr", "vfs_removexattr", "do_truncate2"};
  // removexattr的已确认解锁最晚位于索引28，必须包含该BL而非仅含前置ADD。
  const unsigned int windows[] = {36, 29, 43};
  uintptr_t bodies[3] = {0};
  int offset = -1, kind = 0, found = 0;
  for (unsigned int i = 0; i < 3; i++) {
    uintptr_t at = kallsyms_lookup_name_by_suffix(sources[i]);
    if (!at)
      continue;
    at = nm_inode_lock_body(at, start, end);
    if (!at || end - at < windows[i] * 4)
      return -EOPNOTSUPP;
    for (unsigned int j = 0; j < i; j++)
      if (bodies[j] == at)
        return -EINVAL;  // 同一函数体别名不能算第二个来源。
    bodies[i] = at;
    int current_kind = 0;
    int current = nm_find_inode_lock((const void*)at, windows[i], i == 2 ? 1 : 0, helpers, start, end, &current_kind);
    nm_log_info("layout: inode lock source=%s offset=%d kind=%d\n", sources[i], current, current_kind);
    if (current < 0)
      return current;
    if (offset >= 0 && (offset != current || kind != current_kind))
      return -EINVAL;
    offset = current;
    kind = current_kind;
    found++;
  }
  if (found < 2 || !helpers[(kind - 1) * 2] || !helpers[(kind - 1) * 2 + 1])
    return -ENOENT;
  *layout = (struct nm_setattr_layout){offset, kind, slot, 0};
  return 0;
}

#endif

#ifndef CONFIG_KPM_BASELINES
#include "nm_xattr_signature.c"
#include "nm_xattr_entry_signatures.c"
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
    if (!rc && nm_owned_operation_fallback) {
      rc = calculate_function_key_type_size();
      // 保留既有自建容量契约；新增推导尚未覆盖的入口不改变其它目标的加载行为。
      // 已识别的跨锚点冲突或非法范围不能以容量掩盖。
      if (rc == -ENOENT || rc == -EOPNOTSUPP) {
        if (nm_owned_operation_size(NM_KEY_TYPE) == -E2BIG)
          return -E2BIG;
        nm_log_info("layout: key_type tail not covered (%d); retaining owned zero-table capacity\n", rc);
        rc = 0;
      }
    }
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
