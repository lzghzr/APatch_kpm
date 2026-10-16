/* SPDX-License-Identifier: GPL-2.0-or-later */
static struct btf* kfunc_def(bpf_get_btf_vmlinux)(void);
static int kfunc_def(btf_find_by_name_kind)(const struct btf*, const char*, u8);
static const struct btf_type* kfunc_def(btf_type_by_id)(const struct btf*, u32);
static const char* kfunc_def(btf_name_by_offset)(const struct btf*, u32);
static const struct btf_type* kfunc_def(btf_resolve_size)(const struct btf*, const struct btf_type*, u32*);
static int nm_btf_function(const struct kpm_btf* btf, const char* name, const u8* args, unsigned int count,
                           unsigned int result_size);

static int nm_get_btf(struct kpm_btf* result, bool* unavailable) {
  *unavailable = false;
  kfunc_lookup_name(bpf_get_btf_vmlinux);
  kfunc_lookup_name(btf_find_by_name_kind);
  kfunc_lookup_name(btf_type_by_id);
  kfunc_lookup_name(btf_name_by_offset);
  kfunc_lookup_name(btf_resolve_size);
  if (!kfunc(bpf_get_btf_vmlinux) || !kfunc(btf_find_by_name_kind) || !kfunc(btf_type_by_id)
      || !kfunc(btf_name_by_offset) || !kfunc(btf_resolve_size)) {
    *unavailable = true;
    return -ENODATA;
  }
  const struct btf* data = kfunc(bpf_get_btf_vmlinux)();
  if (IS_ERR(data))
    return PTR_ERR(data);
  if (!data) {
    *unavailable = true;
    return -ENODATA;
  }
  *result = (struct kpm_btf){data, kfunc(btf_find_by_name_kind), kfunc(btf_type_by_id), kfunc(btf_name_by_offset),
                             kfunc(btf_resolve_size)};
  return 0;
}

static int calculate_btf_offsets(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* file = kpm_btf_type(&btf, "file", 4);
  const struct btf_type* inode = kpm_btf_type(&btf, "inode", 4);
  const struct btf_type* dentry = kpm_btf_type(&btf, "dentry", 4);
  const struct btf_type* ops = kpm_btf_type(&btf, "file_operations", 4);
  if (!file || !inode || !dentry || !ops)
    return -ENOENT;
  int objects = kpm_btf_offset(&btf, file, "f_inode", 8);
  if (objects < 0 || objects > 0x7fff
      || kpm_btf_offset(&btf, file, "f_op", 8) != objects + offsetof(struct nm_file_inode_ops, f_op)
      || kpm_btf_offset(&btf, ops, "owner", 8) != offsetof(struct nm_file_ops_head, owner)
      || kpm_btf_offset(&btf, ops, "llseek", 8) != offsetof(struct nm_file_ops_head, llseek)
      || kpm_btf_offset(&btf, inode, "i_mode", 2) != offsetof(struct nm_inode_owner_prefix, i_mode)
      || kpm_btf_offset(&btf, inode, "i_uid", 4) != offsetof(struct nm_inode_owner_prefix, i_uid)
      || kpm_btf_offset(&btf, inode, "i_gid", 4) != offsetof(struct nm_inode_owner_prefix, i_gid))
    return -EINVAL;
  struct_offset.file_inode_ops = objects;
  int mapping = kpm_btf_offset(&btf, file, "f_mapping", 8);
  int sb = kpm_btf_offset(&btf, inode, "i_sb", 8);
  int number = kpm_btf_offset(&btf, inode, "i_ino", 8);
  int nlink = kpm_btf_offset(&btf, inode, "i_nlink", 4);
  int size = kpm_btf_offset(&btf, inode, "i_size", 8);
  int dop = kpm_btf_offset(&btf, dentry, "d_op", 8);
  if (mapping < 0 || sb < 0 || number < 0 || nlink < 0 || size < 0 || dop < 0 || mapping > 0x7fff || sb > 0x7fff
      || number > 0x7fff || nlink > 0x7fff || size > 0x7fff || dop > 0x7fff)
    return -EINVAL;
  struct_offset.file_mapping = mapping;
  struct_offset.inode_superblock = sb;
  struct_offset.inode_number = number;
  struct_offset.inode_nlink = nlink;
  struct_offset.inode_size = size;
  struct_offset.dentry_ops = dop;
  nm_log_info("layout: BTF objects=%d mapping=%d sb=%d ino=%d nlink=%d size=%d d_op=%d\n", objects, mapping, sb, number,
              nlink, size, dop);
  return 0;
}

static int calculate_btf_operation_sizes(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const char* names[] = {"file_operations", "inode_operations", "super_operations", "dentry_operations", "key_type"};
  volatile int16_t* sizes[] = {&struct_offset.file_ops_size, &struct_offset.inode_ops_size,
                               &struct_offset.super_ops_size, &struct_offset.dentry_ops_size,
                               &struct_offset.key_type_size};
  for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    const struct btf_type* type = kpm_btf_type(&btf, names[i], 4);
    if (!type)
      return -ENOENT;
    if (!type->size || type->size > 4096 || type->size % 8)
      return -EINVAL;
    *sizes[i] = type->size;
    nm_log_info("%s size=%d\n", names[i], *sizes[i]);
  }
  return 0;
}

static int calculate_btf_rule_prefixes(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* path = kpm_btf_type(&btf, "path", 4);
  const struct btf_type* dentry = kpm_btf_type(&btf, "dentry", 4);
  if (!path || !dentry)
    return -ENOENT;
  if (path->size != sizeof(struct nm_path) || kpm_btf_offset(&btf, path, "mnt", 8) != offsetof(struct nm_path, mnt)
      || kpm_btf_offset(&btf, path, "dentry", 8) != offsetof(struct nm_path, dentry)
      || kpm_btf_offset(&btf, dentry, "d_inode", 8) != offsetof(struct nm_dentry_head, d_inode))
    return -EINVAL;
  const u8 salted_hash[] = {0x88, 0x88, 4}, pair_hash[] = {0x88, 4};
  int hash = nm_btf_function(&btf, "full_name_hash", salted_hash, 3, 4);
  int count = 3;
  if (hash == -EOPNOTSUPP) {
    hash = nm_btf_function(&btf, "full_name_hash", pair_hash, 2, 4);
    count = 2;
  }
  if (hash)
    return hash;
  struct_offset.name_hash_args = count;
  return 0;
}

// spec 的高位表示指针，其余位为宽度；检查实际调用所需的参数寄存器 ABI。
static int nm_btf_prototype(const struct kpm_btf* btf, const struct btf_type* proto, const u8* spec, unsigned int count,
                            unsigned int result_size) {
  if (!proto || ((proto->info >> 24) & 31) != 13 || (proto->info & 0xffff) != count)
    return -EOPNOTSUPP;
  const struct btf_param* params = (const void*)(proto + 1);
  for (unsigned int i = 0; i <= count; i++) {
    if (i == count && !result_size) {
      if (proto->size)
        return -EOPNOTSUPP;
      continue;
    }
    u32 size = 0;
    const struct btf_type* type = btf->type_by_id(btf->data, i == count ? proto->size : params[i].type);
    type = type ? btf->resolve_size(btf->data, type, &size) : NULL;
    u8 expected = i == count ? result_size : spec[i];
    unsigned int kind = type && !IS_ERR(type) ? (type->info >> 24) & 31 : 0;
    if (!type || IS_ERR(type) || size != (expected & 0x7f) || (expected & 0x80 ? kind != 2 : kind != 1 && kind != 6))
      return -EOPNOTSUPP;
  }
  return 0;
}
static int nm_btf_callback(const struct kpm_btf* btf, const struct btf_type* table, const char* name, const u8* spec,
                           unsigned int count, unsigned int result_size) {
  struct kpm_btf_field field;
  int rc = kpm_btf_member(btf, table, name, &field, 0);
  if (rc)
    return rc;
  if (field.bits || field.size != 8 || ((field.type->info >> 24) & 31) != 2)
    return -EINVAL;
  rc = nm_btf_prototype(btf, btf->type_by_id(btf->data, field.type->size), spec, count, result_size);
  return rc ? rc : kpm_btf_offset(btf, table, name, 8);
}

static int calculate_btf_file_offsets(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* file = kpm_btf_type(&btf, "file", 4);
  const struct btf_type* inode = kpm_btf_type(&btf, "inode", 4);
  const struct btf_type* ops = kpm_btf_type(&btf, "file_operations", 4);
  const struct btf_type* iocb = kpm_btf_type(&btf, "kiocb", 4);
  if (!file || !inode || !ops || !iocb)
    return -ENOENT;
  // 已核对跨版本共同片段，直接访问；这里拒绝启用重排后不匹配的布局。
  if (kpm_btf_offset(&btf, iocb, "ki_filp", 8) != offsetof(struct nm_kiocb_head, ki_filp)
      || kpm_btf_offset(&btf, iocb, "ki_pos", 8) != offsetof(struct nm_kiocb_head, ki_pos)
      || kpm_btf_offset(&btf, iocb, "ki_complete", 8) != offsetof(struct nm_kiocb_head, ki_complete)
      || kpm_btf_offset(&btf, inode, "i_flags", 4) != offsetof(struct nm_inode_owner_prefix, i_flags))
    return -EINVAL;
  const char* common[] = {"owner", "llseek", "read", "write", "read_iter", "write_iter"};
  for (unsigned int i = 0; i < sizeof(common) / sizeof(common[0]); i++)
    if (kpm_btf_offset(&btf, ops, common[i], 8) != i * 8)
      return -EINVAL;
  struct struct_offset next = struct_offset;
  const char* fields[] = {"private_data", "f_pos", "f_flags", "f_cred"};
  int16_t* destinations[] = {&next.file_private, &next.file_position, &next.file_flags, &next.file_cred};
  for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    int offset = kpm_btf_offset(&btf, file, fields[i], i == 2 ? 4 : 8);
    if (offset < 0 || offset > 0x7fff)
      return -EINVAL;
    *destinations[i] = offset;
  }
  if (kpm_btf_offset(&btf, file, "f_mode", 4) != next.file_flags + offsetof(struct nm_file_flags_mode, f_mode))
    return -EINVAL;
  int private = kpm_btf_offset(&btf, inode, "i_private", 8);
  if (private < 0 || private > 0x7fff)
    return -EINVAL;
  next.inode_private = private;
  const u8 two_ptrs[] = {0x88, 0x88}, seek[] = {0x88, 8, 4}, splice[] = {0x88, 0x88, 0x88, 8, 4};
  const char* callbacks[] = {"llseek", "read_iter", "open", "release", "mmap", "splice_read"};
  int16_t* slots[] = {NULL, NULL, &next.fop_open, &next.fop_release, &next.fop_mmap, &next.fop_splice_read};
  for (unsigned int i = 0; i < sizeof(callbacks) / sizeof(callbacks[0]); i++) {
    const u8* spec = i == 0 ? seek : i < 5 ? two_ptrs : splice;
    unsigned int count = i == 0 ? 3 : i < 5 ? 2 : 5;
    int offset = nm_btf_callback(&btf, ops, callbacks[i], spec, count, i >= 2 && i <= 4 ? 4 : 8);
    if (offset < 0 || offset > 0x7fff)
      return offset < 0 ? offset : -EINVAL;
    if (slots[i])
      *slots[i] = offset;
  }
  if (!ops->size || ops->size > 0x7fff)
    return -EINVAL;
  next.file_ops_size = ops->size;
  struct_offset = next;
  return 0;
}

// 参数数目与宽度相同仍可能是不同对象；核对实际指针指向的命名类型。
static int nm_btf_named_parameter(const struct kpm_btf* btf, const struct btf_type* proto, unsigned int index,
                                  const char* name) {
  if (!proto || ((proto->info >> 24) & 31) != 13 || index >= (proto->info & 0xffff))
    return -EOPNOTSUPP;
  const struct btf_param* params = (const void*)(proto + 1);
  u32 size = 0;
  const struct btf_type* pointer = btf->type_by_id(btf->data, params[index].type);
  pointer = pointer ? btf->resolve_size(btf->data, pointer, &size) : NULL;
  if (!pointer || IS_ERR(pointer) || ((pointer->info >> 24) & 31) != 2 || size != 8)
    return -EOPNOTSUPP;
  const struct btf_type* type = btf->type_by_id(btf->data, pointer->size);
  type = type ? btf->resolve_size(btf->data, type, &size) : NULL;
  const struct btf_type* expected = kpm_btf_type(btf, name, 4);
  return type && !IS_ERR(type) && type == expected ? 0 : -EOPNOTSUPP;
}

static const struct btf_type* nm_btf_callback_prototype(const struct kpm_btf* btf, const struct btf_type* table,
                                                        const char* name) {
  struct kpm_btf_field field;
  if (kpm_btf_member(btf, table, name, &field, 0) || ((field.type->info >> 24) & 31) != 2)
    return NULL;
  return btf->type_by_id(btf->data, field.type->size);
}

static int nm_btf_context_kind(const struct kpm_btf* btf, const struct btf_type* proto) {
  if (!nm_btf_named_parameter(btf, proto, 0, "user_namespace"))
    return 1;
  if (!nm_btf_named_parameter(btf, proto, 0, "mnt_idmap"))
    return 2;
  return -EOPNOTSUPP;
}

static int calculate_btf_inode_offsets(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* inode = kpm_btf_type(&btf, "inode", 4);
  const struct btf_type* sb = kpm_btf_type(&btf, "super_block", 4);
  const struct btf_type* data = kpm_btf_type(&btf, "address_space", 4);
  const struct btf_type* iops = kpm_btf_type(&btf, "inode_operations", 4);
  const struct btf_type* sops = kpm_btf_type(&btf, "super_operations", 4);
  const struct btf_type* stat = kpm_btf_type(&btf, "kstat", 4);
  if (!inode || !sb || !data || !iops || !sops || !stat)
    return -ENOENT;
  struct struct_offset next = struct_offset;
  if (kpm_btf_offset(&btf, inode, "i_op", 8) != next.inode_superblock - 8
      || kpm_btf_offset(&btf, inode, "i_mapping", 8) != next.inode_superblock + 8
      || kpm_btf_offset(&btf, inode, "i_opflags", 2) != offsetof(struct nm_inode_owner_prefix, i_opflags))
    return -EINVAL;
  const char* super_fields[] = {"s_dev", "s_blocksize_bits", "s_blocksize", "s_maxbytes", "s_type", "s_op"};
  const int super_positions[] = {
      offsetof(struct nm_super_head, s_dev),       offsetof(struct nm_super_head, s_blocksize_bits),
      offsetof(struct nm_super_head, s_blocksize), offsetof(struct nm_super_head, s_maxbytes),
      offsetof(struct nm_super_head, s_type),      offsetof(struct nm_super_head, s_op)};
  for (unsigned int i = 0; i < sizeof(super_fields) / sizeof(super_fields[0]); i++)
    if (kpm_btf_offset(&btf, sb, super_fields[i], i == 0 ? 4 : i == 1 ? 1 : 8) != super_positions[i])
      return -EINVAL;
  const char* times[] = {"i_atime", "i_mtime", "i_ctime"};
  for (unsigned int i = 0; i < 3; i++) {
    int offset = kpm_btf_offset(&btf, inode, times[i], sizeof(struct nm_timespec));
    if (i == 2 && offset == -ENOENT)
      offset = kpm_btf_offset(&btf, inode, "__i_ctime", sizeof(struct nm_timespec));
    if (offset != next.inode_size + 8 + i * sizeof(struct nm_timespec))
      return -EINVAL;
  }
  if (!data->size || data->size > 4096 || data->size % 8)
    return -EINVAL;
  next.inode_data_size = data->size;
  const char* fields[] = {"i_fop", "i_data", "i_hash", "i_blocks"};
  int16_t* destinations[] = {&next.inode_file_ops, &next.inode_data, &next.inode_hash, &next.inode_blocks};
  for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    int offset = kpm_btf_offset(&btf, inode, fields[i], i == 1 ? data->size : i == 2 ? 16 : 8);
    if (offset < 0 || offset > 0x7fff)
      return -EINVAL;
    *destinations[i] = offset;
  }
  const char* stat_fields[] = {"mode", "ino", "dev", "uid", "gid", "size"};
  int first = kpm_btf_offset(&btf, stat, "ino", 8);
  if (first != 0 && first != offsetof(struct nm_kstat_prefix, ino))
    return -EINVAL;
  next.kstat_inode_first = first == 0;
  const int stat_positions[] = {
      first == 0 ? offsetof(struct nm_kstat_inode_first, mode) : offsetof(struct nm_kstat_prefix, mode),
      first,
      first == 0 ? offsetof(struct nm_kstat_inode_first, dev) : offsetof(struct nm_kstat_prefix, dev),
      first == 0 ? offsetof(struct nm_kstat_inode_first, uid) : offsetof(struct nm_kstat_prefix, uid),
      first == 0 ? offsetof(struct nm_kstat_inode_first, gid) : offsetof(struct nm_kstat_prefix, gid),
      first == 0 ? offsetof(struct nm_kstat_inode_first, size) : offsetof(struct nm_kstat_prefix, size)};
  for (unsigned int i = 0; i < sizeof(stat_fields) / sizeof(stat_fields[0]); i++)
    if (kpm_btf_offset(&btf, stat, stat_fields[i], i == 0 ? 2 : i == 1 || i == 5 ? 8 : 4) != stat_positions[i])
      return -EINVAL;
  const u8 getattr[] = {0x88, 0x88, 4, 4}, mount_getattr[] = {0x88, 0x88, 0x88}, inode_arg[] = {0x88};
  const u8 context_getattr[] = {0x88, 0x88, 0x88, 4, 4};
  next.getattr_context_kind = 0;
  int attr = nm_btf_callback(&btf, iops, "getattr", getattr, 4, 4);
  next.getattr_callback_args = 4;
  if (attr == -EOPNOTSUPP) {
    attr = nm_btf_callback(&btf, iops, "getattr", mount_getattr, 3, 4);
    next.getattr_callback_args = 3;
  }
  if (attr == -EOPNOTSUPP) {
    attr = nm_btf_callback(&btf, iops, "getattr", context_getattr, 5, 4);
    if (attr >= 0) {
      int context = nm_btf_context_kind(&btf, nm_btf_callback_prototype(&btf, iops, "getattr"));
      if (context < 0)
        return context;
      next.getattr_context_kind = context;
      next.getattr_callback_args = 5;
    }
  }
  int drop = nm_btf_callback(&btf, sops, "drop_inode", inode_arg, 1, 4);
  int evict = nm_btf_callback(&btf, sops, "evict_inode", inode_arg, 1, 0);
  if (attr < 0 || drop < 0 || evict < 0 || attr > 0x7fff || drop > 0x7fff || evict > 0x7fff)
    return attr < 0 ? attr : drop < 0 ? drop : evict < 0 ? evict : -EINVAL;
  const u8 pair_getattr[] = {0x88, 0x88};
  int native = nm_btf_function(&btf, "vfs_getattr_nosec", getattr, 4, 4);
  next.getattr_function_args = 4;
  if (native == -EOPNOTSUPP) {
    native = nm_btf_function(&btf, "vfs_getattr_nosec", pair_getattr, 2, 4);
    next.getattr_function_args = 2;
  }
  if (native)
    return native;
  next.iop_getattr = attr;
  next.sop_drop_inode = drop;
  next.sop_evict_inode = evict;
  next.inode_ops_size = iops->size <= 0x7fff ? iops->size : -1;
  next.super_ops_size = sops->size <= 0x7fff ? sops->size : -1;
  struct_offset = next;
  return 0;
}

// BTF_INT_BOOL与SIGNED编码区分真实bool/int，宽度相同的unsigned char不能代替bool。
static int nm_btf_directory_actor(const struct kpm_btf* btf, const struct btf_type* context) {
  const u8 args[] = {0x88, 0x88, 4, 8, 8, 4};
  struct kpm_btf_field field;
  int rc = kpm_btf_member(btf, context, "actor", &field, 0);
  if (rc)
    return rc;
  if (field.bits || field.size != 8 || ((field.type->info >> 24) & 31) != 2)
    return -EINVAL;
  const struct btf_type* proto = btf->type_by_id(btf->data, field.type->size);
  if (!proto || ((proto->info >> 24) & 31) != 13)
    return -EOPNOTSUPP;
  u32 size = 0;
  const struct btf_type* result = btf->type_by_id(btf->data, proto->size);
  result = result ? btf->resolve_size(btf->data, result, &size) : NULL;
  if (!result || IS_ERR(result) || ((result->info >> 24) & 31) != 1)
    return -EOPNOTSUPP;
  u32 encoding = *(const u32*)(result + 1);
  int abi;
  if (size == 4 && encoding == (1U << 24 | 32U))
    abi = 0;
  else if (size == 1 && encoding == (4U << 24 | 8U))
    abi = 1;
  else
    return -EOPNOTSUPP;
  rc = nm_btf_callback(btf, context, "actor", args, 6, size);
  if (rc != offsetof(struct nm_dir_context, actor))
    return rc < 0 ? rc : -EINVAL;
  return abi;
}

static int calculate_btf_directory_offsets(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* inode_ops = kpm_btf_type(&btf, "inode_operations", 4);
  const struct btf_type* file_ops = kpm_btf_type(&btf, "file_operations", 4);
  const struct btf_type* dentry_ops = kpm_btf_type(&btf, "dentry_operations", 4);
  const struct btf_type* context = kpm_btf_type(&btf, "dir_context", 4);
  const struct btf_type* dentry = kpm_btf_type(&btf, "dentry", 4);
  if (!inode_ops || !file_ops || !dentry_ops || !context || !dentry)
    return -ENOENT;
  const u8 lookup[] = {0x88, 0x88, 4}, pair[] = {0x88, 0x88}, revalidate[] = {0x88, 4};
  rc = nm_btf_callback(&btf, inode_ops, "lookup", lookup, 3, 0x88);
  if (rc != offsetof(struct nm_inode_lookup_ops, lookup))
    return rc < 0 ? rc : -EINVAL;
  const char* common[] = {"d_revalidate", "d_weak_revalidate", "d_hash", "d_compare", "d_delete"};
  for (unsigned int i = 0; i < sizeof(common) / sizeof(common[0]); i++)
    if (kpm_btf_offset(&btf, dentry_ops, common[i], 8) != i * 8)
      return -EINVAL;
  rc = nm_btf_callback(&btf, dentry_ops, "d_revalidate", revalidate, 2, 4);
  if (rc < 0)
    return rc;
  rc = nm_btf_callback(&btf, dentry_ops, "d_weak_revalidate", revalidate, 2, 4);
  if (rc < 0)
    return rc;
  rc = kpm_btf_offset(&btf, dentry_ops, "d_release", 8);
  if (rc < 0)
    return rc;
  int release_slot = rc;
  int init_slot = kpm_btf_offset(&btf, dentry_ops, "d_init", 8);
  if (init_slot < 0 && init_slot != -ENOENT)
    return init_slot;
  if (release_slot > 0x7fff || init_slot > 0x7fff)
    return -EINVAL;
  int actor_abi = nm_btf_directory_actor(&btf, context);
  if (actor_abi < 0)
    return actor_abi;
  if (kpm_btf_offset(&btf, context, "pos", 8) != offsetof(struct nm_dir_context, pos)
      || kpm_btf_offset(&btf, dentry, "d_sb", 8) != struct_offset.dentry_ops + offsetof(struct nm_dentry_ops_data, d_sb)
      || kpm_btf_offset(&btf, dentry, "d_time", 8)
             != struct_offset.dentry_ops + offsetof(struct nm_dentry_ops_data, d_time)
      || kpm_btf_offset(&btf, dentry, "d_fsdata", 8)
             != struct_offset.dentry_ops + offsetof(struct nm_dentry_ops_data, d_fsdata))
    return -EINVAL;
  struct struct_offset next = struct_offset;
  next.dir_actor_abi = actor_abi;
  next.dop_init = init_slot == -ENOENT ? -1 : init_slot;
  next.dop_release = release_slot;
  int lock = kpm_btf_offset(&btf, dentry, "d_lockref.lock", 0);
  if (lock < 0 || lock > 0x7fff)
    return -EINVAL;
  next.dentry_lock = lock;
  int iterate = nm_btf_callback(&btf, file_ops, "iterate", pair, 2, 4);
  int shared = nm_btf_callback(&btf, file_ops, "iterate_shared", pair, 2, 4);
  if ((iterate < 0 && iterate != -ENOENT) || (shared < 0 && shared != -ENOENT))
    return iterate < 0 && iterate != -ENOENT ? iterate : shared;
  if (iterate > 0x7fff || shared > 0x7fff)
    return -EINVAL;
  next.fop_iterate = iterate == -ENOENT ? -1 : iterate;
  next.fop_iterate_shared = shared == -ENOENT ? -1 : shared;
  struct_offset = next;
  return 0;
}

static int nm_btf_function(const struct kpm_btf* btf, const char* name, const u8* args, unsigned int count,
                           unsigned int result) {
  const struct btf_type* function = kpm_btf_type(btf, name, 12);
  if (!function)
    return -ENOENT;
  return nm_btf_prototype(btf, btf->type_by_id(btf->data, function->size), args, count, result);
}

static int calculate_btf_virtual_directory_abi(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* file = kpm_btf_type(&btf, "file", 4);
  if (!file
      || kpm_btf_offset(&btf, file, "f_path", sizeof(struct nm_path))
             != struct_offset.file_inode_ops - offsetof(struct nm_file_path_inode_ops, f_inode))
    return -EINVAL;
  const u8 pair[] = {0x88, 0x88}, one[] = {0x88}, nlink[] = {0x88, 4}, seek[] = {0x88, 8, 4};
  const u8 triple[] = {0x88, 0x88, 0x88}, masked[] = {0x88, 4, 0x88, 0x88};
  const u8 iget[] = {0x88, 8, 0x88, 0x88, 0x88};
  int context = struct_offset.getattr_context_kind;
  if (context < 0 || context > 2)
    return -EOPNOTSUPP;
  int count = context + 2;
  rc = nm_btf_function(&btf, "generic_fillattr", context == 0 ? pair : context == 1 ? triple : masked, count, 0);
  if (!rc && context) {
    const struct btf_type* function = kpm_btf_type(&btf, "generic_fillattr", 12);
    if (nm_btf_context_kind(&btf, btf.type_by_id(btf.data, function->size)) != context)
      return -EOPNOTSUPP;
  }
  if (!rc)
    rc = nm_btf_function(&btf, "unlock_new_inode", one, 1, 0);
  if (!rc)
    rc = nm_btf_function(&btf, "set_nlink", nlink, 2, 0);
  if (!rc)
    rc = nm_btf_function(&btf, "generic_file_llseek", seek, 3, 8);
  if (!rc)
    rc = nm_btf_function(&btf, "iget5_locked", iget, 5, 0x88);
  if (rc)
    return rc;
  const struct btf_type* function = kpm_btf_type(&btf, "iget5_locked", 12);
  const struct btf_type* proto = btf.type_by_id(btf.data, function->size);
  const struct btf_param* params = (const void*)(proto + 1);
  for (unsigned int i = 2; i <= 3; i++) {
    u32 size = 0;
    const struct btf_type* pointer = btf.type_by_id(btf.data, params[i].type);
    pointer = pointer ? btf.resolve_size(btf.data, pointer, &size) : NULL;
    if (!pointer || IS_ERR(pointer) || ((pointer->info >> 24) & 31) != 2)
      return -EOPNOTSUPP;
    rc = nm_btf_prototype(&btf, btf.type_by_id(btf.data, pointer->size), pair, 2, 4);
    if (rc)
      return rc;
  }
  struct_offset.fillattr_abi = count;
  return 0;
}

static int calculate_btf_topology_abi(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const u8 pair[] = {0x88, 0x88}, one[] = {0x88};
  rc = nm_btf_function(&btf, "d_hash_and_lookup", pair, 2, 0x88);
  return rc ? rc : nm_btf_function(&btf, "shrink_dcache_parent", one, 1, 0);
}

static int calculate_btf_backing_directory_abi(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const u8 args[] = {0x88, 0x88, 0x88, 4, 0x88};
  return nm_btf_function(&btf, "vfs_path_lookup", args, 5, 4);
}

static int calculate_btf_backing_inode_abi(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const u8 triple[] = {0x88, 0x88, 4}, pair[] = {0x88, 4};
  const struct btf_type* legacy = kpm_btf_type(&btf, "inode_permission2", 12);
  if (legacy) {
    const struct btf_type* proto = btf.type_by_id(btf.data, legacy->size);
    rc = nm_btf_prototype(&btf, proto, triple, 3, 4);
    if (!rc)
      rc = nm_btf_named_parameter(&btf, proto, 0, "vfsmount");
    if (rc)
      return rc;
    struct_offset.permission_abi = 0;
    return 0;
  }
  const struct btf_type* function = kpm_btf_type(&btf, "inode_permission", 12);
  if (!function)
    return -ENOENT;
  const struct btf_type* proto = btf.type_by_id(btf.data, function->size);
  rc = nm_btf_prototype(&btf, proto, pair, 2, 4);
  if (!rc) {
    rc = nm_btf_named_parameter(&btf, proto, 0, "inode");
    if (!rc)
      struct_offset.permission_abi = 1;
    return rc;
  }
  rc = nm_btf_prototype(&btf, proto, triple, 3, 4);
  if (rc)
    return rc;
  int context = nm_btf_context_kind(&btf, proto);
  if (context < 0 || context != struct_offset.getattr_context_kind)
    return -EOPNOTSUPP;
  const struct btf_type* mount = kpm_btf_type(&btf, "vfsmount", 4);
  const char* member = context == 1 ? "mnt_userns" : "mnt_idmap";
  struct kpm_btf_field field;
  if (!mount || kpm_btf_member(&btf, mount, member, &field, 0) || field.bits || field.size != 8
      || ((field.type->info >> 24) & 31) != 2
      || kpm_btf_offset(&btf, mount, member, 8) != offsetof(struct nm_mount_context_head, context))
    return -EINVAL;
  u32 size = 0;
  const struct btf_type* type = btf.type_by_id(btf.data, field.type->size);
  type = type ? btf.resolve_size(btf.data, type, &size) : NULL;
  if (!type || IS_ERR(type) || type != kpm_btf_type(&btf, context == 1 ? "user_namespace" : "mnt_idmap", 4))
    return -EOPNOTSUPP;
  struct_offset.permission_abi = context + 1;
  return 0;
}

static int calculate_btf_control_layout(bool* unavailable) {
  struct kpm_btf btf;
  int rc = nm_get_btf(&btf, unavailable);
  if (rc)
    return rc;
  const struct btf_type* mutex = kpm_btf_type(&btf, "mutex", 4);
  const struct btf_type* key = kpm_btf_type(&btf, "key_type", 4);
  const struct btf_type* prep = kpm_btf_type(&btf, "key_preparsed_payload", 4);
  if (!mutex || !key || !prep)
    return -ENOENT;
  struct kpm_btf_field dep_map;
  rc = kpm_btf_member(&btf, mutex, "dep_map", &dep_map, 0);
  if (!rc)
    return -EOPNOTSUPP;
  if (rc != -ENOENT)
    return rc;
  const u8 one[] = {0x88}, pair[] = {0x88, 0x88}, triple[] = {0x88, 0x88, 0x88};
  int callbacks = nm_btf_callback(&btf, key, "preparse", one, 1, 4);
  if (mutex->size == 0 || mutex->size > 4096 || callbacks < 0
      || kpm_btf_offset(&btf, key, "name", 8) != offsetof(struct nm_key_type_head, name)
      || kpm_btf_offset(&btf, key, "def_datalen", 8) != offsetof(struct nm_key_type_head, def_datalen)
      || nm_btf_callback(&btf, key, "free_preparse", one, 1, 0)
             != callbacks + offsetof(struct nm_key_callbacks, free_preparse)
      || nm_btf_callback(&btf, key, "instantiate", pair, 2, 4)
             != callbacks + offsetof(struct nm_key_callbacks, instantiate))
    return callbacks < 0 ? callbacks : -EINVAL;
  int input = kpm_btf_offset(&btf, prep, "data", 8);
  struct kpm_btf_field data_field, length_field;
  int data_rc = kpm_btf_member(&btf, prep, "data", &data_field, 0);
  int length_rc = kpm_btf_member(&btf, prep, "datalen", &length_field, 0);
  if (input < 0 || input > 4096 - sizeof(struct nm_key_data) || input + sizeof(struct nm_key_data) > prep->size
      || data_rc || length_rc || ((data_field.type->info >> 24) & 31) != 2
      || ((length_field.type->info >> 24) & 31) != 1
      || kpm_btf_offset(&btf, prep, "datalen", 8) != input + offsetof(struct nm_key_data, datalen)
      || key->size != struct_offset.key_type_size)
    return -EINVAL;
  rc = nm_btf_function(&btf, "__mutex_init", triple, 3, 0);
  if (!rc)
    rc = nm_btf_function(&btf, "mutex_lock", one, 1, 0);
  if (!rc)
    rc = nm_btf_function(&btf, "mutex_unlock", one, 1, 0);
  if (!rc)
    rc = nm_btf_function(&btf, "register_key_type", one, 1, 4);
  if (rc)
    return rc;
  struct_offset.mutex_size = mutex->size;
  struct_offset.mutex_no_lockdep = 1;
  struct_offset.key_callbacks = callbacks;
  struct_offset.key_preparse_data = input;
  return nm_validate_control_layout();
}
