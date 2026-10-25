/* SPDX-License-Identifier: GPL-2.0-only */
/* 真实plain2删除入口与syscall内部list入口；不按版本选择原型。 */
enum {
  NM_XATTR_REMOVE_WORDS = 29,
  NM_XATTR_REMOVE_LOCKED_WORDS = 16,
  NM_XATTR_REMOVE_SECURITY_WORDS = 9,
  NM_XATTR_INTERNAL_LIST_WORDS = 25,
  NM_XATTR_LIST_SECURITY_WORDS = 9
};

static int nm_find_xattr_remove2(const uint32_t* src, unsigned int count, const struct nm_setattr_layout* layout,
                                 const uintptr_t helpers[4], uintptr_t locked, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_REMOVE_WORDS || !layout || layout->context || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned int i = 0; i < 7; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  int kind = 0, offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  if (offset < 0)
    return offset;
  if (offset != layout->lock_offset || kind != layout->lock_kind)
    return -EINVAL;
  if (!inst_is_adrp(src[7]) || inst_get_adrp_rd(src[7]) != 8 || !nm_move(src[8], 19, 1) || !nm_move(src[9], 20, 0)
      || !nm_load(src[10], 3, 8) || inst_get_ldr_imm_rt(src[10]) != 8 || !nm_store_at(src[11], 3, 8, 31, 8)
      || !nm_load_at(src[12], 23, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_store_at(src[13], 3, 31, 31, 0)
      || !inst_is_b(src[14]) || inst_get_b_label(src[14]) != 24 || !nm_add_at(src[20], 0, 23, offset)
      || !nm_add_at(src[22], 2, 31, 0) || !nm_move(src[23], 0, 20) || !nm_move(src[24], 1, 19)
      || !nm_xattr_signature_call(&src[25], locked, start, end))
    return -EOPNOTSUPP;
  return 0;
}

static int nm_find_xattr_remove_locked(const uint32_t* src, unsigned int count, uintptr_t permission,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_REMOVE_LOCKED_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 5; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[5], 22, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[6], 21, 2)
      || !nm_move(src[7], 19, 0) || !inst_is_movz_imm(src[8]) || inst_get_movz_imm_sf(src[8])
      || inst_get_movz_imm_hw(src[8]) || inst_get_movz_imm_rd(src[8]) != 2 || inst_get_movz_imm_imm16(src[8]) != 2
      || !nm_move(src[9], 20, 1) || !nm_move(src[10], 0, 22)
      || !nm_xattr_signature_call(&src[11], permission, start, end) || !inst_is_cbnz(src[12])
      || inst_get_cbnz_sf(src[12]) || inst_get_cbnz_rt(src[12]) || inst_get_cbnz_label(src[12]) != 20
      || !nm_move(src[13], 0, 19) || !nm_move(src[14], 1, 20)
      || !nm_xattr_signature_call(&src[15], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// 两个security入口有相同的dentry→inode→S_PRIVATE前部，跳转距离由目标分别确认。
static int nm_find_xattr_security_pair(const uint32_t* src, unsigned int count, int branch) {
  if (!src || count != 9)
    return -EINVAL;
  for (unsigned int i = 0; i < 6; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  return nm_load_at(src[6], 8, 0, offsetof(struct nm_dentry_head, d_inode)) && nm_load(src[7], 0, 8)
                 && inst_get_ldr_imm_rt(src[7]) == 8
                 && inst_get_ldr_imm_imm(src[7]) == offsetof(struct nm_inode_owner_prefix, i_flags) + 1
                 && inst_is_tbnz(src[8]) && inst_get_tbnz_rt(src[8]) == 8 && inst_get_tbnz_bit(src[8]) == 1
                 && inst_get_tbnz_label(src[8]) == branch
             ? 0
             : -EOPNOTSUPP;
}

static int calculate_function_xattr_remove(int context, const struct nm_setattr_layout* layout) {
  if (context || !layout || (struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const char* names[] = {
      "vfs_removexattr", "__vfs_removexattr_locked", "security_inode_removexattr", "xattr_permission", "down_write",
      "up_write"};
  const unsigned int words[] = {
      NM_XATTR_REMOVE_WORDS, NM_XATTR_REMOVE_LOCKED_WORDS, NM_XATTR_REMOVE_SECURITY_WORDS, 2, 2, 2};
  uintptr_t bodies[6];
  for (unsigned int i = 0; i < 6; i++) {
    bodies[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(names[i]), words[i], start, end);
    if (!bodies[i])
      return -ENOENT;
    for (unsigned int j = 0; j < i; j++)
      if (bodies[i] == bodies[j])
        return -EINVAL;
  }
  uintptr_t helpers[4] = {bodies[4], bodies[5], 0, 0};
  int rc = nm_find_xattr_remove2((const void*)bodies[0], words[0], layout, helpers, bodies[1], start, end);
  if (!rc)
    rc = nm_find_xattr_remove_locked((const void*)bodies[1], words[1], bodies[3], bodies[2], start, end);
  if (!rc)
    rc = nm_find_xattr_security_pair((const void*)bodies[2], words[2], 144);
  if (!rc)
    nm_log_info("layout: removexattr plain2/dentry arg0, lock + permission/security witnesses\n");
  return rc;
}

// x0=dentry、x1=user buffer、x2=size；零长度支路保留NULL内核buffer并继续原生查询。
static int nm_find_xattr_internal_list(const uint32_t* src, unsigned int count, uintptr_t allocation,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_INTERNAL_LIST_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 6; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  if (!nm_move(src[6], 20, 1) || !nm_move(src[7], 21, 0) || !inst_is_cbz(src[8]) || !inst_get_cbz_sf(src[8])
      || inst_get_cbz_rt(src[8]) != 2 || inst_get_cbz_label(src[8]) != 48 || !inst_is_subs_imm(src[9])
      || !inst_get_subs_imm_sf(src[9]) || inst_get_subs_imm_rd(src[9]) != 31 || inst_get_subs_imm_rn(src[9]) != 2
      || inst_get_subs_imm_imm(src[9]) != 65536 || !inst_is_movz_imm(src[10]) || inst_get_movz_imm_sf(src[10])
      || inst_get_movz_imm_rd(src[10]) != 8 || inst_get_movz_imm_hw(src[10]) != 1
      || inst_get_movz_imm_imm16(src[10]) != 1 || !inst_is_movz_imm(src[11]) || inst_get_movz_imm_sf(src[11])
      || inst_get_movz_imm_rd(src[11]) != 1 || inst_get_movz_imm_hw(src[11]) || inst_get_movz_imm_imm16(src[11]) != 0xc0
      || !inst_is_csel(src[12]) || !inst_get_csel_sf(src[12]) || inst_get_csel_rd(src[12]) != 22
      || inst_get_csel_rn(src[12]) != 2 || inst_get_csel_rm(src[12]) != 8 || inst_get_csel_cond(src[12]) != 3
      || !inst_is_movk_imm(src[13]) || inst_get_movk_imm_sf(src[13]) || inst_get_movk_imm_rd(src[13]) != 1
      || inst_get_movk_imm_hw(src[13]) != 1 || inst_get_movk_imm_imm16(src[13]) != 0x60 || !inst_is_movn_imm(src[14])
      || inst_get_movn_imm_sf(src[14]) || inst_get_movn_imm_rd(src[14]) != 2 || inst_get_movn_imm_hw(src[14])
      || inst_get_movn_imm_imm16(src[14]) || !nm_move(src[15], 0, 22)
      || !nm_xattr_signature_call(&src[16], allocation, start, end) || !inst_is_cbz(src[17])
      || !inst_get_cbz_sf(src[17]) || inst_get_cbz_rt(src[17]) || inst_get_cbz_label(src[17]) != 236
      || !nm_move(src[18], 19, 0) || !inst_is_b(src[19]) || inst_get_b_label(src[19]) != 12 || !nm_zero64(src[20], 22)
      || !nm_zero64(src[21], 19) || !nm_load_at(src[22], 23, 21, offsetof(struct nm_dentry_head, d_inode))
      || !nm_move(src[23], 0, 21) || !nm_xattr_signature_call(&src[24], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

static int calculate_function_xattr_internal_list(int context) {
  if (context)
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  uintptr_t list =
      nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("listxattr"), NM_XATTR_INTERNAL_LIST_WORDS, start, end);
  uintptr_t security = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("security_inode_listxattr"),
                                               NM_XATTR_LIST_SECURITY_WORDS, start, end);
  uintptr_t allocation = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("kvmalloc_node"), 2, start, end);
  if (!list || !security || !allocation)
    return -ENOENT;
  if (list == security || list == allocation || security == allocation)
    return -EINVAL;
  int rc =
      nm_find_xattr_internal_list((const void*)list, NM_XATTR_INTERNAL_LIST_WORDS, allocation, security, start, end);
  if (!rc)
    rc = nm_find_xattr_security_pair((const void*)security, NM_XATTR_LIST_SECURITY_WORDS, 108);
  if (!rc)
    nm_log_info("layout: syscall listxattr3/dentry arg0, size + security witnesses\n");
  return rc;
}
