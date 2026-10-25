/* SPDX-License-Identifier: GPL-2.0-only */
/* 无BTF的plain5已观察形态；六参路径等待可验证目标，不按版本分支。 */
enum { NM_XATTR_SET_WORDS = 36, NM_XATTR_LOCKED_WORDS = 24, NM_XATTR_SECURITY_WORDS = 11, NM_XATTR_RO_WORDS = 8 };

// 序言不得隐蔽保存额外的x5..x7或改写入口参数；只收已观察的非参数栈保存。
static bool nm_xattr_signature_frame(uint32_t inst) {
  if (!nm_vfs_frame_save(inst))
    return false;
  if (inst_is_stp(inst))
    return inst_get_stp_rt(inst) >= 19 && inst_get_stp_rt2(inst) >= 19;
  return true;
}

static uintptr_t nm_xattr_signature_body(uintptr_t at, unsigned int words, uintptr_t start, uintptr_t end) {
  at = nm_inode_lock_body(at, start, end);
  return at && end - at >= words * sizeof(uint32_t) ? at : 0;
}

static bool nm_xattr_signature_call(const uint32_t* at, uintptr_t target, uintptr_t start, uintptr_t end) {
  return inst_is_bl(*at) && nm_code_matches((uintptr_t)at + inst_get_bl_label(*at), target, start, end);
}

// 第一个见证：entry x0的d_inode进入已独立准备的锁；五个输入按原位宽传给locked。
static int nm_find_xattr_plain5(const uint32_t* src, unsigned int count, const struct nm_setattr_layout* layout,
                                const uintptr_t helpers[4], uintptr_t locked, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_SET_WORDS || !layout || layout->context || layout->lock_offset < 0
      || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned int i = 0; i < 8; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!inst_is_adrp(src[8]) || inst_get_adrp_rd(src[8]) != 8 || !nm_load(src[11], 3, 8)
      || inst_get_ldr_imm_rt(src[11]) != 8 || !nm_store_at(src[15], 3, 8, 31, 8))
    return -EOPNOTSUPP;
  int kind = 0;
  int offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  if (offset < 0)
    return offset;
  if (offset != layout->lock_offset || kind != layout->lock_kind)
    return -EINVAL;
  // 只接受已观察的参数保存/转发，不把最高读寄存器泛化成任意C原型恢复器。
  if (!nm_move32(src[9], 19, 4) || !nm_move(src[10], 20, 3) || !nm_move(src[12], 21, 2) || !nm_move(src[13], 22, 0)
      || !nm_move(src[14], 23, 1) || !nm_load_at(src[16], 26, 0, offsetof(struct nm_dentry_head, d_inode))
      || !nm_store_at(src[17], 3, 31, 31, 0) || !inst_is_b(src[18]) || inst_get_b_label(src[18]) != 24
      || !nm_add_at(src[24], 0, 26, offset) || !nm_add_at(src[26], 5, 31, 0) || !nm_move(src[27], 0, 22)
      || !nm_move(src[28], 1, 23) || !nm_move(src[29], 2, 21) || !nm_move(src[30], 3, 20) || !nm_move32(src[31], 4, 19)
      || !nm_xattr_signature_call(&src[32], locked, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// 独立函数中的第二个见证：同一个转发dentry→d_inode进入xattr_permission，
// 原dentry/name/value/size/flags原样传给完整security_inode_setxattr。
static int nm_find_xattr_locked_plain5(const uint32_t* src, unsigned int count, uintptr_t permission,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_LOCKED_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 7; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[7], 25, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[8], 22, 0)
      || !nm_move(src[9], 21, 2) || !inst_is_movz_imm(src[10]) || inst_get_movz_imm_sf(src[10])
      || inst_get_movz_imm_rd(src[10]) != 2 || inst_get_movz_imm_hw(src[10]) || inst_get_movz_imm_imm16(src[10]) != 2
      || !nm_move(src[11], 23, 5) || !nm_move32(src[12], 19, 4) || !nm_move(src[13], 0, 25) || !nm_move(src[14], 20, 3)
      || !nm_move(src[15], 24, 1) || !nm_xattr_signature_call(&src[16], permission, start, end)
      || !inst_is_cbnz(src[17]) || inst_get_cbnz_sf(src[17]) || inst_get_cbnz_rt(src[17]) != 0
      || inst_get_cbnz_label(src[17]) != 148 || !nm_move(src[18], 0, 22) || !nm_move(src[19], 1, 24)
      || !nm_move(src[20], 2, 21) || !nm_move(src[21], 3, 20) || !nm_move32(src[22], 4, 19)
      || !nm_xattr_signature_call(&src[23], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// security入口自身再次使用同一dentry的inode标志，拒绝仅同名但不同ABI的入口。
static int nm_find_xattr_security_plain5(const uint32_t* src, unsigned int count) {
  if (!src || count != NM_XATTR_SECURITY_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 8; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[8], 8, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_load(src[9], 0, 8)
      || inst_get_ldr_imm_rt(src[9]) != 8
      || inst_get_ldr_imm_imm(src[9]) != offsetof(struct nm_inode_owner_prefix, i_flags) + 1 || !inst_is_tbnz(src[10])
      || inst_get_tbnz_rt(src[10]) != 8 || inst_get_tbnz_bit(src[10]) != 1 || inst_get_tbnz_label(src[10]) != 180)
    return -EOPNOTSUPP;
  return 0;
}

// 完整8条短函数：MNT_READONLY || (mnt_sb->s_flags & SB_RDONLY)，布尔返回。
static int nm_find_xattr_readonly(const uint32_t* src, unsigned int count) {
  if (!src || count != NM_XATTR_RO_WORDS)
    return -EINVAL;
  if (!nm_load(src[0], 0, 0) || inst_get_ldr_imm_rt(src[0]) != 8
      || inst_get_ldr_imm_imm(src[0]) != offsetof(struct nm_mount_context_head, flags) || !inst_is_tbnz(src[1])
      || inst_get_tbnz_rt(src[1]) != 8 || inst_get_tbnz_bit(src[1]) != 6 || inst_get_tbnz_label(src[1]) != 20
      || !nm_load_at(src[2], 8, 0, offsetof(struct nm_mount_context_head, super)) || !nm_load(src[3], 0, 8)
      || inst_get_ldr_imm_rt(src[3]) != 8 || inst_get_ldr_imm_imm(src[3]) != offsetof(struct nm_super_head, s_flags)
      || !inst_is_and_imm(src[4]) || inst_get_and_imm_sf(src[4]) || inst_get_and_imm_rd(src[4]) != 0
      || inst_get_and_imm_rn(src[4]) != 8 || inst_get_and_imm_imm(src[4]) != 1 || !inst_is_ret(src[5])
      || inst_get_ret_rn(src[5]) != 30 || !inst_is_movz_imm(src[6]) || inst_get_movz_imm_sf(src[6])
      || inst_get_movz_imm_rd(src[6]) != 0 || inst_get_movz_imm_hw(src[6]) || inst_get_movz_imm_imm16(src[6]) != 1
      || !inst_is_ret(src[7]) || inst_get_ret_rn(src[7]) != 30)
    return -EOPNOTSUPP;
  return 0;
}

static int calculate_function_xattr_write(int context, const struct nm_setattr_layout* layout) {
  if (context || !layout || (struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
    return -EOPNOTSUPP;
  if (kallsyms_lookup_name_by_suffix("do_set_acl"))
    return -EOPNOTSUPP;  // 具名独立ACL入口的非BTF原型尚未覆盖。
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const char* names[] = {"vfs_setxattr",      "__vfs_setxattr_locked", "security_inode_setxattr",
                         "__mnt_is_readonly", "xattr_permission",      "down_write",
                         "up_write"};
  const unsigned int words[] = {
      NM_XATTR_SET_WORDS, NM_XATTR_LOCKED_WORDS, NM_XATTR_SECURITY_WORDS, NM_XATTR_RO_WORDS, 2, 2, 2};
  uintptr_t bodies[7];
  for (unsigned int i = 0; i < 7; i++) {
    bodies[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(names[i]), words[i], start, end);
    if (!bodies[i])
      return -ENOENT;
    for (unsigned int j = 0; j < i; j++)
      if (bodies[i] == bodies[j])
        return -EINVAL;
  }
  uintptr_t helpers[4] = {bodies[5], bodies[6], 0, 0};
  int rc = nm_find_xattr_plain5((const void*)bodies[0], words[0], layout, helpers, bodies[1], start, end);
  if (!rc)
    rc = nm_find_xattr_locked_plain5((const void*)bodies[1], words[1], bodies[4], bodies[2], start, end);
  if (!rc)
    rc = nm_find_xattr_security_plain5((const void*)bodies[2], words[2]);
  if (!rc)
    rc = nm_find_xattr_readonly((const void*)bodies[3], words[3]);
  if (!rc)
    nm_log_info("layout: setxattr plain5/dentry arg0, lock + permission/security witnesses, readonly bool\n");
  return rc;
}
