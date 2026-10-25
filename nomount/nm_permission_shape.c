/* SPDX-License-Identifier: GPL-2.0-only */
/* 复用已核对的共同i_op前部；ABI与getattr锚点必须同时一致。 */
static int nm_common_owned_permission(int* slot, int* second) {
  *second = -1;
  if (struct_offset.getattr_context_kind != 0)
    return -EOPNOTSUPP;  // userns/idmap的generic_permission原型要求BTF。
  if (struct_offset.permission_abi == 0) {
    if (struct_offset.iop_getattr != offsetof(struct nm_inode_follow_prefix, getattr)
        && struct_offset.iop_getattr != offsetof(struct nm_inode_android_link_prefix, getattr))
      return -EOPNOTSUPP;
    *slot = offsetof(struct nm_inode_android_link_prefix, permission);
    *second = offsetof(struct nm_inode_android_link_prefix, permission2);
  } else if (struct_offset.permission_abi == 1
             && struct_offset.iop_getattr == offsetof(struct nm_inode_plain_link_prefix, getattr)) {
    *slot = offsetof(struct nm_inode_plain_link_prefix, permission);
  } else {
    return -EOPNOTSUPP;
  }
  return 0;
}

// 两个真实Android入口的FASTPERM直达路径；只核对通往generic的参数来源。
static int nm_find_generic_dac_call(const uint32_t* src, unsigned int count, bool split, uintptr_t generic,
                                    uintptr_t start, uintptr_t end) {
  if (!src || count < (split ? 39U : 13U))
    return -ENODATA;
  unsigned int call;
  if (!split) {
    for (unsigned int i = 0; i < 5; i++)
      if (!nm_rule_entry_save(src[i]))
        return -EOPNOTSUPP;
    if (!nm_move32(src[5], 19, 2) || !nm_move(src[6], 20, 1) || !inst_is_tbnz(src[7]) || inst_get_tbnz_rt(src[7]) != 2
        || inst_get_tbnz_bit(src[7]) != 1 || inst_get_tbnz_label(src[7]) <= 20
        || (!nm_load(src[8], 1, 20) || inst_get_ldr_imm_rt(src[8]) != 8
            || inst_get_ldr_imm_imm(src[8]) != offsetof(struct nm_inode_owner_prefix, i_opflags))
        || !inst_is_tbz(src[9]) || inst_get_tbz_rt(src[9]) != 8 || inst_get_tbz_bit(src[9]) != 0
        || inst_get_tbz_label(src[9]) <= 12 || !nm_move(src[10], 0, 20) || !nm_move32(src[11], 1, 19))
      return -EOPNOTSUPP;
    call = 12;
  } else {
    if (!nm_rule_entry_save(src[0]) || !nm_move(src[1], 4, 0) || !nm_rule_entry_save(src[2])
        || !nm_rule_entry_save(src[3]) || !nm_rule_entry_save(src[4]) || !nm_move32(src[5], 20, 2)
        || !nm_move(src[6], 19, 1) || !inst_is_tbz(src[7]) || inst_get_tbz_rt(src[7]) != 20
        || inst_get_tbz_bit(src[7]) != 1 || inst_get_tbz_label(src[7]) != 16
        || (!nm_load(src[11], 1, 19) || inst_get_ldr_imm_rt(src[11]) != 0
            || inst_get_ldr_imm_imm(src[11]) != offsetof(struct nm_inode_owner_prefix, i_opflags))
        || !inst_is_tbnz(src[12]) || inst_get_tbnz_rt(src[12]) != 0 || inst_get_tbnz_bit(src[12]) != 0
        || inst_get_tbnz_label(src[12]) != 96 || !nm_move(src[36], 0, 19) || !nm_move32(src[37], 1, 20))
      return -EOPNOTSUPP;
    call = 38;
  }
  return inst_is_bl(src[call])
                 && nm_code_matches((uintptr_t)&src[call] + inst_get_bl_label(src[call]), generic, start, end)
             ? 0
             : -EOPNOTSUPP;
}

static int nm_confirm_generic_dac_abi(void) {
  // 非Android二参推导已核对入口inode/mask到具名generic的直接调用链。
  if (struct_offset.permission_abi == 1) {
    int rc = calculate_function_permission_abi();
    return rc ? rc : struct_offset.permission_abi == 1 ? 0 : -EINVAL;
  }
  if (struct_offset.permission_abi != 0)
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  uintptr_t generic = kallsyms_lookup_name_by_suffix("generic_permission");
  uintptr_t entry = kallsyms_lookup_name_by_suffix("__inode_permission2");
  bool split = entry != 0;
  if (!entry)
    entry = kallsyms_lookup_name_by_suffix("inode_permission2");
  entry = nm_inode_lock_body(entry, start, end);
  unsigned int count = split ? 39 : 13;
  if (!generic || !entry || entry > end || end - entry < count * sizeof(uint32_t))
    return -ENODATA;
  return nm_find_generic_dac_call((const void*)entry, count, split, generic, start, end);
}
