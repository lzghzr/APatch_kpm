struct struct_offset {
  int16_t subprocess_info_path_offset;
  int16_t cred_security_offset;
  int16_t cred_sid_offset;
  int16_t legacy_worker_size;
};

// 独立数据段供离线替换；volatile 保证访问读取配置表。
volatile struct struct_offset struct_offset __attribute__((section(".data.re_offsets"), used)) = {
    .subprocess_info_path_offset = -1,
    .cred_security_offset = -1,
    .cred_sid_offset = -1,
    .legacy_worker_size = -1,
};

#define subprocess_info_path_offset struct_offset.subprocess_info_path_offset
#define cred_security_offset struct_offset.cred_security_offset
#define cred_sid_offset struct_offset.cred_sid_offset
#define legacy_worker_size struct_offset.legacy_worker_size

#ifdef CONFIG_KPM_BASELINES
static long calculate_offsets() {
  if (subprocess_info_path_offset < 0 || cred_security_offset < 0 || cred_sid_offset < 0
      || (!kfunc(kthread_create_worker) && legacy_worker_size <= 0))
    return -EINVAL;
  // 基线保存结构内 SID 偏移；LSM blob 的起点由启动后的内核给出。
  if (kvar(selinux_blob_sizes)) {
    int blob = kvar_val(selinux_blob_sizes);
    if (blob < 0)
      return -EINVAL;
    cred_sid_offset += blob;
  }
  return 0;
}
#else
static long calculate_offsets() {
  struct kpm_btf btf = {cmd_btf, kfunc(btf_find_by_name_kind), kfunc(btf_type_by_id), kfunc(btf_name_by_offset),
                        kfunc(btf_resolve_size)};
  if (cmd_btf) {
    // 工作项由模块持有，核对实际内核是否能使用这一共同前缀。
    const struct btf_type* work = kpm_btf_type(&btf, "kthread_work", 4);
    if (work
        && (work->size > sizeof(cmd_work) || kpm_btf_offset(&btf, work, "node", 16) != 0
            || kpm_btf_offset(&btf, work, "func", 8) != 16 || kpm_btf_offset(&btf, work, "worker", 8) != 24
            || (kfunc(kthread_create_worker) && kpm_btf_offset(&btf, work, "canceling", 4) != 32)))
      return -EINVAL;
    int path = kpm_btf_offset(&btf, kpm_btf_type(&btf, "subprocess_info", 4), "path", 8);
    int security = kpm_btf_offset(&btf, kpm_btf_type(&btf, "cred", 4), "security", 8);
    int sid = kpm_btf_offset(&btf, kpm_btf_type(&btf, "task_security_struct", 4), "sid", 4);
    if (sid >= 0 && kvar(selinux_blob_sizes)) {
      int blob = kvar_val(selinux_blob_sizes);
      if (blob < 0)
        return -EINVAL;
      sid += blob;
    }
    if (path >= 0 && security >= 0 && sid >= 0) {
      if (cred_offset.security_offset >= 0 && security != cred_offset.security_offset)
        return -EINVAL;
      subprocess_info_path_offset = path;
      cred_security_offset = security;
      cred_sid_offset = sid;
      logkm("BTF: subprocess_info_path=0x%x cred_security=0x%x cred_sid=0x%x\n", subprocess_info_path_offset,
            cred_security_offset, cred_sid_offset);
      goto worker_offsets;
    }
  }

  // subprocess_info->path 是 call_usermodehelper_exec 入口检查的指针。
  uint32_t* src = (uint32_t*)kfunc(call_usermodehelper_exec);
  if (inst_is_b(src[0]))
    src = (uint32_t*)((uintptr_t)src + inst_get_b_label(src[0]));

  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(src[i]))
      break;
    if (inst_get_ldr_imm_uint_size(src[i]) != 3 || inst_get_ldr_imm_uint_rn(src[i]) != 0)
      continue;
    int rt = inst_get_ldr_imm_uint_rt(src[i]);
    for (u32 j = i + 1; j < i + 0xb && j < 0x20; j++) {
      uint32_t inst = src[j];
      // CBZ/CBNZ 只差 op 位，统一为 CBZ 后读取相同的 sf 和 Rt。
      uint32_t branch = inst & ~(1U << 24);
      if (inst_is_cbz(branch)) {
        if (inst_get_cbz_sf(branch) && inst_get_cbz_rt(branch) == rt)
          subprocess_info_path_offset = inst_get_ldr_imm_uint_imm(src[i]);
        break;
      }
      // 路径寄存器必须跨过 completion 的初始化而保持不变。
      if (inst == 0xd503201f || inst_is_str_imm(inst) || (inst_is_stp_imm(inst) && inst_get_stp_imm_rn(inst) != rt)
          || (inst_is_add_imm(inst) && inst_get_add_imm_rd(inst) != rt)
          || (inst_is_mov_reg(inst) && inst_get_mov_reg_rd(inst) != rt))
        continue;
      break;
    }
    break;
  }
  logkm("subprocess_info_path=0x%x\n", subprocess_info_path_offset);
  if (subprocess_info_path_offset < 0)
    return -ENOENT;

  if (!kfunc(selinux_cred_getsecid)) {
    // 旧 task getter：通过 KP 已知的两个凭据槽位定位连续读取链。
    src = (uint32_t*)kfunc(selinux_task_getsecid);
    if (inst_is_b(src[0]))
      src = (uint32_t*)((uintptr_t)src + inst_get_b_label(src[0]));
    int task = 0, out = 1;
    for (u32 i = 0; i + 2 < 0x10; i++) {
      if (inst_is_ret(src[i]))
        break;
      if (inst_get_mov_reg_sf(src[i]) == 1) {
        if (inst_get_mov_reg_rm(src[i]) == 0)
          task = inst_get_mov_reg_rd(src[i]);
        if (inst_get_mov_reg_rm(src[i]) == 1)
          out = inst_get_mov_reg_rd(src[i]);
      }
      if (inst_get_ldr_imm_uint_size(src[i]) != 3 || inst_get_ldr_imm_uint_rn(src[i]) != task
          || (inst_get_ldr_imm_uint_imm(src[i]) != task_struct_offset.real_cred_offset
              && inst_get_ldr_imm_uint_imm(src[i]) != task_struct_offset.cred_offset))
        continue;
      if (inst_get_ldr_imm_uint_size(src[i + 1]) != 3
          || inst_get_ldr_imm_uint_rn(src[i + 1]) != inst_get_ldr_imm_uint_rt(src[i])
          || inst_get_ldr_imm_uint_size(src[i + 2]) != 2
          || inst_get_ldr_imm_uint_rn(src[i + 2]) != inst_get_ldr_imm_uint_rt(src[i + 1]))
        break;
      int security = inst_get_ldr_imm_uint_imm(src[i + 1]);
      if (cred_offset.security_offset >= 0 && security != cred_offset.security_offset)
        break;
      for (u32 j = i + 3; j < i + 6 && j < 0x10; j++) {
        if (inst_is_ret(src[j]))
          break;
        if (inst_get_str_imm_uint_size(src[j]) == 2 && inst_get_str_imm_uint_rn(src[j]) == out
            && !inst_get_str_imm_uint_imm(src[j])
            && inst_get_str_imm_uint_rt(src[j]) == inst_get_ldr_imm_uint_rt(src[i + 2])) {
          cred_security_offset = security;
          cred_sid_offset = inst_get_ldr_imm_uint_imm(src[i + 2]);
          break;
        }
      }
      break;
    }
    logkm("task getter: cred_security=0x%x cred_sid=0x%x\n", cred_security_offset, cred_sid_offset);
    if (cred_sid_offset < 0)
      return -ENOENT;
  } else {
    // 短 getter：cred->security → 可选的 LSM blob 加量 → SID → *secid。
    src = (uint32_t*)kfunc(selinux_cred_getsecid);
    if (inst_is_b(src[0]))
      src = (uint32_t*)((uintptr_t)src + inst_get_b_label(src[0]));
    for (u32 i = 0; i + 2 < 0x10; i++) {
      if (inst_is_ret(src[i]))
        break;
      if (inst_get_ldr_imm_uint_size(src[i]) != 3 || inst_get_ldr_imm_uint_rn(src[i]) != 0)
        continue;
      if (cred_offset.security_offset >= 0 && inst_get_ldr_imm_uint_imm(src[i]) != cred_offset.security_offset)
        break;
      int base = inst_get_ldr_imm_uint_rt(src[i]);
      u32 j = i + 1;
      int blob = 0;
      if (inst_get_ldr_imm_size(src[j]) == 2 && inst_get_ldr_imm_opc(src[j]) == 2) {
        // LDRSW 的全局地址须对应 selinux_blob_sizes.lbs_cred。
        if (!i || j + 3 >= 0x10 || !kvar(selinux_blob_sizes) || !inst_is_adrp(src[i - 1])
            || inst_get_adrp_rd(src[i - 1]) != inst_get_ldr_imm_rn(src[j]))
          break;
        uintptr_t addr = ((uintptr_t)&src[i - 1] & ~0xfffUL) + inst_get_adrp_label(src[i - 1])
                         + ((uintptr_t)inst_get_ldr_imm_imm12(src[j]) << 2);
        if (addr != (uintptr_t)kvar(selinux_blob_sizes) || inst_get_add_reg_sf(src[j + 1]) != 1
            || inst_get_add_reg_shift(src[j + 1]) || inst_get_add_reg_imm6(src[j + 1])
            || inst_get_add_reg_rn(src[j + 1]) != base
            || inst_get_add_reg_rm(src[j + 1]) != inst_get_ldr_imm_rt(src[j]))
          break;
        blob = kvar_val(selinux_blob_sizes);
        if (blob < 0)
          break;
        base = inst_get_add_reg_rd(src[j + 1]);
        j += 2;
      }
      if (inst_get_ldr_imm_uint_size(src[j]) == 2 && inst_get_ldr_imm_uint_rn(src[j]) == base
          && inst_get_str_imm_uint_size(src[j + 1]) == 2 && inst_get_str_imm_uint_rn(src[j + 1]) == 1
          && !inst_get_str_imm_uint_imm(src[j + 1])
          && inst_get_str_imm_uint_rt(src[j + 1]) == inst_get_ldr_imm_uint_rt(src[j])) {
        cred_security_offset = inst_get_ldr_imm_uint_imm(src[i]);
        cred_sid_offset = blob + inst_get_ldr_imm_uint_imm(src[j]);
      }
      break;
    }
    logkm("cred_security=0x%x kp_security=0x%x cred_sid=0x%x\n", cred_security_offset, cred_offset.security_offset,
          cred_sid_offset);
    if (cred_sid_offset < 0)
      return -ENOENT;
  }

worker_offsets:
  if (!kfunc(kthread_create_worker)) {
    const struct btf_type* worker = cmd_btf ? kpm_btf_type(&btf, "kthread_worker", 4) : NULL;
    if (worker) {
      legacy_worker_size = worker->size;
      return legacy_worker_size > 0 ? 0 : -EINVAL;
    }
    // 旧 initializer 的 list_head 自指向，随后是 task 与 current_work。
    src = (uint32_t*)kfunc(__init_kthread_worker);
    if (inst_is_b(src[0]))
      src = (uint32_t*)((uintptr_t)src + inst_get_b_label(src[0]));
    for (u32 i = 0; i + 2 < 0x10; i++) {
      if (inst_is_ret(src[i]))
        break;
      if (inst_get_add_imm_sf(src[i]) != 1 || inst_get_add_imm_rn(src[i]) || inst_get_add_imm_sh(src[i]))
        continue;
      int list = inst_get_add_imm_imm(src[i]), reg = inst_get_add_imm_rd(src[i]);
      for (u32 j = i + 1; j + 2 < 0x10; j++) {
        if (inst_is_ret(src[j]))
          break;
        if (inst_get_str_imm_uint_size(src[j]) == 3 && !inst_get_str_imm_uint_rn(src[j])
            && inst_get_str_imm_uint_rt(src[j]) == reg && inst_get_str_imm_uint_imm(src[j]) == list
            && inst_get_str_imm_uint_size(src[j + 1]) == 3 && inst_get_str_imm_uint_rn(src[j + 1]) == reg
            && inst_get_str_imm_uint_rt(src[j + 1]) == reg && inst_get_str_imm_uint_imm(src[j + 1]) == 8
            && inst_get_str_imm_uint_size(src[j + 2]) == 3 && !inst_get_str_imm_uint_rn(src[j + 2])
            && inst_get_str_imm_uint_rt(src[j + 2]) == 31 && inst_get_str_imm_uint_imm(src[j + 2]) == list + 16) {
          legacy_worker_size = list + 32;
          break;
        }
      }
      break;
    }
    logkm("legacy_worker_size=0x%x\n", legacy_worker_size);
    if (legacy_worker_size < 0)
      return -ENOENT;
  }
  return 0;
}

#endif
