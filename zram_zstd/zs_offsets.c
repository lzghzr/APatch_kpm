struct struct_offset {
  int16_t crypto_alg_flags;
  int16_t crypto_alg_name;
  int16_t crypto_alg_compress;
  int16_t crypto_alg_init;
  int16_t crypto_tfm_ctx;
  int16_t crypto_alg_driver_name;
};

volatile struct struct_offset struct_offset __attribute__((section(".data.re_offsets"), used)) = {
    .crypto_alg_flags = -1,
    .crypto_alg_name = -1,
    .crypto_alg_compress = -1,
    .crypto_alg_init = -1,
    .crypto_tfm_ctx = -1,
    .crypto_alg_driver_name = -1,
};

#ifndef CONFIG_KPM_BASELINES
#include "zs_btf.c"
// 只保留入口参数的寄存器别名；未知写入保守失效。
static unsigned int parameter_regs_after(unsigned int regs, uint32_t inst) {
  if (inst_is_mov_reg(inst) && inst_get_mov_reg_sf(inst)) {
    unsigned int dest = 1U << inst_get_mov_reg_rd(inst);
    regs = (regs & (1U << inst_get_mov_reg_rm(inst))) ? regs | dest : regs & ~dest;
    return regs;
  }
  if (inst_is_bl(inst) || inst_is_blr(inst)) {
    regs &= 0x1ff80000U;
    return regs;
  }
  if (inst_is_b_cond(inst) || inst_is_cbz(inst) || inst_is_cbnz(inst) || inst_is_tbnz(inst) || inst_is_tbz(inst))
    return regs;
  if (inst_is_ldp(inst) || inst_is_stp(inst)) {
    if (inst_is_ldp(inst))
      regs &= ~((1U << inst_get_ldp_rt(inst)) | (1U << inst_get_ldp_rt2(inst)));
    int mode = inst_is_ldp(inst) ? inst_get_ldp_mode(inst) : inst_get_stp_mode(inst);
    int rn = inst_is_ldp(inst) ? inst_get_ldp_rn(inst) : inst_get_stp_rn(inst);
    if (mode == 1 || mode == 3)
      regs &= ~(1U << rn);
    return regs;
  }
  if (inst_is_ldr_imm9(inst) && (inst_get_ldr_imm9_mode(inst) & 1))
    regs &= ~(1U << inst_get_ldr_imm9_rn(inst));
  if (inst_is_str_imm9(inst) && (inst_get_str_imm9_mode(inst) & 1))
    regs &= ~(1U << inst_get_str_imm9_rn(inst));
  regs &= ~(1U << bits32(inst, 4, 0));
  return regs;
}

// 保留入口参数及 MOV 别名；BL 后只保留被调用方保存的寄存器。
static int find_parameter_access_min(const uint32_t* src, unsigned int count, bool store, int size, int minimum) {
  unsigned int regs = 1;
  for (unsigned int i = 0; i < count; i++) {
    uint32_t inst = src[i];
    if (inst_is_ret(inst) || inst_is_b(inst))
      break;
    if (store ? inst_is_str_imm_uint(inst) : inst_is_ldr_imm_uint(inst)) {
      int rn = store ? inst_get_str_imm_uint_rn(inst) : inst_get_ldr_imm_uint_rn(inst);
      int width = store ? inst_get_str_imm_uint_size(inst) : inst_get_ldr_imm_uint_size(inst);
      int offset = store ? inst_get_str_imm_uint_imm(inst) : inst_get_ldr_imm_uint_imm(inst);
      if ((regs & (1U << rn)) && width == size && offset >= minimum)
        return offset;
    }
    if (!store && size == 0 && inst_is_ldrb_imm_uint(inst) && (regs & (1U << inst_get_ldrb_imm_uint_rn(inst)))
        && inst_get_ldrb_imm_uint_imm(inst) >= minimum)
      return inst_get_ldrb_imm_uint_imm(inst);
    if (!store && size == 0 && inst_is_ldr_imm9(inst) && inst_get_ldr_imm9_size(inst) == 0
        && inst_get_ldr_imm9_opc(inst) == 1 && inst_get_ldr_imm9_mode(inst) == 3
        && (regs & (1U << inst_get_ldr_imm9_rn(inst))) && inst_get_ldr_imm9_imm9(inst) >= minimum)
      return inst_get_ldr_imm9_imm9(inst);
    regs = parameter_regs_after(regs, inst);
  }
  return -ENOENT;
}

static int find_parameter_access(const uint32_t* src, unsigned int count, bool store, int size) {
  return find_parameter_access_min(src, count, store, size, 0);
}

static int find_compress_callback(const uint32_t* src) {
  // tfm->__crt_alg 后允许最多三条 CFI 地址准备指令；算法寄存器必须仍保持原值。
  unsigned int regs = 1;
  for (unsigned int i = 0; i < 16; i++) {
    if (inst_is_ret(src[i]) || inst_is_b(src[i]) || inst_is_bl(src[i]) || inst_is_blr(src[i]))
      break;
    if (!inst_is_ldr_imm_uint(src[i]) || inst_get_ldr_imm_uint_size(src[i]) != 3
        || !(regs & (1U << inst_get_ldr_imm_uint_rn(src[i])))) {
      regs = parameter_regs_after(regs, src[i]);
      continue;
    }
    int alg = inst_get_ldr_imm_uint_rt(src[i]);
    for (unsigned int j = i + 1; j < 16 && j <= i + 4; j++) {
      if (inst_is_ldr_imm_uint(src[j]) && inst_get_ldr_imm_uint_size(src[j]) == 3
          && inst_get_ldr_imm_uint_rn(src[j]) == alg)
        return inst_get_ldr_imm_uint_imm(src[j]);
      if (inst_is_ret(src[j]) || inst_is_b(src[j]) || inst_is_bl(src[j]) || inst_is_blr(src[j])
          || !(parameter_regs_after(1U << alg, src[j]) & (1U << alg)))
        break;
    }
    return -ENOENT;
  }
  return -ENOENT;
}

static int find_cts_context(const uint32_t* src, uintptr_t destroy) {
  // CTS 的首个 ctx 成员是 child；销毁 child 时将同类对象的 base 传给 crypto_destroy_tfm。
  // parent->ctx = parent->base + tfm->__crt_ctx，两处实际偏移之差就是 __crt_ctx。
  unsigned int regs = 1;
  for (unsigned int i = 0; i + 2 < 8; i++) {
    uint32_t load = src[i], add = src[i + 1], call = src[i + 2];
    if (inst_is_ret(load) || inst_is_b(load) || inst_is_bl(load) || inst_is_blr(load) || inst_is_b_cond(load)
        || inst_is_cbz(load) || inst_is_cbnz(load) || inst_is_tbz(load) || inst_is_tbnz(load))
      break;
    if (inst_is_ldr_imm_uint(load) && inst_get_ldr_imm_uint_size(load) == 3 && inst_get_ldr_imm_uint_rt(load) == 0
        && (regs & (1U << inst_get_ldr_imm_uint_rn(load)))) {
      if (!inst_is_add_imm(add) || !inst_get_add_imm_sf(add) || inst_get_add_imm_rn(add) != 0
          || inst_get_add_imm_rd(add) != 1 || inst_get_add_imm_sh(add) || !inst_is_bl(call)
          || (uintptr_t)(src + i + 2) + inst_get_bl_label(call) != destroy)
        return -ENOENT;
      int ctx = inst_get_ldr_imm_uint_imm(load) - inst_get_add_imm_imm12(add);
      return ctx > 0 && ctx % 8 == 0 ? ctx : -ENOENT;
    }
    regs = parameter_regs_after(regs, load);
  }
  return -ENOENT;
}

static int calculate_function_offsets(void) {
  struct_offset.crypto_alg_flags = offsetof(struct zs_crypto_alg_prefix, cra_flags);
  logkm("crypto_alg_flags=0x%x\n", struct_offset.crypto_alg_flags);
  if (struct_offset.crypto_alg_flags < 0)
    return -ENOENT;
  struct_offset.crypto_alg_name = offsetof(struct zs_crypto_alg_prefix, cra_name);

  uint32_t* src = (uint32_t*)kallsyms_lookup_name_by_suffix("crypto_check_alg");
  // 独立 helper 的首个字节读取是 driver_name；内联版本在注册入口检查 name 后检查 driver_name。
  struct_offset.crypto_alg_driver_name = src ? find_parameter_access(src, 16, false, 0)
                                             : find_parameter_access_min((uint32_t*)kfunc(crypto_register_alg), 32,
                                                                         false, 0, struct_offset.crypto_alg_name + 1);
  logkm("crypto_alg_driver_name=0x%x\n", struct_offset.crypto_alg_driver_name);
  if (struct_offset.crypto_alg_driver_name < 0)
    return -ENOENT;

  src = (uint32_t*)kallsyms_lookup_name_by_suffix("crypto_compress");
  if (!src)
    src = (uint32_t*)kallsyms_lookup_name_by_suffix("crypto_comp_compress");
  if (!src)
    return -ENOENT;
  struct_offset.crypto_alg_compress = find_compress_callback(src);
  logkm("crypto_alg_compress=0x%x\n", struct_offset.crypto_alg_compress);
  if (struct_offset.crypto_alg_compress < 0)
    return -ENOENT;

  src = (uint32_t*)kallsyms_lookup_name_by_suffix("crypto_mod_get");
  if (!src)
    return -ENOENT;
  // 入口读取 cra_module；init、exit、destroy、module 是四个相邻指针。
  int module = find_parameter_access(src, 8, false, 3);
  int distance = offsetof(struct zs_alg_lifecycle, cra_module);
  struct_offset.crypto_alg_init = module < distance ? -1 : module - distance;
  logkm("crypto_alg_init=0x%x\n", struct_offset.crypto_alg_init);
  if (struct_offset.crypto_alg_init < 0)
    return -ENOENT;

  src = (uint32_t*)kallsyms_lookup_name_by_suffix("lzo_init");
  if (src) {
    struct_offset.crypto_tfm_ctx = find_parameter_access(src, 16, true, 3);
  } else {
    src = (uint32_t*)kallsyms_lookup_name_by_suffix("crypto_cts_exit_tfm");
    uintptr_t destroy = kallsyms_lookup_name_by_suffix("crypto_destroy_tfm");
    struct_offset.crypto_tfm_ctx = src && destroy ? find_cts_context(src, destroy) : -ENOENT;
  }
  logkm("crypto_tfm_ctx=0x%x\n", struct_offset.crypto_tfm_ctx);
  return struct_offset.crypto_tfm_ctx < 0 ? -ENOENT : 0;
}
#endif

static long calculate_offsets(void) {
#ifndef CONFIG_KPM_BASELINES
  int result = calculate_btf_offsets();
  if (result == -ENODATA)
    result = calculate_function_offsets();
  if (result)
    return result;
#endif
  if (struct_offset.crypto_alg_flags < 0 || struct_offset.crypto_alg_name < 0 || struct_offset.crypto_alg_compress < 0
      || struct_offset.crypto_alg_init < 0 || struct_offset.crypto_tfm_ctx < 0
      || struct_offset.crypto_alg_driver_name < 0)
    return -EINVAL;
  // 注册对象由内核写入；所有配置必须位于模块持有的存储内。
  int name_size = struct_offset.crypto_alg_driver_name - struct_offset.crypto_alg_name;
  if (name_size < (int)sizeof("zstd-kpm")
      || struct_offset.crypto_alg_flags != offsetof(struct zs_crypto_alg_prefix, cra_flags)
      || struct_offset.crypto_alg_name != offsetof(struct zs_crypto_alg_prefix, cra_name)
      || struct_offset.crypto_alg_driver_name + name_size > struct_offset.crypto_alg_compress
      || struct_offset.crypto_alg_driver_name + name_size > sizeof(zstd_alg)
      || sizeof(struct zs_crypto_alg_prefix) > sizeof(zstd_alg)
      || struct_offset.crypto_alg_compress + sizeof(struct zs_compress_alg) > sizeof(zstd_alg)
      || struct_offset.crypto_alg_init < struct_offset.crypto_alg_compress + sizeof(struct zs_compress_alg)
      || struct_offset.crypto_alg_init + sizeof(struct zs_alg_lifecycle) > sizeof(zstd_alg))
    return -EINVAL;
  return 0;
}
