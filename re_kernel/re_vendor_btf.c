// 厂商 record 钩子在完整拷贝后、入队加锁前触发；同型 t/in_reply_to 还须核对参数名。
static int binder_vendor_record_abi(void) {
#ifdef CONFIG_KPM_BASELINES
  // 静态移植已离线核对回调／释放 ABI；未配置引用字段时不启用该能力。
  return struct_offset.binder_proc_tmp_ref > 0 && struct_offset.binder_proc_tmp_ref % sizeof(int) == 0 ? 0 : -EINVAL;
#else
  struct kpm_btf btf;
  int rc = kpm_btf_init(&btf);
  if (rc)
    return rc;
  const struct btf_type* func = kpm_btf_type(&btf, "__traceiter_android_vh_binder_transaction_record", 12);
  if (!func)
    return -ENOENT;
  const struct btf_type* proto = btf.type_by_id(btf.data, func->size);
  if (!proto || ((proto->info >> 24) & 31) != 13 || (proto->info & 0xffff) != 4)
    return -EINVAL;
  const struct btf_param* params = (const struct btf_param*)(proto + 1);
  const char* types[] = {NULL, "binder_transaction_data", "binder_transaction", "binder_transaction"};
  const char* names[] = {"__data", "tr", "t", "in_reply_to"};
  for (unsigned int i = 0; i < 4; i++) {
    const char* name = btf.name_by_offset(btf.data, params[i].name_off);
    if (!name || strcmp(name, names[i]))
      return -EINVAL;
    const struct btf_type* type = btf.type_by_id(btf.data, params[i].type);
    u32 size = 0;
    if (!type)
      return -EINVAL;
    type = btf.resolve_size(btf.data, type, &size);
    if (!type || IS_ERR(type) || ((type->info >> 24) & 31) != 2 || size != sizeof(void*))
      return -EINVAL;
    if (!i) {
      if (type->size)
        return -EINVAL;
      continue;
    }
    type = btf.type_by_id(btf.data, type->size);
    if (!type)
      return -EINVAL;
    type = btf.resolve_size(btf.data, type, &size);
    if (!type || IS_ERR(type) || ((type->info >> 24) & 31) != 4)
      return -EINVAL;
    name = btf.name_by_offset(btf.data, type->name_off);
    if (!name || strcmp(name, types[i]))
      return -EINVAL;
  }
  func = kpm_btf_type(&btf, "binder_proc_dec_tmpref", 12);
  if (!func)
    return -ENOENT;
  proto = btf.type_by_id(btf.data, func->size);
  if (!proto || ((proto->info >> 24) & 31) != 13 || (proto->info & 0xffff) != 1 || proto->size)
    return -EINVAL;
  params = (const struct btf_param*)(proto + 1);
  const struct btf_type* type = btf.type_by_id(btf.data, params[0].type);
  u32 size = 0;
  if (!type)
    return -EINVAL;
  type = btf.resolve_size(btf.data, type, &size);
  if (!type || IS_ERR(type) || ((type->info >> 24) & 31) != 2 || size != sizeof(void*))
    return -EINVAL;
  type = btf.type_by_id(btf.data, type->size);
  if (!type)
    return -EINVAL;
  type = btf.resolve_size(btf.data, type, &size);
  if (!type || IS_ERR(type) || ((type->info >> 24) & 31) != 4)
    return -EINVAL;
  const char* name = btf.name_by_offset(btf.data, type->name_off);
  if (!name || strcmp(name, "binder_proc"))
    return -EINVAL;
  struct kpm_btf_field field;
  if (kpm_btf_member(&btf, type, "tmp_ref", &field, 0) || field.bits || field.size != sizeof(int) || field.offset % 32
      || !field.offset || field.offset / 8 > 0x7fff || ((field.type->info >> 24) & 31) != 1
      || !(*(const u32*)(field.type + 1) & (1U << 24)))
    return -EINVAL;
  struct_offset.binder_proc_tmp_ref = field.offset / 8;
  return 0;
#endif
}
