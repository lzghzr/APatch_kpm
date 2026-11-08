/* SPDX-License-Identifier: GPL-2.0-only */
/* Native frontend activation requires the complete live BTF contract, not a version number. */
static const struct btf_type* zs_native_unwrap(const struct kpm_btf* btf, u32 id) {
  for (unsigned int i = 0; i < 32; i++) {
    const struct btf_type* type = btf->type_by_id(btf->data, id);
    if (!type)
      return NULL;
    unsigned int kind = (type->info >> 24) & 31;
    if (kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18)
      return type;
    id = type->size;
  }
  return NULL;
}

static bool zs_native_pointer_to(const struct kpm_btf* btf, const struct btf_type* type, const char* name,
                                 unsigned int kind) {
  if (!type || ((type->info >> 24) & 31) != 2)
    return false;
  type = zs_native_unwrap(btf, type->size);
  if (!type || ((type->info >> 24) & 31) != kind)
    return false;
  const char* actual = btf->name_by_offset(btf->data, type->name_off);
  return actual && !strcmp(actual, name);
}

static bool zs_native_signature(const struct kpm_btf* btf, const struct btf_type* type, unsigned int count,
                                const char* const* params, const char* result) {
  if (!type || ((type->info >> 24) & 31) != 13 || (type->info & 65535) != count)
    return false;
  if (!result) {
    if (type->size)
      return false;
  } else {
    const struct btf_type* ret = zs_native_unwrap(btf, type->size);
    if (!ret || ((ret->info >> 24) & 31) != 1 || ret->size != (!strcmp(result, "_Bool") ? 1 : 4))
      return false;
    const char* actual = btf->name_by_offset(btf->data, ret->name_off);
    if (!actual || strcmp(actual, result))
      return false;
  }
  const struct btf_param* args = (const struct btf_param*)(type + 1);
  for (unsigned int i = 0; i < count; i++) {
    const struct btf_type* arg = zs_native_unwrap(btf, args[i].type);
    if (!zs_native_pointer_to(btf, arg, params[i], !strcmp(params[i], "char") ? 1 : 4))
      return false;
  }
  return true;
}

struct zs_native_field {
  const char* name;
  unsigned int offset, size;
};

static bool zs_native_layout(const struct kpm_btf* btf, const char* name, unsigned int size,
                             const struct zs_native_field* fields, unsigned int count) {
  const struct btf_type* type = kpm_btf_type(btf, name, 4);
  if (!type || type->size != size || (type->info & 65535) != count)
    return false;
  for (unsigned int i = 0; i < count; i++) {
    struct kpm_btf_field field;
    if (kpm_btf_member(btf, type, fields[i].name, &field, 0) || field.bits || field.offset != fields[i].offset * 8
        || field.size != fields[i].size)
      return false;
  }
  return true;
}

static bool zs_native_layouts(const struct kpm_btf* btf) {
  const struct zs_native_field comp[] = {{"stream", 0, 8}, {"ops", 8, 8}, {"params", 16, 8}, {"node", 24, 16}};
  const struct zs_native_field ops[] = {{"compress", 0, 8},     {"decompress", 8, 8},    {"create_ctx", 16, 8},
                                        {"destroy_ctx", 24, 8}, {"setup_params", 32, 8}, {"release_params", 40, 8},
                                        {"name", 48, 8}};
  const struct zs_native_field params[] = {{"dict", 0, 8}, {"dict_sz", 8, 8}, {"level", 16, 4}, {"drv_data", 24, 8}};
  const struct zs_native_field req[] = {{"src", 0, 8}, {"src_len", 8, 8}, {"dst", 16, 8}, {"dst_len", 24, 8}};
  const struct zs_native_field ctx[] = {{"context", 0, 8}};
  const struct zs_native_field strm[] = {{"lock", 0, 0}, {"buffer", 0, 8}, {"local_copy", 8, 8}, {"ctx", 16, 8}};
  if (!zs_native_layout(btf, "zcomp", sizeof(struct zcomp), comp, 4)
      || !zs_native_layout(btf, "zcomp_ops", sizeof(struct zcomp_ops), ops, 7)
      || !zs_native_layout(btf, "zcomp_params", sizeof(struct zcomp_params), params, 4)
      || !zs_native_layout(btf, "zcomp_req", sizeof(struct zcomp_req), req, 4)
      || !zs_native_layout(btf, "zcomp_ctx", sizeof(struct zcomp_ctx), ctx, 1)
      || !zs_native_layout(btf, "zcomp_strm", sizeof(struct zcomp_strm), strm, 4))
    return false;
  const struct btf_type* type = kpm_btf_type(btf, "zcomp_ops", 4);
  const char* const three[] = {"zcomp_params", "zcomp_ctx", "zcomp_req"};
  const char* const two[] = {"zcomp_params", "zcomp_ctx"};
  const char* const context[] = {"zcomp_ctx"};
  const char* const param[] = {"zcomp_params"};
  for (unsigned int i = 0; i < 6; i++) {
    struct kpm_btf_field field;
    if (kpm_btf_member(btf, type, ops[i].name, &field, 0) || ((field.type->info >> 24) & 31) != 2)
      return false;
    const struct btf_type* proto = zs_native_unwrap(btf, field.type->size);
    if (!zs_native_signature(btf, proto,
                             i < 2    ? 3
                             : i == 2 ? 2
                                      : 1,
                             i < 2    ? three
                             : i == 2 ? two
                             : i == 3 ? context
                                      : param,
                             i == 3 || i == 5 ? NULL : "int"))
      return false;
  }
  /* Distinguishes native create(name, params) from legacy create(name). */
  const struct btf_type* create = kpm_btf_type(btf, "zcomp_create", 12);
  create = create ? zs_native_unwrap(btf, create->size) : NULL;
  if (!create || ((create->info >> 24) & 31) != 13 || (create->info & 65535) != 2
      || !zs_native_pointer_to(btf, zs_native_unwrap(btf, create->size), "zcomp", 4))
    return false;
  const struct btf_param* args = (const struct btf_param*)(create + 1);
  if (!zs_native_pointer_to(btf, zs_native_unwrap(btf, args[0].type), "char", 1)
      || !zs_native_pointer_to(btf, zs_native_unwrap(btf, args[1].type), "zcomp_params", 4))
    return false;
  const struct btf_type* available = kpm_btf_type(btf, "zcomp_available_algorithm", 12);
  available = available ? zs_native_unwrap(btf, available->size) : NULL;
  const char* const name[] = {"char"};
  return zs_native_signature(btf, available, 1, name, "_Bool");
}

static bool zs_native_gfp(const struct kpm_btf* btf) {
  const char* names[] = {"___GFP_IO_BIT", "___GFP_FS_BIT", "___GFP_DIRECT_RECLAIM_BIT", "___GFP_KSWAPD_RECLAIM_BIT",
                         "___GFP_ZERO_BIT"};
  unsigned int mask = 0, zero = 0;
  for (u32 id = 1; id < 262144; id++) {
    const struct btf_type* type = btf->type_by_id(btf->data, id);
    if (!type) {
      native_gfp = mask;
      native_gfp_zero = mask | zero;
      return mask && zero;
    }
    if (((type->info >> 24) & 31) != 6 || type->size != 4 || kpm_btf_enum(btf, type, names[0]) < 0)
      continue;
    unsigned int bits = 0, extra = 0;
    for (unsigned int i = 0; i < 5; i++) {
      int bit = kpm_btf_enum(btf, type, names[i]);
      if (bit < 0 || bit > 31 || ((bits | extra) & (1U << bit)))
        return false;
      if (i == 4)
        extra = 1U << bit;
      else
        bits |= 1U << bit;
    }
    if ((mask && mask != bits) || (zero && zero != extra))
      return false;
    mask = bits;
    zero = extra;
  }
  return false;
}

static bool zs_native_validate(struct module* owner, const char* marker_name, const struct zcomp_ops* marker) {
  struct kpm_btf base;
  if (!zs_page_size || !owner || kpm_btf_init(&base))
    return false;
  const struct btf_type* module_type = kpm_btf_type(&base, "module", 4);
  struct kpm_btf_field module_name;
  if (kpm_btf_member(&base, module_type, "name", &module_name, 0) || module_name.bits || module_name.offset % 8
      || module_name.size < 5 || kpm_btf_offset(&base, module_type, "state", 4) != 0
      || memcmp((const u8*)owner + module_name.offset / 8, "zram", 5))
    return false;
#define ZS_NATIVE_LOOKUP(field, symbol) field = (typeof(field))kallsyms_lookup_name_by_suffix(symbol)
  ZS_NATIVE_LOOKUP(native_module_btf, "btf_get_module_btf");
  ZS_NATIVE_LOOKUP(native_btf_put, "btf_put");
  ZS_NATIVE_LOOKUP(native_module_get, "try_module_get");
  ZS_NATIVE_LOOKUP(native_module_put, "module_put");
  ZS_NATIVE_LOOKUP(native_module_address, "__module_address");
  ZS_NATIVE_LOOKUP(native_kmalloc, "__kmalloc_noprof");
  ZS_NATIVE_LOOKUP(native_kfree, "kfree");
  ZS_NATIVE_LOOKUP(native_percpu_alloc, "pcpu_alloc_noprof");
  ZS_NATIVE_LOOKUP(native_percpu_free, "free_percpu");
  ZS_NATIVE_LOOKUP(native_cpuhp_add, "__cpuhp_state_add_instance");
#undef ZS_NATIVE_LOOKUP
  if (!native_module_btf || !native_btf_put || !native_module_address || !native_kmalloc || !native_kfree
      || !native_percpu_alloc || !native_percpu_free || !native_cpuhp_add
      || (owner && (!native_module_get || !native_module_put)) || native_module_address((unsigned long)marker) != owner)
    return false;
  struct btf* data = native_module_btf(owner);
  if (IS_ERR_OR_NULL(data))
    return false;
  struct kpm_btf module = base;
  module.data = data;
  bool valid = zs_native_layouts(&module);
  native_btf_put(data);
  const u32 expected[] = {0x6cfa6c9d, 0x6cfa6c9d, 0x99e4d7cb, 0x719f1be7, 0x819d5c54, 0xef7e90ea};
  if (valid) {
    /* Module BTF may omit VAR records. Resolve qualified functions instead of reading an untyped object. */
    const char* suffixes[] = {"compress", "decompress", "create", "destroy", "setup_params", "release_params"};
    for (unsigned int i = 0; i < 6; i++) {
      char name[64] = "zram:";
      size_t prefix = strlen(marker_name + 8), suffix = strlen(suffixes[i]);
      if (5 + prefix + 1 + suffix + 1 > sizeof(name))
        return false;
      memcpy(name + 5, marker_name + 8, prefix);
      name[5 + prefix] = '_';
      memcpy(name + 6 + prefix, suffixes[i], suffix + 1);
      uintptr_t callback = native_module_symbol(name);
      if (callback < 4 || callback % 4 || display_module_text(callback) != owner
          || display_module_text(callback - 4) != owner) {
        valid = false;
        break;
      }
      u32 tag;
      memcpy(&tag, (const void*)(callback - 4), sizeof(tag));
      if (tag != expected[i]) {
        valid = false;
        break;
      }
    }
  }
  const struct btf_type* cpuhp = kpm_btf_type(&base, "cpuhp_state", 6);
  native_cpuhp_state = kpm_btf_enum(&base, cpuhp, "CPUHP_ZCOMP_PREPARE");
  if (!valid || native_cpuhp_state < 0 || !zs_native_gfp(&base))
    return false;
  return true;
}
