/* Developer synthetic BTF: exercises dispatch/contracts, not target-layout proof. */
static int btf_mode;
static struct {
  struct btf_type type;
  struct btf_member members[8];
} host_alg;
static struct {
  struct btf_type type;
  struct btf_member members[1];
} host_tfm, host_union;
static struct {
  struct btf_type type;
  struct btf_member members[2];
} host_callbacks;
static struct btf_type host_scalar = {0, 1U << 24, 4}, host_pointer = {0, 2U << 24, 8};
static struct btf_type host_names = {0, 3U << 24, 64}, host_ctx = {0, 3U << 24, 0};
static const char* host_names_table[] = {"",         "cra_flags",    "cra_ctxsize",   "cra_name",   "cra_driver_name",
                                         "cra_u",    "cra_init",     "cra_exit",      "cra_module", "__crt_ctx",
                                         "compress", "coa_compress", "coa_decompress"};
static struct btf* host_data(void) {
  return btf_mode == 2 ? NULL : btf_mode == 3 ? (struct btf*)(intptr_t)-EIO : (struct btf*)&host_alg;
}
static int host_find(const struct btf* data, const char* name, u8 kind) {
  if (btf_mode == 4)
    return -ENOENT;
  return !strcmp(name, "crypto_alg") ? 1 : !strcmp(name, "crypto_tfm") ? 2 : -ENOENT;
}
static const struct btf_type* host_type(const struct btf* data, u32 id) {
  const struct btf_type* types[] = {
      NULL,         &host_alg.type, &host_tfm.type, &host_union.type, &host_callbacks.type,
      &host_scalar, &host_pointer,  &host_names,    &host_ctx};
  return id < sizeof(types) / sizeof(types[0]) ? types[id] : NULL;
}
static const char* host_name(const struct btf* data, u32 id) {
  return id < sizeof(host_names_table) / sizeof(host_names_table[0]) ? host_names_table[id] : NULL;
}
static const struct btf_type* host_size(const struct btf* data, const struct btf_type* type, u32* size) {
  *size = type->size;
  return type;
}
static void* btf_lookup(const char* name) {
  if (!btf_mode)
    return NULL;
  if (!strcmp(name, "bpf_get_btf_vmlinux"))
    return host_data;
  if (!strcmp(name, "btf_find_by_name_kind"))
    return host_find;
  if (!strcmp(name, "btf_type_by_id"))
    return host_type;
  if (!strcmp(name, "btf_name_by_offset"))
    return host_name;
  if (!strcmp(name, "btf_resolve_size"))
    return host_size;
  return NULL;
}
static void host_layout(unsigned int length) {
  host_names.size = length;
  unsigned int callback = 0x40 + length * 2, init = callback + 0x40;
  host_alg.type = (struct btf_type){0, 4U << 24 | 8, 1024};
  struct btf_member members[] = {
      {1, 5, 0x20 * 8},     {2, 5, 0x28 * 8}, {3, 7, 0x38 * 8},       {4, 7, (0x38 + length) * 8},
      {5, 3, callback * 8}, {6, 6, init * 8}, {7, 6, (init + 8) * 8}, {8, 6, (init + 24) * 8}};
  memcpy(host_alg.members, members, sizeof(members));
  host_tfm.type = (struct btf_type){0, 4U << 24 | 1, 128};
  host_tfm.members[0] = (struct btf_member){9, 8, 0x80 * 8};
  host_union.type = (struct btf_type){0, 5U << 24 | 1, 16};
  host_union.members[0] = (struct btf_member){10, 4, 0};
  host_callbacks.type = (struct btf_type){0, 4U << 24 | 2, 16};
  host_callbacks.members[0] = (struct btf_member){11, 6, 0};
  host_callbacks.members[1] = (struct btf_member){12, 6, 64};
}
