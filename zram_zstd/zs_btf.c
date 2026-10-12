static struct btf* kfunc_def(bpf_get_btf_vmlinux)(void);
static int kfunc_def(btf_find_by_name_kind)(const struct btf*, const char*, u8);
static const struct btf_type* kfunc_def(btf_type_by_id)(const struct btf*, u32);
static const char* kfunc_def(btf_name_by_offset)(const struct btf*, u32);
static const struct btf_type* kfunc_def(btf_resolve_size)(const struct btf*, const struct btf_type*, u32*);

static int calculate_btf_offsets(void) {
  kfunc_lookup_name(bpf_get_btf_vmlinux);
  kfunc_lookup_name(btf_find_by_name_kind);
  kfunc_lookup_name(btf_type_by_id);
  kfunc_lookup_name(btf_name_by_offset);
  kfunc_lookup_name(btf_resolve_size);
  if (!kfunc(bpf_get_btf_vmlinux) || !kfunc(btf_find_by_name_kind) || !kfunc(btf_type_by_id)
      || !kfunc(btf_name_by_offset) || !kfunc(btf_resolve_size))
    return -ENODATA;
  const struct btf* data = kfunc(bpf_get_btf_vmlinux)();
  if (IS_ERR(data))
    return PTR_ERR(data);
  if (!data)
    return -ENODATA;
  struct kpm_btf btf = {data, kfunc(btf_find_by_name_kind), kfunc(btf_type_by_id), kfunc(btf_name_by_offset),
                        kfunc(btf_resolve_size)};
  const struct btf_type* alg = kpm_btf_type(&btf, "crypto_alg", 4);
  const struct btf_type* tfm = kpm_btf_type(&btf, "crypto_tfm", 4);
  if (!alg || !tfm) {
    logkm("BTF: crypto_alg or crypto_tfm missing\n");
    return -ENOENT;
  }
  int flags = kpm_btf_offset(&btf, alg, "cra_flags", 4);
  int compress = kpm_btf_offset(&btf, alg, "cra_u.compress.coa_compress", 8);
  int init = kpm_btf_offset(&btf, alg, "cra_init", 8);
  int ctx = kpm_btf_offset(&btf, tfm, "__crt_ctx", 0);
  struct kpm_btf_field name, driver;
  if (flags < 0 || compress < 0 || init < 0 || ctx < 0 || flags > 0x7fff || compress > 0x7fff || init > 0x7fff
      || ctx > 0x7fff || kpm_btf_member(&btf, alg, "cra_name", &name, 0)
      || kpm_btf_member(&btf, alg, "cra_driver_name", &driver, 0) || name.bits || driver.bits || name.offset % 8
      || driver.offset % 8 || name.size < sizeof("zstd-kpm") || driver.size != name.size || name.offset / 8 > 0x7fff
      || driver.offset / 8 > 0x7fff || driver.offset != name.offset + name.size * 8)
    return -EINVAL;
  // 注册填写这些连续片段；BTF 必须确认大小、顺序与宽度。
  if (alg->size > sizeof(zstd_alg) || flags != offsetof(struct zs_crypto_alg_prefix, cra_flags)
      || kpm_btf_offset(&btf, alg, "cra_ctxsize", 4) != offsetof(struct zs_crypto_alg_prefix, cra_ctxsize)
      || name.offset / 8 != offsetof(struct zs_crypto_alg_prefix, cra_name)
      || kpm_btf_offset(&btf, alg, "cra_u.compress.coa_decompress", 8)
             != compress + offsetof(struct zs_compress_alg, coa_decompress)
      || kpm_btf_offset(&btf, alg, "cra_exit", 8) != init + offsetof(struct zs_alg_lifecycle, cra_exit)
      || kpm_btf_offset(&btf, alg, "cra_module", 8) != init + offsetof(struct zs_alg_lifecycle, cra_module))
    return -EINVAL;
  struct_offset.crypto_alg_flags = offsetof(struct zs_crypto_alg_prefix, cra_flags);
  struct_offset.crypto_alg_name = offsetof(struct zs_crypto_alg_prefix, cra_name);
  struct_offset.crypto_alg_driver_name = driver.offset / 8;
  struct_offset.crypto_alg_compress = compress;
  struct_offset.crypto_alg_init = init;
  struct_offset.crypto_tfm_ctx = ctx;
  logkm("BTF: flags=0x%x name=0x%x driver=0x%x compress=0x%x init=0x%x ctx=0x%x\n", flags,
        struct_offset.crypto_alg_name, struct_offset.crypto_alg_driver_name, compress, init, ctx);
  return 0;
}
