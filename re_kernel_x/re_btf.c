static struct btf* kfunc_def(bpf_get_btf_vmlinux)(void);
static int kfunc_def(btf_find_by_name_kind)(const struct btf* btf, const char* name, u8 kind);
static const struct btf_type* kfunc_def(btf_type_by_id)(const struct btf* btf, u32 id);
static const char* kfunc_def(btf_name_by_offset)(const struct btf* btf, u32 offset);
static const struct btf_type* kfunc_def(btf_resolve_size)(const struct btf* btf, const struct btf_type* type,
                                                          u32* size);
static struct kpm_btf rekernel_btf;

static int rekernel_btf_release_abi() {
  const struct btf_type* func = kpm_btf_type(&rekernel_btf, "binder_transaction_buffer_release", 12);
  if (!func)
    return -ENOENT;
  const struct btf_type* proto = rekernel_btf.type_by_id(rekernel_btf.data, func->size);
  if (!proto || ((proto->info >> 24) & 31) != 13)
    return -EINVAL;
  u32 count = proto->info & 0xffff;
  if (count < 3 || count > 5)
    return -EINVAL;
  const struct btf_param* params = (const struct btf_param*)(proto + 1);
  // ABI3 的 failed_at 是指针；ABI5/6 的第四个参数同型，以参数名区分语义。
  u32 index = count == 5 ? 3 : 2, size = 0;
  const struct btf_type* arg = rekernel_btf.type_by_id(rekernel_btf.data, params[index].type);
  if (!arg)
    return -EINVAL;
  arg = rekernel_btf.resolve_size(rekernel_btf.data, arg, &size);
  if (!arg || IS_ERR(arg) || size != 8)
    return -EINVAL;
  u32 kind = (arg->info >> 24) & 31;
  if (count == 3)
    return kind == 2 ? 3 : -EINVAL;
  if (count == 4)
    return kind == 1 ? 4 : -EINVAL;
  if (kind != 1)
    return -EINVAL;
  const char* name = rekernel_btf.name_by_offset(rekernel_btf.data, params[3].name_off);
  if (name && !strcmp(name, "off_end_offset"))
    return 5;
  if (name && !strcmp(name, "failed_at"))
    return 6;
  return -EINVAL;
}

#define btf_type(name)                         \
  type = kpm_btf_type(&rekernel_btf, name, 4); \
  if (!type) {                                 \
    logkm("BTF type missing: %s\n", name);     \
    return -ENOENT;                            \
  }

#define btf_offset(field, member, width)                      \
  value = kpm_btf_offset(&rekernel_btf, type, member, width); \
  if (value < 0 || value > 0x7fff) {                          \
    logkm("BTF member invalid: %s\n", #field);                \
    return value < 0 ? value : -EINVAL;                       \
  }                                                           \
  struct_offset.field = value;                                \
  logkm("BTF %s=0x%x\n", #field, value);

#define btf_layout(member, offset, width)                                    \
  if (kpm_btf_offset(&rekernel_btf, type, member, width) != (int)(offset)) { \
    logkm("BTF shared layout changed: %s\n", member);                        \
    return -EINVAL;                                                          \
  }

static int calculate_btf_offsets() {
  kfunc_lookup_name(bpf_get_btf_vmlinux);
  kfunc_lookup_name(btf_find_by_name_kind);
  kfunc_lookup_name(btf_type_by_id);
  kfunc_lookup_name(btf_name_by_offset);
  kfunc_lookup_name(btf_resolve_size);
  if (!kfunc(bpf_get_btf_vmlinux) || !kfunc(btf_find_by_name_kind) || !kfunc(btf_type_by_id)
      || !kfunc(btf_name_by_offset) || !kfunc(btf_resolve_size))
    return -ENODATA;
  const struct btf* btf = kfunc(bpf_get_btf_vmlinux)();
  if (IS_ERR(btf))
    return PTR_ERR(btf);
  if (!btf)
    return -ENODATA;
  rekernel_btf = (struct kpm_btf){btf, kfunc(btf_find_by_name_kind), kfunc(btf_type_by_id), kfunc(btf_name_by_offset),
                                  kfunc(btf_resolve_size)};

  const struct btf_type* type;
  int value;
  btf_type("binder_alloc");
  btf_offset(binder_alloc_buffer_size, "buffer_size", 8);
  btf_offset(binder_alloc_buffer, "buffer", 8);
  btf_offset(binder_alloc_free_async_space, "free_async_space", 8);
  btf_offset(binder_alloc_pid, "pid", 4);

  btf_type("binder_node");
  btf_offset(binder_node_async_todo, "async_todo", 16);
  btf_offset(binder_node_cookie, "cookie", 8);
  btf_offset(binder_node_has_async_transaction, "has_async_transaction", 1);
  btf_offset(binder_node_lock, "lock", 0);
  btf_offset(binder_node_ptr, "ptr", 8);

  btf_type("binder_proc");
  btf_offset(binder_proc_alloc, "alloc", 0);
  btf_offset(binder_proc_context, "context", 8);
  btf_offset(binder_proc_inner_lock, "inner_lock", 0);
  btf_offset(binder_proc_is_dead, "is_dead", 1);
  btf_offset(binder_proc_is_frozen, "is_frozen", 1);
  btf_offset(binder_proc_outer_lock, "outer_lock", 0);
  btf_offset(binder_proc_outstanding_txns, "outstanding_txns", 4);
  btf_layout("pid", __builtin_offsetof(struct binder_proc, pid), 4);
  btf_layout("tsk", __builtin_offsetof(struct binder_proc, tsk), 8);

  btf_type("binder_thread");
  btf_layout("proc", __builtin_offsetof(struct binder_thread, proc), 8);
  btf_type("binder_transaction");
  btf_offset(binder_transaction_buffer, "buffer", 8);
  btf_offset(binder_transaction_code, "code", 4);
  btf_offset(binder_transaction_flags, "flags", 4);
  btf_offset(binder_transaction_from, "from", 8);
  btf_offset(binder_transaction_to_proc, "to_proc", 8);
  btf_layout("work", __builtin_offsetof(struct binder_transaction, work), 0);

  btf_type("binder_work");
  btf_layout("entry", __builtin_offsetof(struct binder_work, entry), 16);
  btf_layout("type", __builtin_offsetof(struct binder_work, type), 4);
  struct kpm_btf_field field;
  if (kpm_btf_member(&rekernel_btf, type, "type", &field, 0)
      || kpm_btf_enum(&rekernel_btf, field.type, "BINDER_WORK_TRANSACTION") != BINDER_WORK_TRANSACTION)
    return -EINVAL;

  btf_type("binder_buffer");
  btf_layout("transaction", __builtin_offsetof(struct binder_buffer, transaction), 8);
  btf_layout("target_node", __builtin_offsetof(struct binder_buffer, target_node), 8);
  btf_layout("data_size", __builtin_offsetof(struct binder_buffer, data_size), 8);
  btf_layout("offsets_size", __builtin_offsetof(struct binder_buffer, offsets_size), 8);
  btf_layout("extra_buffers_size", __builtin_offsetof(struct binder_buffer, extra_buffers_size), 8);
  btf_layout("pid", __builtin_offsetof(struct binder_buffer, pid), 4);
  if (kpm_btf_member(&rekernel_btf, type, "free", &field, 0) || field.bits != 1
      || field.offset != (sizeof(struct list_head) + sizeof(struct rb_node)) * 8)
    return -EINVAL;
  value = kpm_btf_offset(&rekernel_btf, type, "data", 8);
  if ((value < 0 && value != -ENOENT) || value > 0x7fff)
    return value < 0 ? value : -EINVAL;
  struct_offset.binder_buffer_data = value == -ENOENT ? -1 : value;

  btf_type("binder_stats");
  if (kpm_btf_member(&rekernel_btf, type, "obj_deleted", &field, 0) || field.bits || field.offset % 8)
    return -EINVAL;
  value = kpm_btf_enum(&rekernel_btf, kpm_btf_type(&rekernel_btf, "binder_stat_types", 6), "BINDER_STAT_TRANSACTION");
  if (value < 0 || ((unsigned int)value + 1) * sizeof(atomic_t) > field.size
      || field.offset / 8 + value * sizeof(atomic_t) > 0x7fff)
    return -EINVAL;
  struct_offset.binder_stats_deleted_transaction = field.offset / 8 + value * sizeof(atomic_t);
  logkm("BTF binder_stats_deleted_transaction=0x%x\n", struct_offset.binder_stats_deleted_transaction);

  btf_type("task_struct");
  btf_offset(task_struct_group_leader, "group_leader", 8);
  btf_offset(task_struct_jobctl, "jobctl", 8);
  btf_offset(task_struct_pid, "pid", 4);
  btf_offset(task_struct_tgid, "tgid", 4);
  btf_offset(task_struct_cred, "cred", 8);
  btf_offset(task_struct_comm, "comm", 16);
  btf_type("cred");
  btf_offset(cred_uid, "uid", 4);
  btf_type("sock");
  btf_offset(sock_sk_net, "__sk_common.skc_net.net", 8);

  btf_type("sk_buff");
  btf_offset(sk_buff_len, "len", 4);
  btf_offset(sk_buff_transport_header, "transport_header", 2);
  btf_offset(sk_buff_network_header, "network_header", 2);
  btf_offset(sk_buff_head, "head", 8);
  btf_offset(sk_buff_data, "data", 8);
  btf_offset(sk_buff_tail, "tail", 4);
  btf_layout("sk", __builtin_offsetof(struct sk_buff, sk), 8);
  btf_layout("cb", __builtin_offsetof(struct sk_buff, cb), 48);
  btf_type("netlink_skb_parms");
  btf_layout("creds.uid", __builtin_offsetof(struct netlink_skb_parms, creds.uid), 4);

  btf_type("net");
  btf_offset(net_genl_sock, "genl_sock", 8);
  btf_type("genl_family");
  if (type->size > sizeof(struct genl_family))
    return -EINVAL;
  btf_offset(genl_family_id, "id", 4);
  btf_offset(genl_family_config, "hdrsize", 4);
  btf_layout("name", struct_offset.genl_family_config + __builtin_offsetof(struct genl_family_config, name), 16);
  btf_layout("version", struct_offset.genl_family_config + __builtin_offsetof(struct genl_family_config, version), 4);
  btf_layout("maxattr", struct_offset.genl_family_config + __builtin_offsetof(struct genl_family_config, maxattr), 4);
  btf_offset(genl_family_mcgrps, "mcgrps", 8);
  btf_offset(genl_family_n_mcgrps, "n_mcgrps", 0);
  if (kpm_btf_member(&rekernel_btf, type, "n_mcgrps", &field, 0)
      || (field.size != 1 && field.size != 2 && field.size != 4))
    return -EINVAL;
  struct_offset.genl_family_n_mcgrps_size = field.size;
  btf_offset(genl_family_mcgrp_offset, "mcgrp_offset", 4);
  btf_type("genl_multicast_group");
  if (type->size > sizeof(struct genl_multicast_group))
    return -EINVAL;
  btf_layout("name", 0, 16);

  value = rekernel_btf_release_abi();
  if (value < 0)
    return value;
  struct_offset.binder_release_abi = value;
  logkm("BTF binder_release_abi=%d\n", value);
  return 0;
}

#undef btf_type
#undef btf_offset
#undef btf_layout
