/* SPDX-License-Identifier: GPL-2.0-or-later */
static void* nm_registered_key_type;
static int kfunc_def(nm_register_key_type)(struct key_type*);

static int nm_key_preparse(struct key_preparsed_payload* prep) {
  if (!prep)
    return -EINVAL;
  const struct nm_key_data* input = nm_key_preparse_input(prep);
  return nm_exchange_payload(input->data, input->datalen, nm_execute_payload);
}
static void nm_key_free_preparse(struct key_preparsed_payload* prep) {}
static int nm_key_instantiate(struct key* key, struct key_preparsed_payload* prep) { return -EINVAL; }

static int nm_register_control(void) {
  if (nm_registered_key_type)
    return -EALREADY;
  if (!nm_management_mutex || !nm_topology_ready)
    return -ENODEV;
  int rc = nm_validate_control_layout();
  if (rc)
    return rc;
  kfunc(nm_register_key_type) =
      (typeof(kfunc(nm_register_key_type)))kallsyms_lookup_name_by_suffix("register_key_type");
  if (!kfunc(nm_register_key_type))
    return -ENOENT;
  void* table = nm_new_operations(NM_KEY_TYPE, NULL);
  if (IS_ERR(table))
    return PTR_ERR(table);
  ((struct nm_key_type_head*)table)->name = "nomount";
  *nm_key_callback_table(table) = (struct nm_key_callbacks){nm_key_preparse, nm_key_free_preparse, nm_key_instantiate};
  rc = kfunc(nm_register_key_type)(table);
  if (rc) {
    nm_discard_operations(table);
    return rc;
  }
  // 注册为最后一步。内核已能调用表，成功后不得释放；模块驻留到重启。
  nm_registered_key_type = table;
  return 0;
}
