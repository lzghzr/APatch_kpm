/* SPDX-License-Identifier: GPL-2.0-or-later */
static int nm_prepare_operation_sizes(void) {
#ifndef CONFIG_KPM_BASELINES
  nm_owned_operation_fallback = false;
  bool unavailable = false;
  int rc = calculate_btf_operation_sizes(&unavailable);
  if (rc == -ENODATA && unavailable) {
    nm_owned_operation_fallback = true;
    nm_log_info("layout: owned zero-table capacity=%d\n", NM_OWNED_OPERATIONS_CAPACITY);
    rc = calculate_function_operation_sizes();
    if (rc)
      return rc;
  } else if (rc) {
    return rc;
  }
#endif
  for (int kind = NM_FILE_OPS; kind <= NM_KEY_TYPE; kind++) {
    // key仅创建新表；其余类型还用于复制原表，继续要求完整尺寸。
    int size = kind == NM_KEY_TYPE ? nm_owned_operation_size(kind) : nm_operation_size(kind);
    if (size < 0)
      return -ENOENT;
    if (!size || size > 4096 || size % 8)
      return -EINVAL;
  }
  return 0;
}

// 原表按已证尺寸完整复制；自建清零表可使用独立容量，再由调用方填入回调。
static void* nm_new_operations(enum nm_ops_kind kind, const void* original) {
  int size = original ? nm_operation_size(kind) : nm_owned_operation_size(kind);
  if (size <= 0 || size > 4096 || size % 8)
    return ERR_PTR(-EINVAL);
  if (kind == NM_FILE_OPS && size < sizeof(struct nm_file_ops_head))
    return ERR_PTR(-EINVAL);
  void* copy = nm_zalloc(size);
  if (!copy)
    return ERR_PTR(-ENOMEM);
  if (original)
    memcpy(copy, original, size);
  if (kind == NM_FILE_OPS) {
    // KPM 常驻，owner 为 NULL；不构造原生 LKM 的 THIS_MODULE。
    ((struct nm_file_ops_head*)copy)->owner = NULL;
  }
  return copy;
}

// 仅供发布前失败路径；已发布的操作表随 KPM 驻留到重启。
static void nm_discard_operations(void* table) {
  if (!IS_ERR_OR_NULL(table))
    nm_free(table);
}
