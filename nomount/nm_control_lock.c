/* SPDX-License-Identifier: GPL-2.0-or-later */
static struct mutex* nm_management_mutex;
static void kfunc_def(nm_mutex_init)(struct mutex*, const char*, struct lock_class_key*);
static void kfunc_def(nm_mutex_lock)(struct mutex*);
static void kfunc_def(nm_mutex_unlock)(struct mutex*);

static int nm_prepare_management_mutex(void) {
  if (nm_management_mutex)
    return -EALREADY;
  int rc = nm_validate_control_layout();
  if (rc)
    return rc;
  kfunc(nm_mutex_init) = (typeof(kfunc(nm_mutex_init)))kallsyms_lookup_name_by_suffix("__mutex_init");
  kfunc(nm_mutex_lock) = (typeof(kfunc(nm_mutex_lock)))kallsyms_lookup_name_by_suffix("mutex_lock");
  kfunc(nm_mutex_unlock) = (typeof(kfunc(nm_mutex_unlock)))kallsyms_lookup_name_by_suffix("mutex_unlock");
  if (!kfunc(nm_mutex_init) || !kfunc(nm_mutex_lock) || !kfunc(nm_mutex_unlock))
    return -ENOENT;
  struct mutex* lock = nm_zalloc(struct_offset.mutex_size);
  if (!lock)
    return -ENOMEM;
  // 已证实mutex无dep_map，原生初始化不使用class key；完整尺寸内存归模块持有。
  kfunc(nm_mutex_init)(lock, "nomount_management", NULL);
  nm_management_mutex = lock;
  return 0;
}
static void nm_management_lock(void) { kfunc(nm_mutex_lock)(nm_management_mutex); }
static void nm_management_unlock(void) { kfunc(nm_mutex_unlock)(nm_management_mutex); }
// 仅在控制入口尚未发布、没有任何调用者时使用。
static void nm_discard_management_mutex(void) {
  nm_free(nm_management_mutex);
  nm_management_mutex = NULL;
}
