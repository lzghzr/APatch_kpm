/* SPDX-License-Identifier: GPL-2.0-only */

static void* display_module_mutex;
static void (*display_mutex_lock)(void*);
static void (*display_mutex_unlock)(void*);
static struct module* (*display_module_text)(unsigned long);
static int (*display_core_text)(unsigned long);
static bool display_installed;

static bool display_has_algorithm(const char* buf, size_t len) {
  for (size_t start = 0; start < len;) {
    while (start < len && (buf[start] == ' ' || buf[start] == '\t' || buf[start] == '\n')) start++;
    size_t end = start;
    while (end < len && buf[end] != ' ' && buf[end] != '\t' && buf[end] != '\n') end++;
    if ((end - start == 8 && !memcmp(buf + start, "zstd-kpm", 8))
        || (end - start == 10 && !memcmp(buf + start, "[zstd-kpm]", 10)))
      return true;
    start = end;
  }
  return false;
}

static void zstd_list_after(hook_fargs2_t* args, void* udata) {
  char* buf = (char*)args->arg1;
  long size = (long)args->ret;
  // sysfs 页缓冲区也可能传入已用前缀后的地址（recomp_algorithm）。
  // 限于当前 4 KiB 子页，适用于 ARM64 的 4/16/64 KiB 页，不跨过剩余空间。
  size_t capacity = 4096 - ((uintptr_t)buf & 4095);
  if (!buf || size <= 0 || (size_t)size >= capacity || buf[size - 1] != '\n' || display_has_algorithm(buf, size))
    return;
  size_t prefix = size - 1;
  bool space = prefix && buf[prefix - 1] != ' ' && buf[prefix - 1] != '\t';
  static const char suffix[] = "zstd-kpm\n";
  if (prefix + space + sizeof(suffix) > capacity)
    return;
  if (space)
    buf[prefix++] = ' ';
  memcpy(buf + prefix, suffix, sizeof(suffix));
  args->ret = prefix + sizeof(suffix) - 1;
}

static void install_zram_display(void) {
  display_mutex_lock(display_module_mutex);
  if (__atomic_load_n(&display_installed, __ATOMIC_ACQUIRE)) {
    display_mutex_unlock(display_module_mutex);
    return;
  }
  void* target = (void*)kallsyms_lookup_name_by_suffix("zcomp_available_show");
  if (target) {
    // 原生接口允许在 module_mutex 下查询；COMING 模块不能留下 hook。
    struct module* owner = display_module_text((unsigned long)target);
    bool ready =
        owner ? ((struct zs_module_prefix*)owner)->state == ZS_MODULE_LIVE : display_core_text((unsigned long)target);
    if (ready) {
      int rc = hook_wrap(target, 2, NULL, zstd_list_after, NULL);
      if (!rc) {
        __atomic_store_n(&display_installed, true, __ATOMIC_RELEASE);
        logkm("zram algorithm list now includes zstd-kpm\n");
      } else {
        logkm("algorithm list hook failed: %d; select zstd-kpm directly\n", rc);
      }
    }
  }
  display_mutex_unlock(display_module_mutex);
}

static void zram_module_after(hook_fargs1_t* args, void* udata) {
  if ((int)args->ret || __atomic_load_n(&display_installed, __ATOMIC_ACQUIRE))
    return;
  install_zram_display();
}

static void start_zram_display(void) {
  display_module_mutex = (void*)kallsyms_lookup_name_by_suffix("module_mutex");
  display_mutex_lock = (typeof(display_mutex_lock))kallsyms_lookup_name_by_suffix("mutex_lock");
  display_mutex_unlock = (typeof(display_mutex_unlock))kallsyms_lookup_name_by_suffix("mutex_unlock");
  display_module_text = (typeof(display_module_text))kallsyms_lookup_name_by_suffix("__module_text_address");
  display_core_text = (typeof(display_core_text))kallsyms_lookup_name_by_suffix("core_kernel_text");
  if (!display_module_mutex || !display_mutex_lock || !display_mutex_unlock || !display_module_text
      || !display_core_text) {
    logkm("algorithm list helpers unavailable; select zstd-kpm directly\n");
    return;
  }
  // 先接入加载完成事件，再检查已有目标，覆盖这两个步骤之间的成功加载。
  void* init_module = (void*)kallsyms_lookup_name_by_suffix("do_init_module");
  if (!init_module || hook_wrap(init_module, 1, NULL, zram_module_after, NULL))
    logkm("module load hook unavailable; updating the current zram list only\n");
  install_zram_display();
}
