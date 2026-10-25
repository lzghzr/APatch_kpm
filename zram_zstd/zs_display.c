/* SPDX-License-Identifier: GPL-2.0-only */

static void* display_module_mutex;
static void (*display_mutex_lock)(void*);
static void (*display_mutex_unlock)(void*);
static struct module* (*display_module_text)(unsigned long);
static int (*display_core_text)(unsigned long);
static bool display_installed;

static bool display_space(char c) { return c == ' ' || c == '\t' || c == '\n'; }

static bool display_token(const char* token, size_t len, const char* name) {
  size_t size = strlen(name);
  return (len == size && !memcmp(token, name, size))
         || (len == size + 2 && token[0] == '[' && token[len - 1] == ']' && !memcmp(token + 1, name, size));
}

static void zstd_list_after(hook_fargs2_t* args, void* udata) {
  char* buf = (char*)args->arg1;
  long size = (long)args->ret;
  // recomp_algorithm可能传入页内地址；保守限于当前4 KiB子页，不跨页。
  size_t capacity = 4096 - ((uintptr_t)buf & 4095);
  if (!buf || size <= 0 || (size_t)size >= capacity || buf[size - 1] != '\n')
    return;
  const char* names[] = {ZS_ZSTD_NAME, ZS_LZ4_NAME};
  bool found[2] = {false, false};
  size_t needed = 0;
  // 先计算完整结果；容量不足时保留原列表，不追加半个token。
  for (size_t start = 0; start < size;) {
    while (start < size && display_space(buf[start])) start++;
    size_t end = start;
    while (end < size && !display_space(buf[end])) end++;
    size_t len = end - start;
    if (len) {
      needed += (needed != 0) + len;
      for (unsigned int i = 0; i < 2; i++)
        if (display_token(buf + start, len, names[i]))
          found[i] = true;
    }
    start = end;
  }
  for (unsigned int i = 0; i < 2; i++)
    if (!found[i] && algorithm_registered[i])
      needed += (needed != 0) + strlen(names[i]);
  if (needed + 2 > capacity)  // newline + NUL
    return;
  size_t written = 0;
  // 先压紧保留项，写指针不超过读指针；最后才追加较长的主名。
  for (size_t start = 0; start < size;) {
    while (start < size && display_space(buf[start])) start++;
    size_t end = start;
    while (end < size && !display_space(buf[end])) end++;
    size_t len = end - start;
    if (len) {
      if (written)
        buf[written++] = ' ';
      memmove(buf + written, buf + start, len);
      written += len;
    }
    start = end;
  }
  for (unsigned int i = 0; i < 2; i++) {
    if (found[i] || !algorithm_registered[i])
      continue;
    if (written)
      buf[written++] = ' ';
    size_t len = strlen(names[i]);
    memcpy(buf + written, names[i], len);
    written += len;
  }
  buf[written++] = '\n';
  buf[written] = 0;
  args->ret = written;
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
        logkm("zram algorithm list now includes KPM codecs\n");
      } else {
        logkm("algorithm list hook failed: %d; select KPM codec names directly\n", rc);
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
    logkm("algorithm list helpers unavailable; select KPM codec names directly\n");
    return;
  }
  // 先接入加载完成事件，再检查已有目标，覆盖这两个步骤之间的成功加载。
  void* init_module = (void*)kallsyms_lookup_name_by_suffix("do_init_module");
  if (!init_module || hook_wrap(init_module, 1, NULL, zram_module_after, NULL))
    logkm("module load hook unavailable; updating the current zram list only\n");
  install_zram_display();
}
