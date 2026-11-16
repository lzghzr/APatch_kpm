/* SPDX-License-Identifier: GPL-2.0-only */
/* Native namespace mutations must not consume NoMount's synthetic inodes. */
static bool nm_mutation_ready;
static bool nm_mutation_installed[4];
static void* nm_mutation_targets[4];

static bool nm_mutation_virtual(struct dentry* dentry) {
  struct inode* inode = dentry ? nm_dentry_inode(dentry) : NULL;
  return inode && nm_is_virtual_inode(inode);
}

// 原生 VFS 已解析当前调用者的 dentry；不按规则名或历史缓存替它重新判断视图。
static void nm_mutation_remove(hook_fargs2_t* args, void* unused) {
  if (args->skip_origin && (int)args->ret < 0)
    return;
  if (nm_is_virtual_inode((void*)args->arg0) || nm_mutation_virtual((void*)args->arg1)) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)-EPERM;
  }
}
static void nm_mutation_link(hook_fargs3_t* args, void* unused) {
  if (args->skip_origin && (int)args->ret < 0)
    return;
  if (nm_mutation_virtual((void*)args->arg0) || nm_is_virtual_inode((void*)args->arg1)) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)-EPERM;
  }
}
static void nm_mutation_rename(hook_fargs5_t* args, void* unused) {
  if (args->skip_origin && (int)args->ret < 0)
    return;
  if (nm_is_virtual_inode((void*)args->arg0) || nm_is_virtual_inode((void*)args->arg2)
      || nm_mutation_virtual((void*)args->arg1) || nm_mutation_virtual((void*)args->arg3)) {
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)-EPERM;
  }
}

// 与 xattr 同在驻留后的管理锁内接入；未齐全时只拒绝需要虚拟 inode 的本次发布。
// 已安装回调保留供后续补齐，避免 SDK 撤钩不等待在途回调的问题。
static int nm_activate_mutation_guards_locked(void) {
  if (!__atomic_load_n(&nm_xattr_resident, __ATOMIC_ACQUIRE))
    return -ENODEV;
  if (nm_mutation_ready)
    return 0;
  if (!nm_mutation_targets[0]) {
#ifndef CONFIG_KPM_BASELINES
    bool unavailable = false;
    int rc = calculate_btf_mutation(&unavailable);
    if (rc && !(rc == -ENODATA && unavailable))
      return rc;
#endif
    // 共同签名见 KP security.h 和目标 4.4/6.12 security/security.c，均不带 idmap。
    const char* names[] = {"security_inode_unlink", "security_inode_rmdir", "security_inode_link",
                           "security_inode_rename"};
    void* targets[4];
    for (unsigned int i = 0; i < 4; i++) {
      targets[i] = (void*)kallsyms_lookup_name_by_suffix(names[i]);
      if (!targets[i])
        return -ENOENT;
      for (unsigned int j = 0; j < i; j++)
        if (targets[i] == targets[j])
          return -EOPNOTSUPP;
    }
    memcpy(nm_mutation_targets, targets, sizeof(targets));
  }
  const unsigned int counts[] = {2, 2, 3, 5};
  void* callbacks[] = {nm_mutation_remove, nm_mutation_remove, nm_mutation_link, nm_mutation_rename};
  for (unsigned int i = 0; i < 4; i++) {
    if (nm_mutation_installed[i])
      continue;
    hook_err_t rc = hook_wrap(nm_mutation_targets[i], counts[i], callbacks[i], NULL, NULL);
    if (rc)
      return -EINVAL;
    nm_mutation_installed[i] = true;
  }
  nm_mutation_ready = true;
  return 0;
}
