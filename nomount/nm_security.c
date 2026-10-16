/* SPDX-License-Identifier: GPL-2.0-only */
/* Native LSM context transfer; each inode retains its own security allocation. */
struct nm_security_context {
  void* data;
  u32 length;
  u32 secid;
};

static int kfunc_def(nm_security_inode_getsecctx)(struct inode*, void**, u32*);
static int kfunc_def(nm_security_inode_notifysecctx)(struct inode*, void*, u32);
static void kfunc_def(nm_security_release_secctx)(char*, u32);
static void kfunc_def(nm_security_inode_getsecid)(struct inode*, u32*);

static int nm_prepare_security_functions(void) {
  kfunc(nm_security_inode_getsecctx) =
      (typeof(kfunc(nm_security_inode_getsecctx)))kallsyms_lookup_name_by_suffix("security_inode_getsecctx");
  kfunc(nm_security_inode_notifysecctx) =
      (typeof(kfunc(nm_security_inode_notifysecctx)))kallsyms_lookup_name_by_suffix("security_inode_notifysecctx");
  kfunc(nm_security_release_secctx) =
      (typeof(kfunc(nm_security_release_secctx)))kallsyms_lookup_name_by_suffix("security_release_secctx");
  kfunc(nm_security_inode_getsecid) =
      (typeof(kfunc(nm_security_inode_getsecid)))kallsyms_lookup_name_by_suffix("security_inode_getsecid");
  return kfunc(nm_security_inode_getsecctx) && kfunc(nm_security_inode_notifysecctx)
                 && kfunc(nm_security_release_secctx) && kfunc(nm_security_inode_getsecid)
             ? 0
             : -ENOENT;
}

// SELinux getsecid只读已分配的SID；缓存／RCU路径不获取会分配、重验证的上下文。
static u32 nm_inode_secid(struct inode* inode) {
  u32 secid = 0;
  if (inode)
    kfunc(nm_security_inode_getsecid)(inode, &secid);
  return secid;
}

static void nm_release_security_context(struct nm_security_context* context) {
  if (context->data)
    kfunc(nm_security_release_secctx)(context->data, context->length);
  *context = (struct nm_security_context){0};
}

// 调用者保活源inode；在iget/hash锁和模块RCU范围外获取可睡眠的上下文。
static int nm_get_security_context(struct inode* source, struct nm_security_context* context) {
  *context = (struct nm_security_context){0};
  int rc = kfunc(nm_security_inode_getsecctx)(source, &context->data, &context->length);
  if (!rc) {
    context->secid = nm_inode_secid(source);
    if (!context->data || !context->length || !context->secid)
      rc = -EOPNOTSUPP;
  }
  if (rc)
    nm_release_security_context(context);
  return rc;
}

// 只用于未公开的新inode，调用者独占初始化；目录I_NEW仍阻挡iget等待者。
// 先设i_mode，让LSM选择正确对象类。原生notify只改内存标签，不写文件系统xattr。
static int nm_initialize_inode_security(struct inode* inode, const struct nm_security_context* context) {
  int rc = kfunc(nm_security_inode_notifysecctx)(inode, context->data, context->length);
  if (!rc && nm_inode_secid(inode) != context->secid)
    rc = -EACCES;  // LSM可能把不支持的标记返回成功；必须确认实际SID。
  return rc;
}
