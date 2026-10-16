/* SPDX-License-Identifier: GPL-2.0-only */
/* Native-parent lookup, enumeration and revalidation adapted from the pinned NoMount source. */
struct nm_directory_proxy {
  struct rcu_head rcu;
  struct nm_directory_node* node;
  const void* original_inode_ops;
  const void* original_file_ops;
  unsigned char tables[] __attribute__((aligned(128)));
};
struct nm_dentry_proxy {
  struct nm_dentry_proxy* next;
  const void* original;
  unsigned char tables[] __attribute__((aligned(128)));
};
static struct nm_dentry_proxy* nm_dentry_proxies;
static void* nm_owned_dentry_ops;

static void kfunc_def(nm_spin_lock)(void*);
static void kfunc_def(nm_spin_unlock)(void*);
static void kfunc_def(nm_d_drop)(struct dentry*);
static void kfunc_def(nm_dput)(struct dentry*);
static struct dentry* kfunc_def(nm_dget_parent)(struct dentry*);

static int nm_prepare_directory_functions(void) {
  kfunc(nm_spin_lock) = (typeof(kfunc(nm_spin_lock)))kallsyms_lookup_name_by_suffix("_raw_spin_lock");
  kfunc(nm_spin_unlock) = (typeof(kfunc(nm_spin_unlock)))kallsyms_lookup_name_by_suffix("_raw_spin_unlock");
  kfunc(nm_d_drop) = (typeof(kfunc(nm_d_drop)))kallsyms_lookup_name_by_suffix("d_drop");
  kfunc(nm_dput) = (typeof(kfunc(nm_dput)))kallsyms_lookup_name_by_suffix("dput");
  kfunc(nm_dget_parent) = (typeof(kfunc(nm_dget_parent)))kallsyms_lookup_name_by_suffix("dget_parent");
  return kfunc(nm_dget_parent) && kfunc(nm_spin_lock) && kfunc(nm_spin_unlock) && kfunc(nm_d_drop) && kfunc(nm_dput)
             ? 0
             : -ENOENT;
}

static struct dentry* nm_directory_lookup(struct inode*, struct dentry*, unsigned int);
static int nm_directory_iterate(struct file*, struct nm_dir_context*);
static int nm_dentry_revalidate(struct dentry*, unsigned int);
static int nm_dentry_weak_revalidate(struct dentry*, unsigned int);

static unsigned int nm_directory_file_table_offset(void) { return (struct_offset.inode_ops_size + 63U) & ~63U; }
static struct nm_directory_proxy* nm_directory_proxy(const void* table) {
  if (table == nm_inode_engine.directory_ops)
    return NULL;
  const struct nm_inode_lookup_ops* head = table;
  return head && head->lookup == nm_directory_lookup
             ? (void*)((uintptr_t)table - offsetof(struct nm_directory_proxy, tables))
             : NULL;
}
static struct nm_directory_proxy* nm_directory_file_proxy(const void* table) {
  bool owned = table
               && ((struct_offset.fop_iterate >= 0
                    && nm_operation_callback(table, struct_offset.fop_iterate) == nm_directory_iterate)
                   || (struct_offset.fop_iterate_shared >= 0
                       && nm_operation_callback(table, struct_offset.fop_iterate_shared) == nm_directory_iterate));
  return owned ? (void*)((uintptr_t)table - nm_directory_file_table_offset()
                         - offsetof(struct nm_directory_proxy, tables))
               : NULL;
}
// 调用者持原生 inode 引用及 RCU 读锁；节点引用带出读侧后才可继续使用。
static struct nm_directory_node* nm_inode_directory_node(struct inode* inode) {
  if (nm_is_directory_inode(inode)) {
    struct nm_inode_info* info = nm_inode_private(inode);
    return info ? info->dir_node : NULL;
  }
  struct nm_directory_proxy* proxy = nm_directory_proxy(nm_inode_ops(inode));
  return proxy ? nm_rules_load(proxy->node) : NULL;
}
static unsigned int nm_dentry_table_offset(void) { return (struct_offset.dentry_ops_size + 63U) & ~63U; }
static struct nm_dentry_proxy* nm_dentry_proxy(const void* table) {
  if (table == nm_owned_dentry_ops)
    return NULL;
  const struct nm_dentry_revalidation_ops* head = table;
  return head && head->d_revalidate == nm_dentry_revalidate && head->d_weak_revalidate == nm_dentry_weak_revalidate
             ? (void*)((uintptr_t)table - nm_dentry_table_offset() - offsetof(struct nm_dentry_proxy, tables))
             : NULL;
}

// 按完整原表字节共用不可变快照；published 表随模块驻留，不与某个 dentry 的寿命绑定。
static void* nm_cached_dentry_table(const void* original) {
  unsigned int span = nm_dentry_table_offset();
  struct nm_dentry_proxy* candidate = NULL;
  for (;;) {
    struct nm_dentry_proxy* head = __atomic_load_n(&nm_dentry_proxies, __ATOMIC_ACQUIRE);
    for (struct nm_dentry_proxy* entry = head; entry; entry = entry->next) {
      if (!!entry->original == !!original
          && (!original || !memcmp(entry->original, original, struct_offset.dentry_ops_size))) {
        if (candidate)
          nm_free(candidate);
        return entry->tables + span;
      }
    }
    if (!candidate) {
      candidate = nm_zalloc(offsetof(struct nm_dentry_proxy, tables) + span + struct_offset.dentry_ops_size);
      if (!candidate)
        return ERR_PTR(-ENOMEM);
      if (original) {
        memcpy(candidate->tables, original, struct_offset.dentry_ops_size);
        memcpy(candidate->tables + span, original, struct_offset.dentry_ops_size);
        candidate->original = candidate->tables;
      }
      struct nm_dentry_revalidation_ops* table = (void*)(candidate->tables + span);
      table->d_revalidate = nm_dentry_revalidate;
      table->d_weak_revalidate = nm_dentry_weak_revalidate;
      continue;  // 分配期间可能已有同样快照发布，重新核对当前链表。
    }
    candidate->next = head;
    if (__atomic_compare_exchange_n(&nm_dentry_proxies, &head, candidate, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
      return candidate->tables + span;
  }
}

// 新建的 injected dentry 使用共享表；原生条目使用保留完整原生回调的快照。
static int nm_wrap_dentry(struct dentry* dentry, bool owned) {
  const void* observed = nm_dentry_ops(dentry);
  if (observed == nm_owned_dentry_ops || (!owned && nm_dentry_proxy(observed)))
    return 0;
  struct nm_dentry_proxy* old_proxy = nm_dentry_proxy(observed);
  const void* original = old_proxy ? old_proxy->original : observed;
  void* table = owned ? nm_owned_dentry_ops : nm_cached_dentry_table(original);
  if (IS_ERR(table))
    return PTR_ERR(table);
  kfunc(nm_spin_lock)(nm_dentry_lock_address(dentry));
  int rc = 0;
  if (nm_dentry_ops(dentry) != observed) {
    rc = -EAGAIN;
  } else if (owned
             && (nm_dentry_inode(dentry) || nm_dentry_objects(dentry)->d_fsdata
                 || (original
                     && ((struct_offset.dop_init >= 0 && nm_operation_callback(original, struct_offset.dop_init))
                         || nm_operation_callback(original, struct_offset.dop_release))))) {
    // 文件系统私有 dentry 初始化／清理尚未接入 injected 对象，保留原生状态。
    rc = -EOPNOTSUPP;
  } else {
    nm_publish_dentry_ops(dentry, table, owned);
  }
  kfunc(nm_spin_unlock)(nm_dentry_lock_address(dentry));
  return rc;
}

static int nm_dentry_validate(struct dentry* dentry, unsigned int flags, bool weak) {
  // ref-walk 保证 dentry/inode 生命周期，RCU-walk 由 VFS 重试为 ref-walk。
  if (flags & 0x40U)  // LOOKUP_RCU。
    return -ECHILD;
  struct dentry* parent_dentry = kfunc(nm_dget_parent)(dentry);
  struct inode* parent = nm_dentry_inode(parent_dentry);
  if (!parent) {
    kfunc(nm_dput)(parent_dentry);
    return 1;
  }
  u32 uid = nm_current_fsuid();
  bool blocked = nomount_is_uid_blocked(uid), has_rule = false, valid_rule = false, whiteout = false;
  if (!blocked && nm_is_directory_inode(parent) && nm_inode_engine.check_directory_search) {
    int rc = nm_inode_engine.check_directory_search(parent);
    if (rc) {
      kfunc(nm_dput)(parent_dentry);
      return rc;
    }
  }
  struct inode* inode = nm_dentry_inode(dentry);
  bool owned = nm_dentry_ops(dentry) == nm_owned_dentry_ops || (inode && nm_is_virtual_inode(inode));
  const struct nm_qstr* name = &((struct nm_dentry_head*)dentry)->d_name;
  nm_rcu_read_lock();
  struct nm_directory_node* node = nm_inode_directory_node(parent);
  struct nomount_leaf* leaf =
      !blocked && node ? nm_find_child(nm_rules_load(node->children), name->name, name->len) : NULL;
  struct nomount_rule* rule = leaf ? nm_select_rule(leaf, uid) : NULL;
  if (rule) {
    has_rule = true;
    whiteout = rule->flags & NM_FLAG_WHITEOUT;
    if (inode && nm_is_virtual_inode(inode)) {
      struct nm_inode_info* info = nm_inode_private(inode);
      valid_rule =
          info && nm_inode_number(inode) == leaf->v_ino
          && nm_inode_matches_binding(
              inode, &rule->r_path, nm_is_directory_inode(inode) ? nm_rules_load(leaf->this_dir) : NULL, rule->flags,
              nm_inode_secid(rule->r_path.dentry ? nm_dentry_inode(rule->r_path.dentry) : parent));
      struct nm_inode_info* parent_info = nm_is_directory_inode(parent) ? nm_inode_private(parent) : NULL;
      if (rule->inherit_backing && parent_info && parent_info->r_path.dentry)
        valid_rule = false;  // 源目录暂缺时物化了 pure inode，出现后仍需重新解析。
    }
  }
  nm_rcu_read_unlock();
  int result;
  if (whiteout) {
    result = !inode;
  } else if (valid_rule) {
    result = 1;
  } else if (has_rule || owned) {
    kfunc(nm_d_drop)(dentry);
    result = 0;
  } else {
    struct nm_dentry_proxy* proxy = nm_dentry_proxy(nm_dentry_ops(dentry));
    const struct nm_dentry_control_ops* original = proxy ? proxy->original : NULL;
    int (*callback)(struct dentry*, unsigned int) =
        original ? (weak ? original->d_weak_revalidate : original->d_revalidate) : NULL;
    result = callback ? callback(dentry, flags) : 1;
  }
  kfunc(nm_dput)(parent_dentry);
  return result;
}
static int nm_dentry_revalidate(struct dentry* dentry, unsigned int flags) {
  return nm_dentry_validate(dentry, flags, false);
}
static int nm_dentry_weak_revalidate(struct dentry* dentry, unsigned int flags) {
  return nm_dentry_validate(dentry, flags, true);
}

static struct dentry* nm_directory_lookup(struct inode* parent, struct dentry* dentry, unsigned int flags) {
  u32 uid = nm_current_fsuid();
  struct nomount_rule* rule = NULL;
  struct nm_directory_node* child_node = NULL;
  u64 number = 0;
  const struct nm_qstr* name = &((struct nm_dentry_head*)dentry)->d_name;
  bool blocked = nomount_is_uid_blocked(uid);
  if (!blocked && nm_is_directory_inode(parent) && nm_inode_engine.check_directory_search) {
    int rc = nm_inode_engine.check_directory_search(parent);
    if (rc)
      return ERR_PTR(rc);
  }
  nm_rcu_read_lock();
  struct nm_directory_proxy* proxy = nm_directory_proxy(nm_inode_ops(parent));
  const struct nm_inode_lookup_ops* original = proxy ? proxy->original_inode_ops : NULL;
  struct nm_directory_node* node = nm_inode_directory_node(parent);
  struct nomount_leaf* leaf =
      !blocked && node ? nm_find_child(nm_rules_load(node->children), name->name, name->len) : NULL;
  rule = leaf ? nm_select_rule(leaf, uid) : NULL;
  if (rule) {
    nm_rule_get(rule);
    number = leaf->v_ino;
    if (rule->flags & NM_FLAG_IS_DIR) {
      child_node = nm_rules_load(leaf->this_dir);
      if (child_node)
        nm_directory_node_get(child_node);
    }
  }
  nm_rcu_read_unlock();
  if (rule) {
    int rc = nm_wrap_dentry(dentry, true);
    struct dentry* result;
    if (rc)
      result = ERR_PTR(rc);
    else if (rule->flags & NM_FLAG_WHITEOUT)
      result = kfunc(nm_d_splice_alias)(NULL, dentry);
    else if (rule->flags & NM_FLAG_IS_DIR)
      result = nm_inode_engine.materialize_directory
                   ? nm_inode_engine.materialize_directory(parent, dentry, rule, child_node, number)
                   : ERR_PTR(-EOPNOTSUPP);
    else
      result = nm_materialize_file(parent, dentry, rule, number);
    nm_directory_node_put(child_node);
    nm_rule_put(rule);
    return result;
  }
  if (nm_is_directory_inode(parent)) {
    int rc = nm_wrap_dentry(dentry, true);
    if (rc)
      return ERR_PTR(rc);
    struct nm_inode_info* info = nm_inode_private(parent);
    if (!blocked && nm_inode_engine.lookup_backing && info && info->r_path.dentry)
      return nm_inode_engine.lookup_backing(parent, dentry, flags);
    return kfunc(nm_d_splice_alias)(NULL, dentry);
  }
  if (!original || !original->lookup)
    return ERR_PTR(-EOPNOTSUPP);
  struct dentry* result = original->lookup(parent, dentry, flags);
  if (IS_ERR(result))
    return result;
  struct dentry* target = result ? result : dentry;
  int rc = nm_wrap_dentry(target, false);
  if (rc) {
    // 原生 lookup 已可发布条目；包装失败时摘哈希并释放 alias 返回引用。
    kfunc(nm_d_drop)(target);
    if (result)
      kfunc(nm_dput)(result);
    return ERR_PTR(rc);
  }
  return result;
}

struct nm_directory_actor {
  struct nm_dir_context context;
  struct nm_dir_context* outer;
  struct nm_directory_node* node;
  u32 uid;
  bool emitted;
};
static int nm_directory_filter(struct nm_dir_context* context, const char* name, int length, int64_t offset, u64 number,
                               unsigned int type) {
  struct nm_directory_actor* actor = (void*)context;
  nm_rcu_read_lock();
  bool hidden = length > 0 && nm_directory_rule(actor->node, name, length, actor->uid, NULL, false);
  nm_rcu_read_unlock();
  if (hidden) {
    context->pos = offset;
    return 0;
  }
  actor->outer->pos = context->pos;
  int rc = nm_dir_emit(actor->outer, name, length, offset, number, type);
  context->pos = actor->outer->pos;
  actor->emitted = true;
  return rc;
}
static bool nm_directory_filter_bool(struct nm_dir_context* context, const char* name, int length, int64_t offset,
                                     u64 number, unsigned int type) {
  return nm_directory_filter(context, name, length, offset, number, type) == 0;
}
static int nm_directory_iterate(struct file* file, struct nm_dir_context* context) {
  nm_rcu_read_lock();
  struct nm_directory_proxy* proxy = nm_directory_file_proxy(nm_file_ops(file));
  struct nm_directory_node* node = proxy ? nm_rules_load(proxy->node) : NULL;
  const void* original = proxy ? proxy->original_file_ops : NULL;
  if (node)
    nm_directory_node_get(node);
  nm_rcu_read_unlock();
  int (*iterate)(void*, struct nm_dir_context*) =
      struct_offset.fop_iterate_shared >= 0 ? nm_operation_callback(original, struct_offset.fop_iterate_shared) : NULL;
  if (!iterate && struct_offset.fop_iterate >= 0)
    iterate = nm_operation_callback(original, struct_offset.fop_iterate);
  u32 uid = nm_current_fsuid();
  bool compat = nm_current_compat(), blocked = nomount_is_uid_blocked(uid);
  int rc;
  if (nm_virtual_position(context->pos, compat)) {
    rc = blocked ? 0 : nm_emit_children(node, context, uid, compat);
  } else if (!node || blocked || !nm_rules_load(node->children)) {
    rc = nm_iterate_original(file, context, iterate);
  } else {
    struct nm_directory_actor actor = {
        .context = {.actor = nm_directory_filter, .pos = context->pos}, .outer = context, .node = node, .uid = uid};
    if (struct_offset.dir_actor_abi == 1)
      actor.context.actor_bool = nm_directory_filter_bool;
    rc = nm_iterate_original(file, &actor.context, iterate);
    context->pos = actor.context.pos;
    if (rc >= 0 && !actor.emitted)
      rc = nm_emit_children(node, context, uid, compat);
  }
  nm_directory_node_put(node);
  return rc;
}

static int64_t nm_directory_llseek(struct file* file, int64_t offset, int whence) {
  bool compat = nm_current_compat();
  if (whence == 0 && nm_virtual_position(offset, compat))
    return kfunc(nm_vfs_setpos)(file, offset, 0x7fffffffffffffffLL);
  if (whence == 1 && !offset && nm_virtual_position(*nm_file_position(file), compat))
    return *nm_file_position(file);
  struct nm_directory_proxy* proxy = nm_directory_file_proxy(nm_file_ops(file));
  const struct nm_file_io_ops* original = proxy ? proxy->original_file_ops : NULL;
  int64_t (*seek)(struct file*, int64_t, int) = original ? original->llseek : NULL;
  return seek ? seek(file, offset, whence) : -ESPIPE;
}

static void nm_directory_proxy_rcu_free(struct rcu_head* head) {
  struct nm_directory_proxy* proxy = (void*)head;
  nm_directory_node_put(proxy->node);
  nm_free_rcu(proxy);
}
static void nm_release_directory_inode(struct inode* inode) {
  struct nm_directory_proxy* proxy = nm_directory_proxy(nm_inode_ops(inode));
  if (!proxy)
    proxy = nm_directory_file_proxy(nm_inode_file_ops(inode));
  if (proxy) {
    nm_publish_inode_ops(inode, proxy->original_inode_ops, proxy->original_file_ops);
    nm_rcu_call(&proxy->rcu, nm_directory_proxy_rcu_free);
  }
}

// 调用者持管理锁和 parent 引用。先安装空视图，成功后才发布 children。
static int nm_install_directory(struct inode* parent, struct nm_directory_node* node) {
  if (!nm_owned_dentry_ops || !nm_inode_engine.release_directory)
    return -ENODEV;
  if (!node || (nm_inode_mode(parent) & 0170000) != 0040000)
    return -EINVAL;
  const void* iops = nm_inode_ops(parent);
  const void* fops = nm_inode_file_ops(parent);
  struct nm_directory_proxy* installed = nm_directory_proxy(iops);
  if (installed)
    return installed->node == node ? 0 : -EEXIST;
  if (nm_rules_load(node->children))
    return -EINVAL;
  if (!iops || !fops || !((const struct nm_inode_lookup_ops*)iops)->lookup
      || !((struct_offset.fop_iterate_shared >= 0 && nm_operation_callback(fops, struct_offset.fop_iterate_shared))
           || (struct_offset.fop_iterate >= 0 && nm_operation_callback(fops, struct_offset.fop_iterate))))
    return -EOPNOTSUPP;
  unsigned int file_start = nm_directory_file_table_offset();
  struct nm_directory_proxy* proxy =
      nm_zalloc(offsetof(struct nm_directory_proxy, tables) + file_start + struct_offset.file_ops_size);
  if (!proxy)
    return -ENOMEM;
  proxy->original_inode_ops = iops;
  proxy->original_file_ops = fops;
  proxy->node = node;
  memcpy(proxy->tables, iops, struct_offset.inode_ops_size);
  memcpy(proxy->tables + file_start, fops, struct_offset.file_ops_size);
  ((struct nm_inode_lookup_ops*)proxy->tables)->lookup = nm_directory_lookup;
  ((struct nm_file_io_ops*)(proxy->tables + file_start))->owner = NULL;
  ((struct nm_file_io_ops*)(proxy->tables + file_start))->llseek = nm_directory_llseek;
  const int slots[] = {struct_offset.fop_iterate, struct_offset.fop_iterate_shared};
  for (unsigned int i = 0; i < 2; i++)
    if (slots[i] >= 0 && nm_operation_callback(fops, slots[i]))
      nm_set_operation_callback(proxy->tables + file_start, slots[i], nm_directory_iterate);
  int rc = nm_install_super_proxy(nm_inode_superblock(parent));
  if (rc) {
    nm_free(proxy);
    return rc;
  }
  nm_directory_node_get(node);
  nm_publish_inode_ops(parent, proxy->tables, proxy->tables + file_start);
  return 0;
}

static int nm_prepare_directory_engine(void) {
  int rc = nm_prepare_directory_layout();
  if (!rc)
    rc = nm_prepare_current();
  if (!rc)
    rc = nm_prepare_directory_functions();
  if (rc)
    return rc;
  if (nm_owned_dentry_ops)
    return -EALREADY;
  void* table = nm_new_operations(NM_DENTRY_OPS, NULL);
  if (IS_ERR(table))
    return PTR_ERR(table);
  struct nm_dentry_revalidation_ops* head = table;
  head->d_revalidate = nm_dentry_revalidate;
  head->d_weak_revalidate = nm_dentry_weak_revalidate;
  nm_owned_dentry_ops = table;
  nm_inode_engine.release_directory = nm_release_directory_inode;
  return 0;
}
