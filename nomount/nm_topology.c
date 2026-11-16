/* SPDX-License-Identifier: GPL-2.0-only */
/* Path topology and retirement adapted from the pinned NoMount implementation. */
struct nm_topology_leaf {
  struct nm_topology_leaf* next;
  struct nomount_leaf* leaf;
  struct nm_directory_node* parent;
  bool automatic;
};
struct nm_topology_anchor {
  struct nm_topology_anchor* next;
  struct nm_path path;
  struct nm_directory_node* node;
};
struct nm_topology_updates {
  struct nm_rule_updates rules;
  struct nm_topology_leaf* leaves;
  struct nm_topology_anchor* anchors;
};
static struct nm_topology_leaf* nm_topology_leaves;
static struct nm_topology_anchor* nm_topology_anchors;
static bool nm_topology_ready;
static struct dentry* kfunc_def(nm_d_hash_and_lookup)(struct dentry*, struct nm_qstr*);
static void kfunc_def(nm_shrink_dcache_parent)(struct dentry*);
// 原生 async API 自行持有 work_struct；KPM 不依赖其配置相关布局。
static u64 (*nm_async_schedule_node)(void (*)(void*, u64), void*, int);
static u64 (*nm_async_schedule)(void (*)(void*, u64), void*);

static int nm_prepare_topology_functions(void) {
  if (!nm_inode_engine.materialize_directory)
    return -ENODEV;
#ifndef CONFIG_KPM_BASELINES
  int rc = nm_prepare_topology_abi();
  if (rc)
    return rc;
#endif
  kfunc(nm_d_hash_and_lookup) =
      (typeof(kfunc(nm_d_hash_and_lookup)))kallsyms_lookup_name_by_suffix("d_hash_and_lookup");
  kfunc(nm_shrink_dcache_parent) =
      (typeof(kfunc(nm_shrink_dcache_parent)))kallsyms_lookup_name_by_suffix("shrink_dcache_parent");
  if (!kfunc(nm_d_hash_and_lookup) || !kfunc(nm_shrink_dcache_parent))
    return -ENOENT;
  nm_async_schedule_node = (void*)kallsyms_lookup_name_by_suffix("async_schedule_node");
  nm_async_schedule = nm_async_schedule_node ? NULL : (void*)kallsyms_lookup_name_by_suffix("async_schedule");
  nm_log_info("topology retirement: %s\n", nm_async_schedule_node || nm_async_schedule ? "async" : "synchronous");
  nm_topology_ready = true;
  return 0;
}

// 拓扑索引使用规范绝对路径；尾部斜线由调用者裁掉，单个分量限 NAME_MAX。
static int nm_topology_path_valid(const char* path, unsigned int length) {
  if (!nm_rule_path_valid(path, length) || length == 1)
    return -EINVAL;
  unsigned int start = 1;
  for (unsigned int i = 1; i <= length; i++) {
    if (i != length && path[i] != '/')
      continue;
    unsigned int count = i - start;
    if (!count || (count == 1 && path[start] == '.') || (count == 2 && path[start] == '.' && path[start + 1] == '.'))
      return -EINVAL;
    if (count > 255)
      return -ENAMETOOLONG;
    start = i + 1;
  }
  return 0;
}
static struct nm_topology_leaf* nm_topology_find(const char* path, unsigned int length) {
  for (struct nm_topology_leaf* entry = nm_topology_leaves; entry; entry = entry->next)
    if (entry->leaf->v_len == length && !memcmp(entry->leaf->paths, path, length))
      return entry;
  return NULL;
}
static bool nm_topology_has_directory_ancestor(const char* path, unsigned int length) {
  for (struct nm_topology_leaf* entry = nm_topology_leaves; entry; entry = entry->next) {
    unsigned int count = entry->leaf->v_len;
    if (entry->leaf->this_dir && count < length && path[count] == '/' && !memcmp(entry->leaf->paths, path, count))
      return true;
  }
  return false;
}
static struct nm_topology_anchor* nm_topology_anchor(struct nm_directory_node* node) {
  for (struct nm_topology_anchor* anchor = nm_topology_anchors; anchor; anchor = anchor->next)
    if (anchor->node == node)
      return anchor;
  return NULL;
}
static bool nm_topology_cycle(struct nm_directory_node* parent, struct nm_directory_node* child) {
  while (parent) {
    if (parent == child)
      return true;
    parent = parent->owner ? parent->owner->parent : NULL;
  }
  return false;
}

static void nm_topology_free_leaf(struct nm_topology_leaf* entry) {
  struct nm_directory_node* node = entry->leaf->this_dir;
  nm_free_leaf(entry->leaf);
  nm_directory_node_put(node);
  nm_directory_node_put(entry->parent);
  nm_free(entry);
}
static void nm_topology_free_anchor(struct nm_topology_anchor* anchor) {
  // 始终在进程上下文释放原生路径，RCU 回调只处理模块私有内存。
  kfunc(nm_path_put)(&anchor->path);
  nm_directory_node_put(anchor->node);
  nm_free(anchor);
}

// 成功接收 rule 的一份引用；失败时仍归调用者。新建的节点和数组此时尚不可达。
static struct nm_topology_leaf* nm_topology_new_leaf(const char* path, u16 length, struct nomount_rule* rule,
                                                     bool automatic) {
  struct nm_topology_leaf* entry = nm_zalloc(sizeof(*entry));
  if (!entry)
    return ERR_PTR(-ENOMEM);
  entry->leaf = nm_alloc_leaf(path, length);
  if (IS_ERR(entry->leaf)) {
    long rc = PTR_ERR(entry->leaf);
    nm_free(entry);
    return ERR_PTR(rc);
  }
  entry->automatic = automatic;
  if (rule->flags & NM_FLAG_IS_DIR) {
    // 自动父目录必须保持私有；仅显式目录可复用先前已有的原生视图。
    // prefix 探测后真实命名空间仍可能变化，不能再解析一次并把私有子项发布到原生节点。
    if (!automatic && !nm_topology_has_directory_ancestor(path, length)) {
      // 原生目录可能已有视图。复用节点，让原先建立的子项继续属于同一个目录。
      struct nm_path native = {0};
      int rc = kfunc(nm_kern_path)(entry->leaf->paths, 1, &native);
      if (!rc) {
        struct inode* inode = nm_dentry_inode(native.dentry);
        nm_rcu_read_lock();
        struct nm_directory_node* node =
            inode && (nm_inode_mode(inode) & 0170000) == 0040000 ? nm_inode_directory_node(inode) : NULL;
        if (node)
          nm_directory_node_get(node);
        nm_rcu_read_unlock();
        entry->leaf->this_dir = node;
        kfunc(nm_path_put)(&native);
      } else if (rc != -ENOENT) {
        nm_topology_free_leaf(entry);
        return ERR_PTR(rc);
      }
    }
    if (entry->leaf->this_dir && entry->leaf->this_dir->owner) {
      nm_topology_free_leaf(entry);
      return ERR_PTR(-EEXIST);
    }
    if (!entry->leaf->this_dir)
      entry->leaf->this_dir = nm_new_directory_node();
    if (!entry->leaf->this_dir) {
      nm_topology_free_leaf(entry);
      return ERR_PTR(-ENOMEM);
    }
    entry->leaf->this_dir->owner = entry;
  }
  struct nm_rule_updates private_updates = {0};
  int rc = nm_set_leaf_rule(entry->leaf, rule, &private_updates);
  if (rc) {
    if (entry->leaf->this_dir)
      entry->leaf->this_dir->owner = NULL;
    nm_topology_free_leaf(entry);
    return ERR_PTR(rc);
  }
  return entry;
}

// 消耗 path 引用。inode 的原生表可能在上次释放空 anchor 后继续缓存，必须复用其节点。
static struct nm_topology_anchor* nm_topology_make_anchor(struct nm_path path, bool* fresh) {
  struct inode* inode = nm_dentry_inode(path.dentry);
  if (!inode || (nm_inode_mode(inode) & 0170000) != 0040000 || nm_is_directory_inode(inode)) {
    int rc = inode && nm_is_directory_inode(inode) ? -EXDEV : -ENOTDIR;
    kfunc(nm_path_put)(&path);
    return ERR_PTR(rc);
  }
  nm_rcu_read_lock();
  struct nm_directory_node* node = nm_inode_directory_node(inode);
  if (node)
    nm_directory_node_get(node);
  nm_rcu_read_unlock();
  if (!node)
    node = nm_new_directory_node();
  if (!node) {
    kfunc(nm_path_put)(&path);
    return ERR_PTR(-ENOMEM);
  }
  struct nm_topology_anchor* anchor = nm_topology_anchor(node);
  if (anchor) {
    kfunc(nm_path_put)(&path);
    nm_directory_node_put(node);
    *fresh = false;
    return anchor;
  }
  anchor = nm_zalloc(sizeof(*anchor));
  if (!anchor) {
    kfunc(nm_path_put)(&path);
    nm_directory_node_put(node);
    return ERR_PTR(-ENOMEM);
  }
  anchor->path = path;
  anchor->node = node;
  *fresh = true;
  return anchor;
}
static struct dentry* nm_topology_cached_child(struct nm_topology_anchor* anchor, struct nomount_leaf* leaf) {
  if (!anchor)
    return NULL;  // 纯虚拟父目录的负项已有模块重验证。
  struct nm_qstr name = {.name = leaf->paths + leaf->v_len - leaf->child_len, .len = leaf->child_len};
  return kfunc(nm_d_hash_and_lookup)(anchor->path.dentry, &name);
}
static void nm_topology_invalidate(struct nm_topology_anchor* anchor, struct dentry* child) {
  if (child) {
    kfunc(nm_d_drop)(child);
    kfunc(nm_dput)(child);
  }
  if (anchor)
    kfunc(nm_shrink_dcache_parent)(anchor->path.dentry);
}

// 管理锁内沿已持有的节点/path检查；节点可同时被原生 anchor 与虚拟 owner 使用。
// 两种视图都可能成为 lookup 的 parent，不另做字符串解析，也不漏掉旧原生 FD 的视图。
static int nm_topology_check_inode_allocation(struct nm_directory_node* node, struct nm_topology_anchor* anchor) {
  bool checked = false;
  while (node) {
    if (!anchor)
      anchor = nm_topology_anchor(node);
    if (anchor) {
      int rc = nm_check_inode_allocation(nm_inode_superblock(nm_dentry_inode(anchor->path.dentry)));
      if (rc)
        return rc;
      checked = true;
    }
    node = node->owner ? node->owner->parent : NULL;
    anchor = NULL;
  }
  return checked ? 0 : -ENODEV;
}

static int nm_topology_replace(struct nm_topology_leaf* entry, struct nomount_rule* rule,
                               struct nm_topology_updates* updates) {
  if (rule->flags != NM_FLAG_WHITEOUT || entry->leaf->this_dir) {
    int rc = nm_topology_check_inode_allocation(entry->parent, NULL);
    if (rc)
      return rc;
  }
  struct nm_rule_array* array = nm_build_leaf_rule_array(entry->leaf, rule);
  if (IS_ERR(array))
    return PTR_ERR(array);
  struct nm_directory_node* node = NULL;
  if ((rule->flags & NM_FLAG_IS_DIR) && !entry->leaf->this_dir) {
    node = nm_new_directory_node();
    if (!node) {
      nm_free(array);
      return -ENOMEM;
    }
  }
  struct nm_topology_anchor* anchor = nm_topology_anchor(entry->parent);
  struct dentry* child = nm_topology_cached_child(anchor, entry->leaf);
  if (IS_ERR(child)) {
    nm_directory_node_put(node);
    nm_free(array);
    return PTR_ERR(child);
  }
  if (node) {
    node->owner = entry;
    nm_rules_publish(entry->leaf->this_dir, node);
  }
  nm_publish_leaf_rule(entry->leaf, rule, array, &updates->rules);
  entry->automatic = false;
  nm_topology_invalidate(anchor, child);
  return 0;
}

// 调用者在进程上下文持管理锁；控制层负责串行。成功接收规则引用。
static int nm_topology_add_prepared_locked(const char* path, u16 length, struct nomount_rule* rule,
                                           struct nm_topology_updates* updates, int (*prepare_inodes)(void)) {
  if (!nm_topology_ready)
    return -ENODEV;
  length = path ? nm_trim_path(path, length) : length;
  int rc = nm_topology_path_valid(path, length);
  if (rc || !rule || rule->published)
    return rc ? rc : -EINVAL;
  if ((rule->flags & NM_FLAG_IS_DIR) && !(rule->flags & NM_FLAG_VIRTUAL_DIR) && !nm_inode_engine.lookup_backing)
    return -EOPNOTSUPP;
  struct nm_topology_leaf* found = nm_topology_find(path, length);
  if (found) {
    // 原生父目录内的纯白化只发布负项；其它替换仍先准备自建 inode 所需入口。
    if (prepare_inodes
        && (rule->flags != NM_FLAG_WHITEOUT || found->leaf->this_dir || found->parent->owner
            || !nm_topology_anchor(found->parent))) {
      rc = prepare_inodes();
      if (rc)
        return rc;
    }
    return nm_topology_replace(found, rule, updates);
  }
  struct nm_topology_leaf* pending = nm_topology_new_leaf(path, length, rule, false);
  if (IS_ERR(pending))
    return PTR_ERR(pending);
  // 另留一份输入引用：成功后撤销暂存引用，失败时调用者仍持有原引用。
  nm_rule_get(rule);
  struct nm_topology_leaf* child = pending;
  struct nm_directory_node* boundary = NULL;
  struct nm_topology_anchor* anchor = NULL;
  bool new_anchor = false;
  char* scratch = nm_zalloc(length + 1UL);
  if (!scratch) {
    rc = -ENOMEM;
    goto failed;
  }
  memcpy(scratch, path, length);
  unsigned int cursor = length;
  while (cursor > 1) {
    unsigned int slash = cursor - 1;
    while (slash && scratch[slash] != '/') slash--;
    unsigned int parent_length = slash ? slash : 1;
    struct nm_topology_leaf* parent = nm_topology_find(path, parent_length);
    if (parent) {
      struct nomount_rule* selected = nm_select_rule(parent->leaf, rule->target_uid);
      if ((selected && !(selected->flags & NM_FLAG_IS_DIR)) || !parent->leaf->this_dir) {
        rc = -ENOTDIR;
        break;
      }
      boundary = parent->leaf->this_dir;
      anchor = nm_topology_anchor(boundary);
      break;
    }
    char saved = scratch[parent_length];
    scratch[parent_length] = 0;
    struct nm_path native = {0};
    bool inherited = nm_topology_has_directory_ancestor(path, parent_length);
    // 已登记目录下建立私有管理父链；读侧按实际父视图继承来源，避免捕获管理者的 UID 视图。
    rc = inherited ? -ENOENT : kfunc(nm_kern_path)(scratch, 1, &native);
    scratch[parent_length] = saved;
    if (!rc) {
      anchor = nm_topology_make_anchor(native, &new_anchor);
      if (IS_ERR(anchor)) {
        rc = PTR_ERR(anchor);
        anchor = NULL;
      } else {
        boundary = anchor->node;
      }
      break;
    }
    if (rc != -ENOENT || parent_length == 1)
      break;
    struct nomount_rule* directory = nm_alloc_rule(NULL, 0, NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR, 0);
    if (IS_ERR(directory)) {
      rc = PTR_ERR(directory);
      break;
    }
    directory->inherit_backing = true;  // 父视图以后可从pure替换为backing，来源由每次查找决定。
    directory->automatic_parent = true;
    parent = nm_topology_new_leaf(path, parent_length, directory, true);
    if (IS_ERR(parent)) {
      rc = PTR_ERR(parent);
      nm_rule_put(directory);
      break;
    }
    parent->next = pending;
    pending = parent;
    rc = nm_insert_child(&parent->leaf->this_dir->children, child->leaf);
    if (rc)
      break;
    nm_directory_node_get(parent->leaf->this_dir);
    child->parent = parent->leaf->this_dir;
    child = parent;
    cursor = parent_length;
  }
  nm_free(scratch);
  if (!boundary || rc)
    goto failed;
  if (nm_topology_cycle(boundary, child->leaf->this_dir)) {
    rc = -ELOOP;
    goto failed;
  }
  // 用本次实际解析并持有的拓扑判定，避免另做一次路径探测后出现 TOCTOU。
  // 多个 pending 节点表示新增了虚拟父链；owner 表示已在管理目录视图内。
  if (rule->flags != NM_FLAG_WHITEOUT || pending->next || !anchor || boundary->owner) {
    rc = nm_topology_check_inode_allocation(boundary, anchor);
    if (!rc && prepare_inodes)
      rc = prepare_inodes();
    if (rc)
      goto failed;
  }
  struct nomount_child_array* array = nm_build_inserted_child(nm_rules_load(boundary->children), child->leaf);
  if (IS_ERR(array)) {
    rc = PTR_ERR(array);
    goto failed;
  }
  struct dentry* cached = nm_topology_cached_child(anchor, child->leaf);
  if (IS_ERR(cached)) {
    nm_free(array);
    rc = PTR_ERR(cached);
    goto failed;
  }
  if (anchor) {
    rc = nm_install_directory(nm_dentry_inode(anchor->path.dentry), boundary);
    if (rc) {
      if (cached)
        kfunc(nm_dput)(cached);
      nm_free(array);
      goto failed;
    }
  }
  nm_directory_node_get(boundary);
  child->parent = boundary;
  if (new_anchor) {
    anchor->next = nm_topology_anchors;
    nm_topology_anchors = anchor;
  }
  // 最后一项发布前，记录、节点引用及整个私有子树均已完成；之后没有分配或失败返回。
  nm_publish_children(&boundary->children, array);
  while (pending) {
    struct nm_topology_leaf* next = pending->next;
    pending->next = nm_topology_leaves;
    nm_topology_leaves = pending;
    pending = next;
  }
  nm_rule_put(rule);  // 抵消暂存引用，成功保留由叶节点持有的输入引用。
  nm_topology_invalidate(anchor, cached);
  return 0;
failed:
  while (pending) {
    struct nm_topology_leaf* next = pending->next;
    if (pending->leaf->this_dir && pending->leaf->this_dir->owner == pending)
      pending->leaf->this_dir->owner = NULL;
    nm_topology_free_leaf(pending);
    pending = next;
  }
  if (new_anchor)
    nm_topology_free_anchor(anchor);
  rule->published = false;  // 此失败路径的私有树从未发布，输入仍可由调用者重试或释放。
  return rc;
}

// 原有拓扑入口不承担控制接口接线；控制层用 prepared 入口在实际发布边界准备能力。
static int nm_topology_add_locked(const char* path, u16 length, struct nomount_rule* rule,
                                  struct nm_topology_updates* updates) {
  return nm_topology_add_prepared_locked(path, length, rule, updates, NULL);
}

static void nm_topology_unlink(struct nm_topology_leaf* entry, struct nm_topology_updates* updates) {
  struct nm_topology_leaf** slot = &nm_topology_leaves;
  while (*slot != entry) slot = &(*slot)->next;
  *slot = entry->next;
  if (entry->leaf->this_dir) {
    entry->leaf->this_dir->owner = NULL;
    nm_publish_children(&entry->leaf->this_dir->children, NULL);
  }
  entry->next = updates->leaves;
  updates->leaves = entry;
}
static void nm_topology_retire_empty_anchors(struct nm_topology_updates* updates) {
  struct nm_topology_anchor** slot = &nm_topology_anchors;
  while (*slot) {
    struct nm_topology_anchor* anchor = *slot;
    if (nm_rules_load(anchor->node->children) || anchor->node->owner) {
      slot = &anchor->next;
      continue;
    }
    *slot = anchor->next;
    anchor->next = updates->anchors;
    updates->anchors = anchor;
  }
}

static int nm_topology_remove_scope_locked(const char* path, u16 length, u32 uid, u32 end, u32 deny_start, u32 deny_end,
                                           struct nm_topology_updates* updates) {
  if (!nm_topology_ready)
    return -ENODEV;
  length = path ? nm_trim_path(path, length) : length;
  int rc = nm_topology_path_valid(path, length);
  if (rc)
    return rc;
  struct nm_topology_leaf* entry = nm_topology_find(path, length);
  struct nm_rule_array* rules = entry ? nm_rules_load(entry->leaf->rules) : NULL;
  if (!rules)
    return -ENOENT;
  struct nomount_rule* rule = NULL;
  for (u32 i = 0; i < rules->count; i++)
    if (rules->rules[i]->target_uid == uid && rules->rules[i]->uid_end == end
        && rules->rules[i]->deny_start == deny_start && rules->rules[i]->deny_end == deny_end)
      rule = rules->rules[i];
  if (!rule)
    return -ENOENT;
  if (entry->leaf->this_dir && nm_rules_load(entry->leaf->this_dir->children)) {
    if ((rule->flags & NM_FLAG_IS_DIR) || (!uid && !end) || rules->rules[0]->target_uid || rules->rules[0]->uid_end) {
      if (rule->flags & NM_FLAG_VIRTUAL_DIR)
        return 0;
      struct nomount_rule* directory =
          nm_alloc_scoped_rule(NULL, 0, NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR, uid, end, deny_start, deny_end);
      if (IS_ERR(directory))
        return PTR_ERR(directory);
      directory->inherit_backing = entry->parent && entry->parent->owner;
      rc = nm_topology_replace(entry, directory, updates);
      if (rc)
        nm_rule_put(directory);
      return rc;
    }
  } else if (rules->count == 1) {
    struct nm_topology_leaf* top = entry;
    while (top->parent && top->parent->owner) {
      struct nm_topology_leaf* parent = top->parent->owner;
      struct nm_rule_array* array = nm_rules_load(parent->leaf->rules);
      struct nomount_child_array* children = nm_rules_load(top->parent->children);
      if (!array || !children || children->count != 1 || nm_entries(children)[0].leaf != top->leaf)
        break;
      // 与上游一致：最后子项删除后，所有作用域均为虚拟目录的父节点可一并退役。
      // 显式目录撤销后也会降级为虚拟目录；automatic 只决定创建方式与列表可见性。
      u32 i;
      for (i = 0; i < array->count; i++)
        if (!(array->rules[i]->flags & NM_FLAG_VIRTUAL_DIR))
          break;
      if (i < array->count)
        break;
      top = parent;
    }
    struct nm_directory_node* boundary = top->parent;
    struct nomount_child_array* array = nm_build_removed_child(nm_rules_load(boundary->children), top->leaf);
    if (IS_ERR(array))
      return PTR_ERR(array);
    struct nm_topology_anchor* anchor = nm_topology_anchor(boundary);
    struct dentry* cached = nm_topology_cached_child(anchor, top->leaf);
    if (IS_ERR(cached)) {
      if (array)
        nm_free(array);
      return PTR_ERR(cached);
    }
    nm_publish_children(&boundary->children, array);
    for (;;) {
      struct nm_topology_leaf* parent = entry->parent->owner;
      bool last = entry == top;
      nm_topology_unlink(entry, updates);
      if (last)
        break;
      entry = parent;
    }
    nm_topology_retire_empty_anchors(updates);
    nm_topology_invalidate(anchor, cached);
    return 0;
  }
  rc = nm_remove_leaf_rule_scope(entry->leaf, uid, end, deny_start, deny_end, &updates->rules);
  return rc;
}

static int nm_topology_remove_locked(const char* path, u16 length, u32 uid, struct nm_topology_updates* updates) {
  return nm_topology_remove_scope_locked(path, length, uid, uid, 0, 0, updates);
}

// 调用者解锁后执行；一次宽限期覆盖本批次的规则、叶节点和原生 anchor 路径。
static void nm_reclaim_topology_updates(struct nm_topology_updates* updates) {
  if (!updates->rules.rules && !updates->leaves && !updates->anchors)
    return;
  nm_rcu_synchronize();
  while (updates->rules.rules) {
    struct nomount_rule* rule = updates->rules.rules;
    updates->rules.rules = rule->next;
    nm_rule_put(rule);
  }
  while (updates->leaves) {
    struct nm_topology_leaf* entry = updates->leaves;
    updates->leaves = entry->next;
    nm_topology_free_leaf(entry);
  }
  while (updates->anchors) {
    struct nm_topology_anchor* anchor = updates->anchors;
    updates->anchors = anchor->next;
    nm_topology_free_anchor(anchor);
  }
}

static void nm_reclaim_topology_async(void* data, u64 cookie) {
  struct nm_topology_updates* updates = data;
  nm_reclaim_topology_updates(updates);
  nm_free(updates);
}

// 所有读侧入口已在管理锁内撤销；提交后只转交私有退役链，不再访问活动拓扑。
// 原生 async 可能因分配失败同步执行，因此必须在解锁后的进程上下文调用。
static void nm_finish_topology_updates(struct nm_topology_updates* updates) {
  if (!updates->rules.rules && !updates->leaves && !updates->anchors)
    return;
  struct nm_topology_updates* pending =
      nm_async_schedule_node || nm_async_schedule ? nm_zalloc(sizeof(*pending)) : NULL;
  if (!pending) {
    nm_reclaim_topology_updates(updates);
    return;
  }
  *pending = *updates;
  *updates = (struct nm_topology_updates){0};
  if (nm_async_schedule_node)
    nm_async_schedule_node(nm_reclaim_topology_async, pending, -1);  // NUMA_NO_NODE。
  else
    nm_async_schedule(nm_reclaim_topology_async, pending);
}

// 全部清空不分配新数组；先撤销所有读侧入口，再把引用交给解锁后的统一回收。
static int nm_topology_clear_locked(struct nm_topology_updates* updates) {
  if (!nm_topology_ready)
    return -ENODEV;
  while (nm_topology_leaves) {
    struct nm_topology_leaf* entry = nm_topology_leaves;
    nm_topology_leaves = entry->next;
    if (entry->leaf->this_dir) {
      entry->leaf->this_dir->owner = NULL;
      nm_publish_children(&entry->leaf->this_dir->children, NULL);
    }
    entry->next = updates->leaves;
    updates->leaves = entry;
  }
  for (struct nm_topology_anchor* anchor = nm_topology_anchors; anchor; anchor = anchor->next)
    nm_publish_children(&anchor->node->children, NULL);
  nm_topology_retire_empty_anchors(updates);
  return 0;
}
