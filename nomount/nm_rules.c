/* SPDX-License-Identifier: GPL-2.0-only */
/* Rule selection and immutable arrays adapted from the pinned NoMount source. */
static int kfunc_def(nm_kern_path)(const char*, unsigned int, struct nm_path*);
static void kfunc_def(nm_path_put)(const struct nm_path*);
static void kfunc_def(nm_path_get)(const struct nm_path*);
static u32 kfunc_def(nm_full_name_hash)(const void*, const char*, unsigned int);
static u32 (*nm_full_name_hash_pair)(const char*, unsigned int);

static u32 nm_name_hash(const void* salt, const char* name, unsigned int length) {
  return nm_full_name_hash_pair ? nm_full_name_hash_pair(name, length) : kfunc(nm_full_name_hash)(salt, name, length);
}

static int nm_prepare_rule_functions(void) {
  int args = nm_name_hash_arguments();
  if (args < 0)
    return -ENOENT;
  if (args != 2 && args != 3)
    return -EOPNOTSUPP;
  kfunc(nm_kern_path) = (typeof(kfunc(nm_kern_path)))kallsyms_lookup_name_by_suffix("kern_path");
  kfunc(nm_path_put) = (typeof(kfunc(nm_path_put)))kallsyms_lookup_name_by_suffix("path_put");
  kfunc(nm_path_get) = (typeof(kfunc(nm_path_get)))kallsyms_lookup_name_by_suffix("path_get");
  kfunc(nm_full_name_hash) = (typeof(kfunc(nm_full_name_hash)))kallsyms_lookup_name_by_suffix("full_name_hash");
  nm_full_name_hash_pair = args == 2 ? (void*)kfunc(nm_full_name_hash) : NULL;
  return kfunc(nm_kern_path) && kfunc(nm_path_put) && kfunc(nm_path_get) && kfunc(nm_full_name_hash) ? 0 : -ENOENT;
}

// 仅适用于 head-first 的模块私有分配对象；不释放任何原生路径引用。
static void nm_rules_rcu_free(struct rcu_head* head) { nm_free_rcu(head); }

static void nm_rules_retire(struct rcu_head* head) {
  if (head)
    nm_rcu_call(head, nm_rules_rcu_free);
}

static unsigned int nm_trim_path(const char* path, unsigned int length) {
  while (length > 1 && path[length - 1] == '/') length--;
  return length;
}

static bool nm_rule_path_valid(const char* path, unsigned int length) {
  return path && length && length < 4096 && path[0] == '/' && !memchr(path, 0, length);
}

// 路径引用归规则对象持有；最后一个引用在进程上下文释放。
static struct nomount_rule* nm_alloc_rule(const char* path, u16 length, u32 flags, u32 uid) {
  if (flags & ~(NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT))
    return ERR_PTR(-EINVAL);
  if ((flags & NM_FLAG_VIRTUAL_DIR) && (!(flags & NM_FLAG_IS_DIR) || (flags & NM_FLAG_WHITEOUT)))
    return ERR_PTR(-EINVAL);
  bool backed = !(flags & (NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT));
  if (backed && !nm_rule_path_valid(path, length))
    return ERR_PTR(-EINVAL);
  length = backed ? nm_trim_path(path, length) : 0;
  struct nomount_rule* rule = nm_zalloc(sizeof(*rule) + length + 1);
  if (!rule)
    return ERR_PTR(-ENOMEM);
  rule->refs = 1;
  rule->target_uid = uid;
  rule->flags = flags;
  rule->r_len = length;
  if (backed) {
    memcpy(rule->paths, path, length);
    struct nm_path resolved = {0};
    int rc = kfunc(nm_kern_path)(rule->paths, 1, &resolved);  // LOOKUP_FOLLOW, namei.h
    if (rc) {
      nm_free(rule);
      return ERR_PTR(rc);
    }
    const struct inode* inode = nm_dentry_inode(resolved.dentry);
    if (!inode) {
      kfunc(nm_path_put)(&resolved);
      nm_free(rule);
      return ERR_PTR(-ENOENT);
    }
    // IS_DIR 来自 backing inode，不能靠控制载荷把普通文件伪装成目录。
    rule->flags &= ~NM_FLAG_IS_DIR;
    if ((nm_inode_mode(inode) & 0170000) == 0040000)
      rule->flags |= NM_FLAG_IS_DIR;
    rule->r_path = resolved;
  }
  return rule;
}

static void nm_rule_get(struct nomount_rule* rule) { __atomic_add_fetch(&rule->refs, 1, __ATOMIC_RELAXED); }

static void nm_rule_put(struct nomount_rule* rule) {
  if (!rule || __atomic_sub_fetch(&rule->refs, 1, __ATOMIC_ACQ_REL))
    return;
  if (rule->r_path.dentry)
    kfunc(nm_path_put)(&rule->r_path);
  nm_free(rule);
}

// 管理层解锁后调用。一次宽限期覆盖本批次退役的所有规则。
static void nm_finish_rule_updates(struct nm_rule_updates* updates) {
  if (!updates->rules)
    return;
  nm_rcu_synchronize();
  while (updates->rules) {
    struct nomount_rule* rule = updates->rules;
    updates->rules = rule->next;
    nm_rule_put(rule);
  }
}

static struct nomount_leaf* nm_alloc_leaf(const char* path, u16 length) {
  if (!nm_rule_path_valid(path, length))
    return ERR_PTR(-EINVAL);
  length = nm_trim_path(path, length);
  struct nomount_leaf* leaf = nm_zalloc(sizeof(*leaf) + length + 1);
  if (!leaf)
    return ERR_PTR(-ENOMEM);
  leaf->v_len = length;
  memcpy(leaf->paths, path, length);
  leaf->v_ino = nm_name_hash((const void*)(uintptr_t)NOMOUNT_MAGIC_SIG, leaf->paths, length);
  unsigned int slash = length;
  while (slash && path[slash - 1] != '/') slash--;
  leaf->child_len = length - slash;
  return leaf;
}

// 叶节点已从所有拓扑索引摘下，且调用者等待过原生 RCU 宽限期。
static void nm_free_leaf(struct nomount_leaf* leaf) {
  struct nm_rule_array* rules = nm_rules_load(leaf->rules);
  if (rules) {
    for (u32 i = 0; i < rules->count; i++) nm_rule_put(rules->rules[i]);
    nm_free(rules);
  }
  nm_free(leaf);
}

// 指针只在调用者的 RCU 读侧范围内有效；带出范围须先取得规则引用。
static struct nomount_rule* nm_select_rule(struct nomount_leaf* leaf, u32 uid) {
  struct nm_rule_array* array = nm_rules_load(leaf->rules);
  struct nomount_rule* fallback = NULL;
  if (array) {
    for (u32 i = 0; i < array->count; i++) {
      struct nomount_rule* rule = array->rules[i];
      if (rule->target_uid == uid)
        return rule;
      if (!rule->target_uid)
        fallback = rule;
      if (rule->target_uid > uid)
        break;
    }
  }
  return fallback;
}

static struct nm_rule_array* nm_alloc_rule_array(u32 count) {
  struct nm_rule_array* array = nm_zalloc(sizeof(*array) + (unsigned long)count * sizeof(array->rules[0]));
  if (array)
    array->count = count;
  return array;
}

// 只构造新数组，失败保持原状态；拓扑层可先备齐节点再统一发布。
static struct nm_rule_array* nm_build_leaf_rule_array(struct nomount_leaf* leaf, struct nomount_rule* rule) {
  if (rule->published)
    return ERR_PTR(-EINVAL);
  struct nm_rule_array* old = nm_rules_load(leaf->rules);
  u32 count = old ? old->count : 0, pos = 0;
  while (pos < count && old->rules[pos]->target_uid < rule->target_uid) pos++;
  bool replace = pos < count && old->rules[pos]->target_uid == rule->target_uid;
  if (!replace && count == (u32)-1)
    return ERR_PTR(-EOVERFLOW);
  struct nm_rule_array* array = nm_alloc_rule_array(count + !replace);
  if (!array)
    return ERR_PTR(-ENOMEM);
  if (old) {
    memcpy(array->rules, old->rules, pos * sizeof(rule));
    memcpy(array->rules + pos + 1, old->rules + pos + replace, (count - pos - replace) * sizeof(rule));
  }
  array->rules[pos] = rule;
  return array;
}

// 修改者持管理锁，array 来自本次 nm_build_leaf_rule_array；接收新规则的一份引用。
static void nm_publish_leaf_rule(struct nomount_leaf* leaf, struct nomount_rule* rule, struct nm_rule_array* array,
                                 struct nm_rule_updates* updates) {
  struct nm_rule_array* old = nm_rules_load(leaf->rules);
  struct nomount_rule* retired = NULL;
  if (old)
    for (u32 i = 0; i < old->count; i++)
      if (old->rules[i]->target_uid == rule->target_uid) {
        retired = old->rules[i];
        break;
      }
  rule->published = true;
  nm_rules_publish(leaf->rules, array);
  if (retired) {
    retired->next = updates->rules;
    updates->rules = retired;
  }
  if (old)
    nm_rules_retire(&old->rcu);
}

// 输入为尚未发布的新规则。成功转交一个引用；失败时调用者仍持有该引用。
static int nm_set_leaf_rule(struct nomount_leaf* leaf, struct nomount_rule* rule, struct nm_rule_updates* updates) {
  struct nm_rule_array* array = nm_build_leaf_rule_array(leaf, rule);
  if (IS_ERR(array))
    return PTR_ERR(array);
  nm_publish_leaf_rule(leaf, rule, array, updates);
  return 0;
}

// 拓扑层先处理有子目录的叶节点（保留虚拟目录规则），再调用这个数组操作。
static int nm_remove_leaf_rule(struct nomount_leaf* leaf, u32 uid, struct nm_rule_updates* updates) {
  struct nm_rule_array* old = nm_rules_load(leaf->rules);
  if (!old)
    return -ENOENT;
  u32 pos = 0;
  while (pos < old->count && old->rules[pos]->target_uid != uid) pos++;
  if (pos == old->count)
    return -ENOENT;
  struct nm_rule_array* array = NULL;
  if (old->count > 1) {
    array = nm_alloc_rule_array(old->count - 1);
    if (!array)
      return -ENOMEM;
    memcpy(array->rules, old->rules, pos * sizeof(array->rules[0]));
    memcpy(array->rules + pos, old->rules + pos + 1, (old->count - pos - 1) * sizeof(array->rules[0]));
  }
  struct nomount_rule* retired = old->rules[pos];
  nm_rules_publish(leaf->rules, array);
  retired->next = updates->rules;
  updates->rules = retired;
  nm_rules_retire(&old->rcu);
  return 0;
}

static struct nm_child* nm_entries(struct nomount_child_array* array) {
  return (void*)(array->bloom + array->bloom_words);
}

static u32 nm_bloom_words_for(u32 count) {
  if (count <= 2)
    return 0;
  if (count <= 16)
    return 4;
  if (count <= 64)
    return 16;
  if (count <= 256)
    return 64;
  return count <= 1024 ? 128 : 256;
}

static u32 nm_qhash(const char* name, unsigned int length) {
  u32 hash = (u8)name[0] ^ length;
  hash = (hash << 5) + (u8)name[length - 1];
  return (hash << 5) + (u8)name[length >> 1];
}

static struct nomount_child_array* nm_alloc_children(u32 count) {
  u32 words = nm_bloom_words_for(count);
  struct nomount_child_array* array =
      nm_zalloc(sizeof(*array) + words * sizeof(u64) + (unsigned long)count * sizeof(struct nm_child));
  if (array) {
    array->count = count;
    array->bloom_words = words;
  }
  return array;
}

static void nm_rebuild_bloom(struct nomount_child_array* array) {
  if (!array->bloom_words)
    return;
  for (u32 i = 0; i < array->count; i++) {
    u32 hash = nm_entries(array)[i].bloom_hash;
    array->bloom[(hash >> 6) & (array->bloom_words - 1)] |= 1ULL << (hash & 63);
  }
}

static bool nm_child_matches(struct nomount_leaf* leaf, const char* name, unsigned int length) {
  if (!leaf || !length || leaf->child_len != length)
    return false;
  const char* child = leaf->paths + leaf->v_len - length;
  return child[0] == name[0] && child[length - 1] == name[length - 1] && !memcmp(child, name, length);
}

static struct nomount_leaf* nomount_bsearch_child(struct nomount_child_array* array, const char* name,
                                                  unsigned int length, u32 hash, u32* index) {
  u32 lower = 0, count = array->count;
  struct nm_child* entries = nm_entries(array);
  while (count) {
    u32 step = count >> 1, middle = lower + step;
    if (entries[middle].hash < hash) {
      lower = middle + 1;
      count -= step + 1;
    } else {
      count = step;
    }
  }
  if (index)
    *index = lower;
  for (u32 i = lower; i < array->count && entries[i].hash == hash; i++) {
    struct nomount_leaf* leaf = entries[i].leaf;
    if (nm_child_matches(leaf, name, length)) {
      if (index)
        *index = i;
      return leaf;
    }
  }
  return NULL;
}

static struct nomount_leaf* nm_find_child(struct nomount_child_array* array, const char* name, unsigned int length) {
  if (!array || !name || !length)
    return NULL;
  u32 quick = nm_qhash(name, length);
  if (!array->bloom_words) {
    struct nm_child* entries = nm_entries(array);
    for (u32 i = 0; i < array->count; i++)
      if (entries[i].bloom_hash == quick && nm_child_matches(entries[i].leaf, name, length))
        return entries[i].leaf;
    return NULL;
  }
  if (!(array->bloom[(quick >> 6) & (array->bloom_words - 1)] & (1ULL << (quick & 63))))
    return NULL;
  u32 hash = nm_name_hash((const void*)(uintptr_t)NOMOUNT_MAGIC_SIG, name, length);
  return nomount_bsearch_child(array, name, length, hash, NULL);
}

// 构造而不发布。原数组和 leaf 的引用仍由调用者管理。
static struct nomount_child_array* nm_build_inserted_child(struct nomount_child_array* old, struct nomount_leaf* leaf) {
  if (!leaf || !leaf->child_len || leaf->child_len > leaf->v_len)
    return ERR_PTR(-EINVAL);
  const char* name = leaf->paths + leaf->v_len - leaf->child_len;
  u32 hash = nm_name_hash((const void*)(uintptr_t)NOMOUNT_MAGIC_SIG, name, leaf->child_len);
  u32 pos = 0, count = old ? old->count : 0;
  if (old && nomount_bsearch_child(old, name, leaf->child_len, hash, &pos))
    return ERR_PTR(-EEXIST);
  if (count == (u32)-1)
    return ERR_PTR(-EOVERFLOW);
  struct nomount_child_array* array = nm_alloc_children(count + 1);
  if (!array)
    return ERR_PTR(-ENOMEM);
  if (old) {
    memcpy(nm_entries(array), nm_entries(old), pos * sizeof(struct nm_child));
    memcpy(nm_entries(array) + pos + 1, nm_entries(old) + pos, (count - pos) * sizeof(struct nm_child));
  }
  nm_entries(array)[pos] = (struct nm_child){hash, nm_qhash(name, leaf->child_len), leaf};
  nm_rebuild_bloom(array);
  return array;
}
static struct nomount_child_array* nm_build_removed_child(struct nomount_child_array* old, struct nomount_leaf* leaf) {
  if (!old)
    return ERR_PTR(-ENOENT);
  u32 pos = 0;
  while (pos < old->count && nm_entries(old)[pos].leaf != leaf) pos++;
  if (pos == old->count)
    return ERR_PTR(-ENOENT);
  struct nomount_child_array* array = NULL;
  if (old->count > 1) {
    array = nm_alloc_children(old->count - 1);
    if (!array)
      return ERR_PTR(-ENOMEM);
    memcpy(nm_entries(array), nm_entries(old), pos * sizeof(struct nm_child));
    memcpy(nm_entries(array) + pos, nm_entries(old) + pos + 1, (old->count - pos - 1) * sizeof(struct nm_child));
    nm_rebuild_bloom(array);
  }
  return array;
}
static void nm_publish_children(struct nomount_child_array** children, struct nomount_child_array* array) {
  struct nomount_child_array* old = nm_rules_load(*children);
  nm_rules_publish(*children, array);
  if (old)
    nm_rules_retire(&old->rcu);
}

// 仅发布 child 指针，引用和父目录关系由拓扑层持有；失败保持旧数组。
static int nm_insert_child(struct nomount_child_array** children, struct nomount_leaf* leaf) {
  struct nomount_child_array* array = nm_build_inserted_child(nm_rules_load(*children), leaf);
  if (IS_ERR(array))
    return PTR_ERR(array);
  nm_publish_children(children, array);
  return 0;
}
static int nm_remove_child(struct nomount_child_array** children, struct nomount_leaf* leaf) {
  struct nomount_child_array* array = nm_build_removed_child(nm_rules_load(*children), leaf);
  if (IS_ERR(array))
    return PTR_ERR(array);
  nm_publish_children(children, array);
  // 拓扑层移除叶节点时，仍需等宽限期再释放 leaf。
  return 0;
}

static struct nm_uid_array* nomount_uids;
static bool nm_block_isolated_uids;

static void nm_uid_bloom_set(struct nm_uid_array* array, u32 uid) {
  array->bloom_mask[(uid >> 6) & 3] |= 1ULL << (uid & 63);
}
static bool nm_uid_bloom_test(const struct nm_uid_array* array, u32 uid) {
  return !!(array->bloom_mask[(uid >> 6) & 3] & (1ULL << (uid & 63)));
}

static int nm_uid_add(u32 uid) {
  struct nm_uid_array* old = nm_rules_load(nomount_uids);
  u32 count = old ? old->count : 0;
  for (u32 i = 0; i < count; i++)
    if (old->uids[i] == uid)
      return -EEXIST;
  if (count == (u32)-1)
    return -EOVERFLOW;
  struct nm_uid_array* array = nm_zalloc(sizeof(*array) + ((unsigned long)count + 1) * sizeof(u32));
  if (!array)
    return -ENOMEM;
  array->count = count + 1;
  if (old) {
    memcpy(array->uids, old->uids, count * sizeof(u32));
    memcpy(array->bloom_mask, old->bloom_mask, sizeof(array->bloom_mask));
  }
  array->uids[count] = uid;
  nm_uid_bloom_set(array, uid);
  nm_rules_publish(nomount_uids, array);
  if (old)
    nm_rules_retire(&old->rcu);
  return 0;
}

static int nm_uid_del(u32 uid) {
  struct nm_uid_array* old = nm_rules_load(nomount_uids);
  if (!old)
    return -ENOENT;
  u32 pos = 0;
  while (pos < old->count && old->uids[pos] != uid) pos++;
  if (pos == old->count)
    return -ENOENT;
  struct nm_uid_array* array = NULL;
  if (old->count > 1) {
    array = nm_zalloc(sizeof(*array) + (unsigned long)(old->count - 1) * sizeof(u32));
    if (!array)
      return -ENOMEM;
    array->count = old->count - 1;
    memcpy(array->uids, old->uids, pos * sizeof(u32));
    memcpy(array->uids + pos, old->uids + pos + 1, (old->count - pos - 1) * sizeof(u32));
    for (u32 i = 0; i < array->count; i++) nm_uid_bloom_set(array, array->uids[i]);
  }
  nm_rules_publish(nomount_uids, array);
  nm_rules_retire(&old->rcu);
  return 0;
}

static void nm_uid_clear(void) {
  struct nm_uid_array* old = nm_rules_load(nomount_uids);
  nm_rules_publish(nomount_uids, NULL);
  if (old)
    nm_rules_retire(&old->rcu);
}

static bool nomount_is_uid_blocked(u32 uid) {
  u32 app_id = uid % 100000U;
  if (__atomic_load_n(&nm_block_isolated_uids, __ATOMIC_RELAXED) && app_id >= 90000U && app_id <= 99999U)
    return true;
  if (!nm_rules_load(nomount_uids))
    return false;
  bool blocked = false;
  nm_rcu_read_lock();
  struct nm_uid_array* array = nm_rules_load(nomount_uids);
  if (array && nm_uid_bloom_test(array, uid))
    for (u32 i = 0; i < array->count; i++)
      if (array->uids[i] == uid) {
        blocked = true;
        break;
      }
  nm_rcu_read_unlock();
  return blocked;
}

static void nm_uid_list(struct nm_payload* payload) {
  u32 index = payload->arg1, count = 0;
  nm_rcu_read_lock();
  struct nm_uid_array* array = nm_rules_load(nomount_uids);
  if (array) {
    while (index < array->count && count < sizeof(payload->buffer) / sizeof(u32)) {
      memcpy(payload->buffer + count * sizeof(u32), &array->uids[index++], sizeof(u32));
      count++;
    }
  }
  nm_rcu_read_unlock();
  payload->arg1 = index;
  payload->data_size = count * sizeof(u32);
}
