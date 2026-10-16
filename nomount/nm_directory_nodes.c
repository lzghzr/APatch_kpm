/* SPDX-License-Identifier: GPL-2.0-only */
/* Private child views and enumeration adapted from the pinned NoMount source. */
struct nm_topology_leaf;
struct nm_directory_node {
  struct rcu_head rcu;
  struct nomount_child_array* children;
  u32 refs;
  struct nm_topology_leaf* owner;  // 仅管理锁内使用，不进入回调热路径。
};

static struct nm_directory_node* nm_new_directory_node(void) {
  struct nm_directory_node* node = nm_zalloc(sizeof(*node));
  if (node)
    node->refs = 1;
  return node;
}
static void nm_directory_node_get(struct nm_directory_node* node) {
  __atomic_add_fetch(&node->refs, 1, __ATOMIC_RELAXED);
}
static void nm_directory_node_rcu_free(struct rcu_head* head) {
  struct nm_directory_node* node = (void*)head;
  nm_free_rcu(nm_rules_load(node->children));
  nm_free_rcu(node);
}
static void nm_directory_node_put(struct nm_directory_node* node) {
  if (node && !__atomic_sub_fetch(&node->refs, 1, __ATOMIC_ACQ_REL))
    nm_rcu_call(&node->rcu, nm_directory_node_rcu_free);
}

// 调用者在原生 RCU 读侧；需要交给物化层时另取引用。
static struct nomount_rule* nm_directory_rule(struct nm_directory_node* node, const char* name, unsigned int length,
                                              u32 uid, u64* number, bool retain) {
  struct nomount_leaf* leaf = node ? nm_find_child(nm_rules_load(node->children), name, length) : NULL;
  struct nomount_rule* rule = leaf ? nm_select_rule(leaf, uid) : NULL;
  if (rule) {
    if (number)
      *number = leaf->v_ino;
    if (retain)
      nm_rule_get(rule);
  }
  return rule;
}

// 保持原版 cookie 编码，且不在 32 位索引耗尽时回绕。
static bool nm_virtual_position(int64_t position, bool compat) {
  return compat ? ((u64)position & 0xffff0000ULL) == 0x6e6d0000ULL
                : ((u64)position & 0xffffffff00000000ULL) == 0x6e6d000000000000ULL;
}
static int64_t nm_directory_position(u32 index, bool compat) {
  return compat ? (0x6e6d0000ULL | index) : (0x6e6d000000000000ULL | index);
}
static int nm_emit_children(struct nm_directory_node* node, struct nm_dir_context* context, u32 uid, bool compat) {
  if (!nm_virtual_position(context->pos, compat))
    context->pos = nm_directory_position(0, compat);
  u32 index = compat ? (u64)context->pos & 0xffffU : (u64)context->pos & 0xffffffffU;
  for (;;) {
    char name[256];
    unsigned int length = 0, type = 0;
    u64 number = 0;
    nm_rcu_read_lock();
    struct nomount_child_array* array = node ? nm_rules_load(node->children) : NULL;
    bool more = array && index < array->count;
    if (compat && array && array->count > 0xffffU) {
      nm_rcu_read_unlock();
      return -EOVERFLOW;
    }
    if (more) {
      struct nomount_leaf* leaf = nm_entries(array)[index].leaf;
      struct nomount_rule* rule = leaf ? nm_select_rule(leaf, uid) : NULL;
      if (rule && !(rule->flags & NM_FLAG_WHITEOUT) && leaf->child_len && leaf->child_len <= 255) {
        length = leaf->child_len;
        memcpy(name, leaf->paths + leaf->v_len - length, length);
        number = leaf->v_ino;
        type = rule->flags & NM_FLAG_IS_DIR ? 4 : 8;  // DT_DIR / DT_REG。
      }
    }
    nm_rcu_read_unlock();
    if (!more)
      return 0;
    context->pos = nm_directory_position(index, compat);
    // 原生 actor 可拷贝用户页；不能在 RCU 读锁内调用。
    if (length && nm_dir_emit(context, name, length, context->pos, number, type))
      return 0;
    if (index == (u32)-1)
      return -EOVERFLOW;
    index++;
    context->pos = nm_directory_position(index, compat);
  }
}
