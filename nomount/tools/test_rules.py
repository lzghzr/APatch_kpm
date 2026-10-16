#!/usr/bin/env python3
"""执行规则生产代码的宿主自检；原生引用/RCU 路由为契约夹具，不证明内核并发。"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    symbols = {name: kind for _, kind, name in json.loads(args.symbols.read_text())}
    dependencies = ('kern_path', 'path_put', 'full_name_hash')
    assert all(symbols.get(name) in ('T', 't') for name in dependencies)
    files = ('nomount/nm_structs.h', 'nomount/nm_protocol.h', 'nomount/nm_rules.h',
             'nomount/nm_rules.c', 'nomount/nm_offsets.c')
    prelude = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
struct rcu_head { struct rcu_head* next; void (*func)(struct rcu_head*); };
static void* host_alloc(unsigned long);
static void host_free(const void*);
static void* (*kf_nm_vzalloc)(unsigned long) = host_alloc;
static void (*kf_nm_vfree)(const void*) = host_free;
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
static void nm_rcu_read_lock(void);
static void nm_rcu_read_unlock(void);
static void nm_rcu_synchronize(void);
static void nm_rcu_call(struct rcu_head*, void (*)(struct rcu_head*));
'''
    source = prelude
    for name in files[:3]:
        source += (root / name).read_text()
    offsets = (root / files[4]).read_text()
    accessors = offsets.split('static struct inode* nm_dentry_inode', 1)[1].split('static int validate_offsets', 1)[0]
    source += 'static struct inode* nm_dentry_inode' + accessors
    source += (root / files[3]).read_text()
    source += r'''
static int allocated, released, fail_next, depth, syncs, path_refs, path_puts, path_error;
static const char* missing;
static bool collide = true;
static struct rcu_head* queue[8192];
static unsigned int queued;
static struct nm_inode_owner_prefix file_inode = {.i_mode = 0100644};
static struct nm_inode_owner_prefix dir_inode = {.i_mode = 0040755};
static struct nm_dentry_head file_dentry, dir_dentry, negative_dentry;
static void* host_alloc(unsigned long size) {
  if (fail_next) { fail_next = 0; return NULL; }
  void* out = calloc(1, size); assert(out); allocated++; return out;
}
static void host_free(const void* allocation) {
  assert(allocation); released++; free((void*)allocation);
}
static void nm_rcu_read_lock(void) { depth++; }
static void nm_rcu_read_unlock(void) { assert(depth); depth--; }
static void nm_rcu_synchronize(void) { assert(!depth); syncs++; }
static void nm_rcu_call(struct rcu_head* head, void (*callback)(struct rcu_head*)) {
  assert(queued < sizeof(queue)/sizeof(queue[0])); head->func = callback; queue[queued++] = head;
}
static void flush_callbacks(void) {
  assert(!depth);
  while (queued) { struct rcu_head* head = queue[--queued]; head->func(head); }
}
static int host_path(const char* name, unsigned int flags, struct nm_path* result) {
  assert(flags == 1);
  assert(!depth);
  if (path_error) return path_error;
  result->mnt = (void*)123;
  if (!strcmp(name, "/data/file")) result->dentry = &file_dentry;
  else if (!strcmp(name, "/data/dir")) result->dentry = &dir_dentry;
  else if (!strcmp(name, "/data/negative")) result->dentry = &negative_dentry;
  else return -ENOENT;
  path_refs++; return 0;
}
static void host_path_put(const struct nm_path* path) {
  assert(path->mnt == (void*)123 && path->dentry && path_refs > 0 && !depth);
  path_refs--; path_puts++;
}
// 强制全名哈希碰撞，确认二分查找之后仍比较完整名字。
static u32 host_hash(const void* salt, const char* name, unsigned int length) {
  assert((uintptr_t)salt == NOMOUNT_MAGIC_SIG && name && length);
  if (collide) return 17;
  u32 hash = 2166136261U;
  for (unsigned int i = 0; i < length; i++) hash = (hash ^ (u8)name[i]) * 16777619U;
  return hash;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (missing && !strcmp(missing, name)) return 0;
  if (!strcmp(name, "kern_path")) return (uintptr_t)host_path;
  if (!strcmp(name, "path_put")) return (uintptr_t)host_path_put;
  if (!strcmp(name, "full_name_hash")) return (uintptr_t)host_hash;
  return 0;
}
static struct nomount_rule* alloc_rule(u32 uid, u32 flags) {
  struct nomount_rule* rule = nm_alloc_rule("/data/file", 10, flags, uid);
  assert(!IS_ERR(rule)); return rule;
}
static struct nomount_leaf* alloc_leaf(const char* name) {
  struct nomount_leaf* leaf = nm_alloc_leaf(name, strlen(name)); assert(!IS_ERR(leaf)); return leaf;
}
static void release_leaf(struct nomount_leaf* leaf) { nm_rcu_synchronize(); nm_free_leaf(leaf); }
static void check_rule_paths(void) {
  assert(PTR_ERR(nm_alloc_rule(NULL, 0, 0, 0)) == -EINVAL);
  assert(PTR_ERR(nm_alloc_rule("relative", 8, 0, 0)) == -EINVAL);
  assert(PTR_ERR(nm_alloc_rule("/data\0file", 10, 0, 0)) == -EINVAL);
  assert(PTR_ERR(nm_alloc_rule("/data/file", 10, 8, 0)) == -EINVAL);
  assert(PTR_ERR(nm_alloc_rule(NULL, 0, NM_FLAG_VIRTUAL_DIR, 0)) == -EINVAL);
  assert(PTR_ERR(nm_alloc_rule(NULL, 0, NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR|NM_FLAG_WHITEOUT, 0)) == -EINVAL);
  struct nomount_rule* rule = nm_alloc_rule("/data/dir///", 12, 0, 1000);
  assert(!IS_ERR(rule) && rule->r_len == 9 && !strcmp(rule->paths, "/data/dir"));
  assert(rule->flags == NM_FLAG_IS_DIR && path_refs == 1); nm_rule_put(rule);
  rule = alloc_rule(0, NM_FLAG_IS_DIR); assert(!rule->flags); nm_rule_put(rule);
  rule = nm_alloc_rule(NULL, 0, NM_FLAG_IS_DIR|NM_FLAG_VIRTUAL_DIR, 0);
  assert(!IS_ERR(rule) && !rule->r_path.dentry && !rule->r_len); nm_rule_put(rule);
  rule = nm_alloc_rule(NULL, 0, NM_FLAG_WHITEOUT, 0);
  assert(!IS_ERR(rule) && !rule->r_path.dentry); nm_rule_put(rule);
}
static void check_rules(void) {
  struct nm_rule_updates updates = {0};
  struct nomount_leaf* leaf = alloc_leaf("/system/app/Example.apk///");
  assert(!strcmp(leaf->paths, "/system/app/Example.apk") && leaf->child_len == 11);
  struct nomount_rule* fallback = alloc_rule(0, 0);
  struct nomount_rule* specific = alloc_rule(1000, 0);
  struct nomount_rule* earlier = alloc_rule(999, 0);
  assert(!nm_set_leaf_rule(leaf, specific, &updates));
  assert(!nm_set_leaf_rule(leaf, fallback, &updates));
  assert(!nm_set_leaf_rule(leaf, earlier, &updates));
  assert(leaf->rules->count == 3 && leaf->rules->rules[0] == fallback && leaf->rules->rules[2] == specific);
  struct nm_rule_array* unchanged = leaf->rules;
  nm_rule_get(specific);
  assert(nm_set_leaf_rule(leaf, specific, &updates) == -EINVAL && leaf->rules == unchanged && !updates.rules);
  assert(specific->refs == 2); nm_rule_put(specific);
  struct nomount_leaf* another = alloc_leaf("/system/another");
  nm_rule_get(specific);
  assert(nm_set_leaf_rule(another, specific, &updates) == -EINVAL && !another->rules && !updates.rules);
  nm_rule_put(specific); release_leaf(another);
  nm_rcu_read_lock();
  assert(nm_select_rule(leaf, 1000) == specific && nm_select_rule(leaf, 998) == fallback);
  nm_rule_get(specific); nm_rcu_read_unlock();
  struct nm_rule_array* previous = leaf->rules;
  struct nomount_rule* replacement = alloc_rule(1000, NM_FLAG_WHITEOUT);
  int before = syncs, puts = path_puts;
  assert(!nm_set_leaf_rule(leaf, replacement, &updates) && syncs == before);
  assert(path_puts == puts && specific->refs == 2 && previous->rules[2] == specific);
  nm_finish_rule_updates(&updates);
  assert(syncs == before + 1 && specific->refs == 1 && !updates.rules);
  flush_callbacks(); nm_rule_put(specific); assert(path_puts == puts + 1);
  struct nomount_rule* failed = alloc_rule(42, 0);
  previous = leaf->rules; fail_next = 1;
  assert(nm_set_leaf_rule(leaf, failed, &updates) == -ENOMEM && leaf->rules == previous && failed->refs == 1);
  nm_rule_put(failed);
  fail_next = 1; assert(nm_remove_leaf_rule(leaf, 999, &updates) == -ENOMEM && leaf->rules == previous);
  assert(nm_remove_leaf_rule(leaf, 8, &updates) == -ENOENT);
  before = syncs; puts = path_puts;
  assert(!nm_remove_leaf_rule(leaf, 999, &updates));
  assert(!nm_remove_leaf_rule(leaf, 1000, &updates));
  assert(!nm_remove_leaf_rule(leaf, 0, &updates) && !leaf->rules);
  assert(nm_remove_leaf_rule(leaf, 0, &updates) == -ENOENT);
  assert(syncs == before && path_puts == puts);
  nm_finish_rule_updates(&updates);
  assert(syncs == before + 1 && path_puts == puts + 2 && !updates.rules);
  flush_callbacks(); release_leaf(leaf);
}
static void check_children(void) {
  struct nomount_child_array* children = NULL;
  struct nomount_leaf *a = alloc_leaf("/system/aa"), *b = alloc_leaf("/system/ab"), *c = alloc_leaf("/system/ba");
  assert(!nm_insert_child(&children, a) && !nm_insert_child(&children, b) && !nm_insert_child(&children, c));
  struct nomount_child_array* held = children;
  assert(nm_insert_child(&children, b) == -EEXIST && children == held);
  struct nomount_leaf* d = alloc_leaf("/system/ac");
  fail_next = 1; assert(nm_insert_child(&children, d) == -ENOMEM && children == held);
  nm_rcu_read_lock();
  assert(nm_find_child(children, "aa", 2) == a && nm_find_child(children, "ab", 2) == b);
  assert(nm_find_child(children, "ba", 2) == c && !nm_find_child(children, "bb", 2));
  assert(!nm_find_child(children, "", 0));
  nm_rcu_read_unlock();
  fail_next = 1; assert(nm_remove_child(&children, a) == -ENOMEM && children == held);
  assert(nm_remove_child(&children, d) == -ENOENT);
  assert(!nm_remove_child(&children, b) && held->count == 3);
  assert(!nm_find_child(children, "ab", 2) && nm_find_child(children, "aa", 2) == a);
  assert(!nm_remove_child(&children, c));
  assert(!nm_remove_child(&children, a) && !children);
  assert(nm_remove_child(&children, a) == -ENOENT);
  flush_callbacks(); release_leaf(a); release_leaf(b); release_leaf(c); release_leaf(d);
  assert(nm_bloom_words_for(16) == 4 && nm_bloom_words_for(17) == 16);
  assert(nm_bloom_words_for(64) == 16 && nm_bloom_words_for(65) == 64);
  assert(nm_bloom_words_for(256) == 64 && nm_bloom_words_for(257) == 128);
  assert(nm_bloom_words_for(1024) == 128 && nm_bloom_words_for(1025) == 256);
}
static void check_child_ordering(void) {
  collide = false;
  struct nomount_child_array* children = NULL;
  struct nomount_leaf* leaves[59];
  char name[64];
  for (unsigned int i = 0; i < 59; i++) {
    snprintf(name, sizeof(name), "/system/entry_%u", (i * 37) % 59);
    leaves[i] = alloc_leaf(name); assert(!nm_insert_child(&children, leaves[i]));
  }
  for (u32 i = 1; i < children->count; i++) assert(nm_entries(children)[i-1].hash <= nm_entries(children)[i].hash);
  for (unsigned int i = 0; i < 59; i++) {
    const char* name = leaves[i]->paths + leaves[i]->v_len - leaves[i]->child_len;
    assert(nm_find_child(children, name, leaves[i]->child_len) == leaves[i]);
  }
  for (unsigned int i = 0; i < 59; i += 2) assert(!nm_remove_child(&children, leaves[i]));
  for (unsigned int i = 0; i < 59; i++) {
    const char* name = leaves[i]->paths + leaves[i]->v_len - leaves[i]->child_len;
    assert(nm_find_child(children, name, leaves[i]->child_len) == ((i & 1) ? leaves[i] : NULL));
  }
  for (unsigned int i = 1; i < 59; i += 2) assert(!nm_remove_child(&children, leaves[i]));
  assert(!children); flush_callbacks();
  for (unsigned int i = 0; i < 59; i++) release_leaf(leaves[i]);
}
static void check_uids(void) {
  assert(!nomount_is_uid_blocked(1000) && nm_uid_del(1000) == -ENOENT);
  assert(!nm_uid_add(1000) && !nm_uid_add(1001) && nm_uid_add(1000) == -EEXIST);
  assert(nomount_is_uid_blocked(1000) && !nomount_is_uid_blocked(2000));
  struct nm_uid_array* previous = nomount_uids; fail_next = 1;
  assert(nm_uid_add(1002) == -ENOMEM && nomount_uids == previous);
  fail_next = 1; assert(nm_uid_del(1000) == -ENOMEM && nomount_uids == previous);
  struct nm_payload payload = {.arg1 = 1}; u32 uid;
  nm_uid_list(&payload); memcpy(&uid, payload.buffer, 4);
  assert(uid == 1001 && payload.arg1 == 2 && payload.data_size == 4);
  payload.arg1 = 123456; nm_uid_list(&payload); assert(!payload.data_size && payload.arg1 == 123456);
  assert(!nm_uid_del(1001) && previous->count == 2 && previous->uids[1] == 1001);
  assert(!nm_uid_del(1000) && !nomount_uids);
  nm_block_isolated_uids = true;
  assert(nomount_is_uid_blocked(90000) && nomount_is_uid_blocked(199999));
  assert(!nomount_is_uid_blocked(89999) && !nomount_is_uid_blocked(200000));
  nm_block_isolated_uids = false;
  // UID 分页不能越过 4068 字节协议缓冲区。
  for (u32 i = 0; i < 1020; i++) { assert(!nm_uid_add(i)); flush_callbacks(); }
  payload.arg1 = 0; nm_uid_list(&payload); assert(payload.data_size == 4068 && payload.arg1 == 1017);
  nm_uid_list(&payload); assert(payload.data_size == 12 && payload.arg1 == 1020);
  memcpy(&uid, payload.buffer + 8, 4); assert(uid == 1019);
  nm_uid_clear(); assert(!nomount_uids); flush_callbacks();
}
int main(void) {
  const char* deps[] = {"kern_path", "path_put", "full_name_hash"};
  for (unsigned int i = 0; i < 3; i++) { missing = deps[i]; assert(nm_prepare_rule_functions() == -ENOENT); }
  missing = NULL; assert(!nm_prepare_rule_functions());
  file_dentry.d_inode = (struct inode*)&file_inode; dir_dentry.d_inode = (struct inode*)&dir_inode;
  assert(PTR_ERR(nm_alloc_rule("/data/negative", 14, 0, 0)) == -ENOENT && !path_refs);
  path_error = -EACCES; assert(PTR_ERR(nm_alloc_rule("/data/file", 10, 0, 0)) == -EACCES);
  path_error = 0; fail_next = 1; assert(PTR_ERR(nm_alloc_rule("/data/file", 10, 0, 0)) == -ENOMEM);
  check_rule_paths(); path_error = 0;
  check_rules(); check_children(); check_child_ordering(); check_uids(); flush_callbacks();
  assert(!path_refs && allocated == released && !depth);
  puts("rule arrays, native path ownership, UID policy: PASS"); return 0;
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    test = args.output / 'rules.c'
    test.write_text(source)
    binary = args.output / 'rules'
    command = ['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
               '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(test), '-o', str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    executed = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output / 'run.log').write_text(executed.stdout + executed.stderr)
    executed.check_returncode()
    receipt = {
        'level': 'Developer host contracts; no kernel concurrency or device conclusion',
        'inputs': {str(name): sha(root / name) for name in files},
        'tool_sha256': sha(Path(__file__)), 'symbols_sha256': sha(args.symbols),
        'native_dependencies': list(dependencies),
        'generated_source_sha256': sha(test), 'binary_sha256': sha(binary),
        'compiler_command': [part.replace(str(args.output), '<output>').replace(str(root), '<repo>') for part in command],
        'result': executed.stdout.strip(),
    }
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(executed.stdout.strip())
    print(f'receipt SHA-256 {sha(args.output / "receipt.json")}')


if __name__ == '__main__':
    main()
