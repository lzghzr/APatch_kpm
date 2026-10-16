#!/usr/bin/env python3
"""对原生接口封装执行宿主契约自检；不模拟或证明内核并发。"""

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
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    entries = {name: {'offset': offset, 'kind': kind}
               for offset, kind, name in json.loads(args.symbols.read_text())}
    dependencies = ('__rcu_read_lock', '__rcu_read_unlock', 'synchronize_rcu', 'call_rcu',
                    'kfree', 'capable', 'memdup_user', 'vfs_setpos', 'iterate_dir', 'seq_buf_to_user', 'vzalloc', 'vfree')
    assert all(name in entries and entries[name]['kind'] in ('T', 't') for name in dependencies)
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
#define __user
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define CONFIG_KPM_BASELINES 1
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define pr_err(...) ((void)0)
struct rcu_head { struct rcu_head* next; void (*func)(struct rcu_head*); };
typedef void (*rcu_callback_t)(struct rcu_head*);
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
static int compat_copy_to_user(void*, const void*, int);
struct fake_file { void* inode; int64_t pos; };
static struct inode* nm_file_inode(const void* file) { return ((const struct fake_file*)file)->inode; }
'''
    source = prelude + (root / 'nomount/nm_structs.h').read_text()
    offsets = (root / 'nomount/nm_offsets.c').read_text().split('static struct inode* nm_file_inode', 1)[0]
    source += offsets.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source += (root / 'nomount/nm_protocol.h').read_text() + (root / 'nomount/nm_native.c').read_text()
    source += (root / 'nomount/nm_operations.c').read_text()
    reference = json.loads(args.reference.read_text())
    types = reference['type_sizes_and_offsets']
    sizes = {name: types[kind]['size'] for name, kind in (
        ('file_ops_size', 'file_operations'), ('inode_ops_size', 'inode_operations'),
        ('super_ops_size', 'super_operations'), ('dentry_ops_size', 'dentry_operations'), ('key_type_size', 'key_type'))}
    source += '\nstatic void target_sizes(void) {\n' + '\n'.join(
        f'struct_offset.{name} = {value};' for name, value in sizes.items()) + '\n}\n'
    source += r'''
static const char* missing;
static int authorized = 1, read_depth, sync_calls, free_calls, copy_calls, execute_calls, setpos_calls, iterate_calls;
static int dup_error, short_copy, setpos_error, native_error, original_calls;
static int alloc_error, ops_allocations, ops_frees;
static uintptr_t observed_address;
static struct nm_payload user;
static rcu_callback_t pending_callback;
static struct rcu_head* pending_head;
static void host_read_lock(void) { read_depth++; }
static void host_read_unlock(void) { assert(read_depth > 0); read_depth--; }
static void host_sync(void) { sync_calls++; }
static void host_call_rcu(struct rcu_head* head, rcu_callback_t callback) {
  assert(!pending_head); pending_head = head; pending_callback = callback;
}
static void host_free(const void* ptr) { free_calls++; free((void*)ptr); }
static void* host_vzalloc(unsigned long size) {
  if (alloc_error) return NULL;
  void* out = NULL; assert(!posix_memalign(&out, 4096, size)); memset(out, 0, size);
  ops_allocations++; return out;
}
static void host_vfree(const void* ptr) { ops_frees++; free((void*)ptr); }
static bool host_capable(int cap) { assert(cap == 21); return authorized; }
static void* host_memdup(const void* address, size_t size) {
  observed_address = (uintptr_t)address; assert(size == sizeof(user));
  if (dup_error) return ERR_PTR(dup_error);
  void* out = malloc(size); assert(out); memcpy(out, &user, size); return out;
}
static int64_t host_setpos(void* file, int64_t pos, int64_t max) {
  assert(max == INT64_MAX); setpos_calls++;
  if (setpos_error) return setpos_error;
  ((struct fake_file*)file)->pos = pos; return pos;
}
static int host_iterate(void* file, struct nm_dir_context* ctx) {
  iterate_calls++; assert(((struct fake_file*)file)->pos == ctx->pos);
  ctx->pos += 3; ((struct fake_file*)file)->pos = ctx->pos; return native_error;
}
static int host_original(void* file, struct nm_dir_context* ctx) {
  assert(file && ctx); original_calls++; return 17;
}
static int host_execute(struct nm_payload* payload) {
  execute_calls++;
  assert(payload != &user && payload->status == 0);
  // 用户在执行期间改写原页，执行器仍只读自己的快照。
  u32 command = payload->cmd; user.cmd = 99; assert(payload->cmd == command);
  payload->data_size = 2; memcpy(payload->buffer, "OK", 2);
  return -ENOENT;
}
static int compat_copy_to_user(void* address, const void* data, int size) {
  assert((uintptr_t)address == observed_address && size == sizeof(user)); copy_calls++;
  if (short_copy) return size - 1;
  memcpy(&user, data, size); return size;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (missing && !strcmp(name, missing)) return 0;
  if (!strcmp(name, "__rcu_read_lock")) return (uintptr_t)host_read_lock;
  if (!strcmp(name, "__rcu_read_unlock")) return (uintptr_t)host_read_unlock;
  if (!strcmp(name, "synchronize_rcu")) return (uintptr_t)host_sync;
  if (!strcmp(name, "call_rcu")) return (uintptr_t)host_call_rcu;
  if (!strcmp(name, "kfree")) return (uintptr_t)host_free;
  if (!strcmp(name, "vzalloc")) return (uintptr_t)host_vzalloc;
  if (!strcmp(name, "vfree")) return (uintptr_t)host_vfree;
  if (!strcmp(name, "capable")) return (uintptr_t)host_capable;
  if (!strcmp(name, "memdup_user")) return (uintptr_t)host_memdup;
  if (!strcmp(name, "vfs_setpos")) return (uintptr_t)host_setpos;
  if (!strcmp(name, "iterate_dir")) return (uintptr_t)host_iterate;
  assert(!"unexpected native symbol"); return 0;
}
int main(void) {
  const char* names[] = {"__rcu_read_lock", "__rcu_read_unlock", "synchronize_rcu", "call_rcu", "kfree",
                        "capable", "memdup_user", "vfs_setpos", "iterate_dir", "vzalloc", "vfree"};
  for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    missing = names[i]; assert(nm_prepare_native() == -ENOENT);
  }
  missing = NULL; assert(nm_prepare_native() == 0);
  nm_rcu_read_lock(); assert(read_depth == 1); nm_rcu_read_unlock(); assert(read_depth == 0);
  nm_rcu_synchronize(); assert(sync_calls == 1);
  struct rcu_head* memory = calloc(1, sizeof(*memory)); assert(memory);
  nm_rcu_free(memory); assert(free_calls == 0 && pending_head == memory);
  pending_callback(pending_head); pending_head = NULL; assert(free_calls == 1);

  struct fake_file outer = {.inode = &user}, backing = {.inode = &memory};
  struct nm_dir_context context = {.pos = 7};
  assert(nm_iterate_backing(&outer, &backing, &context) == 0);
  assert(context.pos == 10 && backing.pos == 10 && setpos_calls == 1 && iterate_calls == 1);
  setpos_error = -EINVAL;
  assert(nm_iterate_backing(&outer, &backing, &context) == -EINVAL && iterate_calls == 1);
  setpos_error = 0; native_error = -EACCES;
  assert(nm_iterate_backing(&outer, &backing, &context) == -EACCES);
  int old_calls = setpos_calls; backing.inode = outer.inode;
  assert(nm_iterate_backing(&outer, &backing, &context) == -ELOOP && setpos_calls == old_calls);
  assert(nm_iterate_original(&outer, &context, host_original) == 17 && original_calls == 1);
  assert(setpos_calls == old_calls && nm_iterate_original(&outer, &context, NULL) == -ENOTDIR);

  uint64_t address = 0x123456789abc; user.magic = NOMOUNT_MAGIC_SIG;
  user.cmd = NM_CMD_ADD_RULE; user.status = 57;
  assert(nm_exchange_payload(&address, 8, host_execute) == -ECANCELED);
  assert(observed_address == address && user.status == -ENOENT && user.data_size == 2);
  assert(!memcmp(user.buffer, "OK", 2) && user.cmd == NM_CMD_ADD_RULE);
  uint32_t compat_address = 0xfedcba98;
  assert(nm_exchange_payload(&compat_address, 4, host_execute) == -ECANCELED);
  assert(observed_address == (uint64_t)compat_address);
  authorized = 0; int before = execute_calls, copies = copy_calls;
  assert(nm_exchange_payload(NULL, 8, host_execute) == -EPERM);
  assert(execute_calls == before && copy_calls == copies); authorized = 1;
  assert(nm_exchange_payload(&address, 5, host_execute) == -EINVAL);
  address = 0; assert(nm_exchange_payload(&address, 8, host_execute) == -EINVAL); address = 99;
  dup_error = -EFAULT;
  assert(nm_exchange_payload(&address, 8, host_execute) == -EFAULT && execute_calls == before);
  dup_error = 0; user.magic = 0;
  assert(nm_exchange_payload(&address, 8, host_execute) == -EFAULT && execute_calls == before);
  user.magic = NOMOUNT_MAGIC_SIG; short_copy = 1;
  assert(nm_exchange_payload(&address, 8, host_execute) == -EFAULT && execute_calls == before + 1);
  assert(nm_prepare_operation_sizes() == -ENOENT);
  target_sizes(); assert(nm_prepare_operation_sizes() == 0);
  for (int kind = NM_FILE_OPS; kind <= NM_KEY_TYPE; kind++) {
    int size = nm_operation_size(kind); unsigned char* original = malloc(size); assert(original);
    for (int i = 0; i < size; i++) original[i] = (unsigned char)(i * 7 + 5);
    unsigned char* clone = nm_new_operations(kind, original); assert(!IS_ERR_OR_NULL(clone));
    assert(!((uintptr_t)clone % 64));
    int copied_start = kind == NM_FILE_OPS ? sizeof(void*) : 0;
    assert(!memcmp(clone + copied_start, original + copied_start, size - copied_start));
    if (kind == NM_FILE_OPS) assert(((struct nm_file_ops_head*)clone)->owner == NULL);
    nm_discard_operations(clone); free(original);
    clone = nm_new_operations(kind, NULL); assert(!IS_ERR_OR_NULL(clone));
    for (int i = 0; i < size; i++) assert(clone[i] == 0);
    nm_discard_operations(clone);
  }
  int before_alloc = ops_allocations;
  struct_offset.file_ops_size = 8;
  assert(PTR_ERR(nm_new_operations(NM_FILE_OPS, NULL)) == -EINVAL && ops_allocations == before_alloc);
  struct_offset.file_ops_size = 4097; assert(nm_prepare_operation_sizes() == -EINVAL);
  target_sizes(); alloc_error = 1;
  assert(PTR_ERR(nm_new_operations(NM_FILE_OPS, NULL)) == -ENOMEM);
  assert(PTR_ERR(nm_new_operations((enum nm_ops_kind)-1, NULL)) == -EINVAL);
  nm_discard_operations(NULL); nm_discard_operations(ERR_PTR(-ENOMEM));
  assert(ops_allocations == ops_frees);
  puts("PASS: native dependency failure, RCU routing, backing/original directory paths, payload ABI/auth/copy");
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = args.output / 'native.c'
    fixture.write_text(source)
    binary = args.output / 'native'
    subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-g', str(fixture), '-o', str(binary)], check=True)
    run = subprocess.run([str(binary)], check=True, text=True, capture_output=True)
    assert not run.stderr, run.stderr
    inputs = [Path(__file__), root / 'nomount/nm_native.c', root / 'nomount/nm_structs.h', root / 'nomount/nm_protocol.h',
              root / 'nomount/nm_offsets.c', root / 'nomount/nm_operations.c']
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer host interface contract checks; no concurrency, CFI, key registration or device proof',
        'symbols_sha256': sha(args.symbols), 'target_dependencies': {n: entries[n] for n in dependencies},
        'reference_sha256': sha(args.reference), 'target_sizes': sizes,
        'sources': {str(p.relative_to(root)): sha(p) for p in inputs}, 'stdout': run.stdout,
    }, indent=2) + '\n')
    print(run.stdout, end='')


if __name__ == '__main__':
    main()
