#!/usr/bin/env python3
"""执行生产文件回调的宿主契约自检，不证明内核页缓存、VMA 引用或实机行为。"""

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
    parser.add_argument('--ops-reference', type=Path, required=True)
    parser.add_argument('--entry-reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    values = json.loads(args.reference.read_text())['values']
    ops = json.loads(args.ops_reference.read_text())['type_sizes_and_offsets']
    entry_fields = json.loads(args.entry_reference.read_text())['derived_fields']
    symbols = {name: kind for _, kind, name in json.loads(args.symbols.read_text())}
    deps = ('dentry_open', 'fput', 'vfs_llseek', 'generic_file_readonly_mmap')
    assert all(symbols.get(name) in ('t', 'T') for name in deps)
    files = ('nomount/nm_structs.h', 'nomount/nm_rules.h', 'nomount/nm_offsets.c',
             'nomount/nm_operations.c', 'nomount/nm_file.c')
    source = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define CONFIG_KPM_BASELINES 1
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
struct rcu_head { struct rcu_head* next; void (*func)(struct rcu_head*); };
static void* host_alloc(unsigned long);
static void host_free(const void*);
static void* (*kf_nm_vzalloc)(unsigned long) = host_alloc;
static void (*kf_nm_vfree)(const void*) = host_free;
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
'''
    source += (root / files[0]).read_text() + (root / files[1]).read_text()
    source += (root / files[2]).read_text().split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
    source = source.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source += (root / files[3]).read_text() + (root / files[4]).read_text()
    mapping = {'file_private': 'file.private_data', 'file_position': 'file.f_pos', 'file_flags': 'file.f_flags',
               'file_cred': 'file.f_cred', 'fop_open': 'file_operations.open', 'fop_release': 'file_operations.release',
               'fop_mmap': 'file_operations.mmap', 'fop_splice_read': 'file_operations.splice_read'}
    source += '\nstatic void set_target(void) {\n' + '\n'.join(
        f'struct_offset.{key} = {values[name]};' for key, name in mapping.items())
    source += f'\nstruct_offset.file_mapping = {values["file.f_mapping"]};\n'
    source += f'struct_offset.file_ops_size = {ops["file_operations"]["size"]};\n'
    source += 'struct_offset.file_inode_ops = 32;\n'
    source += '\n'.join(f'struct_offset.{name} = {value};' for name, value in entry_fields.items()) + '\n}\n'
    source += r'''
static _Alignas(8) unsigned char outer_storage[512], backing_storage[512], inode_storage[768], ops_storage[512];
static struct file* outer = (void*)outer_storage;
static struct file* backing = (void*)backing_storage;
static struct inode* inode = (void*)inode_storage;
static int failures, allocations, frees, opens, put_calls, reads, seeks, maps, splices;
static int open_error, io_result = 7, mmap_error, shared_write;
static const char* missing;
static void* host_alloc(unsigned long size) { if (failures) { failures = 0; return NULL; } allocations++; return calloc(1,size); }
static void host_free(const void* pointer) { frees++; free((void*)pointer); }
static struct file* host_open(const struct nm_path* path, int flags, const struct cred* cred) {
  assert(path->dentry == (void*)1 && path->mnt == (void*)2);
  assert(flags == 01000000 && cred == (void*)123); opens++;
  return open_error ? ERR_PTR(open_error) : backing;
}
static void host_put(struct file* file) { assert(file == backing && !nm_file_private(outer)); put_calls++; }
static int64_t host_seek(struct file* file, int64_t offset, int whence) {
  assert(file == backing && whence == 1); seeks++;
  if (offset == -999) return -EINVAL;
  *nm_file_position(file) += offset; return *nm_file_position(file);
}
static int host_mmap(struct file* file, struct vm_area_struct* area) {
  assert(file == outer && area == (void*)1234); maps++;
  return shared_write ? -EINVAL : mmap_error;
}
static long host_read(struct kiocb* request, struct iov_iter* iter) {
  struct nm_kiocb_head* head = (void*)request;
  assert(head->ki_filp == backing && !head->ki_complete && iter == (void*)321); reads++;
  head->ki_pos += 7; return io_result;
}
static long host_splice_read(struct file* file, int64_t* position, struct pipe_inode_info* pipe,
                             unsigned long length, unsigned int flags) {
  assert(file == backing && *position == 3 && pipe == (void*)45 && length == 100 && flags == 1); splices++; return 23;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (missing && !strcmp(missing,name)) return 0;
  if (!strcmp(name,"dentry_open")) return (uintptr_t)host_open;
  if (!strcmp(name,"fput")) return (uintptr_t)host_put;
  if (!strcmp(name,"vfs_llseek")) return (uintptr_t)host_seek;
  if (!strcmp(name,"generic_file_readonly_mmap")) return (uintptr_t)host_mmap;
  return 0;
}
int main(void) {
  set_target();
  const char* deps[] = {"dentry_open","fput","vfs_llseek","generic_file_readonly_mmap"};
  for (unsigned int i = 0; i < 4; i++) { missing = deps[i]; assert(nm_prepare_file_functions() == -ENOENT); }
  missing = NULL; assert(!nm_prepare_file_functions());
  struct nomount_rule rule = {.r_path = {(void*)2,(void*)1}};
  struct nm_inode_info info = {.rule = &rule}; void* pointer = &info;
  memcpy(inode_storage + struct_offset.inode_private, &pointer, 8);
  pointer = (void*)123; memcpy(outer_storage + struct_offset.file_cred, &pointer, 8);
  u32 flags = 01000000|0100|0200|0400; memcpy(outer_storage + struct_offset.file_flags,&flags,4);
  memcpy(outer_storage + struct_offset.file_inode_ops,&inode,8);
  pointer = ops_storage; memcpy(backing_storage + struct_offset.file_inode_ops + 8,&pointer,8);
  for (u32 forbidden = 1; forbidden <= 2; forbidden++) {
    u32 modified = flags | forbidden; memcpy(outer_storage + struct_offset.file_flags,&modified,4);
    assert(nm_open(inode,outer) == -EROFS && !opens && !nm_file_private(outer));
  }
  u32 truncation = flags | 01000; memcpy(outer_storage + struct_offset.file_flags,&truncation,4);
  assert(nm_open(inode,outer) == -EROFS && !opens);
  memcpy(outer_storage + struct_offset.file_flags,&flags,4);
  assert(!nm_open(inode,outer) && nm_file_private(outer) == backing && opens == 1);
  open_error = -EACCES; nm_set_file_private(outer,NULL);
  assert(nm_open(inode,outer) == -EACCES && !nm_file_private(outer)); open_error = 0;
  rule.flags = NM_FLAG_VIRTUAL_DIR; assert(!nm_open(inode,outer) && !nm_file_private(outer)); rule.flags = 0;
  pointer = NULL; memcpy(inode_storage + struct_offset.inode_private,&pointer,8);
  assert(nm_open(inode,outer) == -ENODEV); pointer = &info; memcpy(inode_storage + struct_offset.inode_private,&pointer,8);
  nm_set_file_private(outer,backing);
  *nm_file_position(outer) = 8; assert(nm_llseek(outer,3,1) == 11 && *nm_file_position(outer) == 11);
  assert(nm_llseek(outer,-999,1) == -EINVAL && *nm_file_position(outer) == 11);
  struct nm_file_io_ops* io = (void*)ops_storage; io->read_iter = host_read;
  struct nm_kiocb_head request = {.ki_filp = outer, .ki_pos = 10};
  assert(nm_read_iter((void*)&request,(void*)321) == 7 && request.ki_filp == outer && request.ki_pos == 17);
  io_result = -EIO; assert(nm_read_iter((void*)&request,(void*)321) == -EIO && request.ki_filp == outer);
  int before = reads; request.ki_complete = (void*)1;
  assert(nm_read_iter((void*)&request,(void*)321) == -EOPNOTSUPP);
  assert(reads == before && request.ki_filp == outer);
  request.ki_complete = NULL; io->read_iter = NULL;
  assert(nm_read_iter((void*)&request,(void*)321) == -EINVAL && request.ki_filp == outer);
  pointer = (void*)6789; memcpy(outer_storage + struct_offset.file_mapping,&pointer,8);
  memcpy(backing_storage + struct_offset.file_mapping,&pointer,8);
  struct nm_inode_owner_prefix* owner = (void*)inode_storage; owner->i_flags = 512|16;
  assert(!nm_mmap(outer,(void*)1234) && owner->i_flags == 16);
  owner->i_flags = 512|16; shared_write = 1;
  assert(nm_mmap(outer,(void*)1234) == -EINVAL && owner->i_flags == (512|16)); shared_write = 0;
  mmap_error = -ENOEXEC; assert(nm_mmap(outer,(void*)1234) == -ENOEXEC && owner->i_flags == (512|16)); mmap_error = 0;
  pointer = NULL; memcpy(backing_storage + struct_offset.file_mapping,&pointer,8); before = maps;
  assert(nm_mmap(outer,(void*)1234) == -EINVAL && maps == before);
  nm_set_fop(ops_storage,struct_offset.fop_splice_read,host_splice_read); int64_t position = 3;
  assert(nm_splice_read(outer,&position,(void*)45,100,1) == 23);
  void* table = nm_new_file_operations(); assert(!IS_ERR(table));
  assert(!((struct nm_file_io_ops*)table)->owner && ((struct nm_file_io_ops*)table)->read_iter == nm_read_iter);
  assert(*(void**)((char*)table + struct_offset.fop_open) == nm_open);
  assert(!((struct nm_file_io_ops*)table)->write_iter);
  nm_discard_operations(table); failures = 1; assert(PTR_ERR(nm_new_file_operations()) == -ENOMEM);
  int16_t slot = struct_offset.fop_release; struct_offset.fop_release = struct_offset.fop_open;
  assert(PTR_ERR(nm_new_file_operations()) == -EINVAL); struct_offset.fop_release = slot;
  int16_t data = struct_offset.file_private; struct_offset.file_private = struct_offset.file_cred;
  assert(PTR_ERR(nm_new_file_operations()) == -EINVAL); struct_offset.file_private = data;
  assert(!nm_release(inode,outer) && !nm_file_private(outer) && put_calls == 1);
  assert(!nm_release(inode,outer) && put_calls == 1);
  assert(nm_llseek(outer,3,1) == -EINVAL);
  assert(allocations == frees && splices == 1);
  printf("file callbacks, synchronous I/O, mapping contract, operations builder: PASS\n"); return 0;
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    c_file = args.output / 'file.c'; c_file.write_text(source)
    binary = args.output / 'file'
    compiled = subprocess.run(['/usr/bin/clang', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                               '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c_file),
                               '-o', str(binary)], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr); compiled.check_returncode()
    run = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr); run.check_returncode()
    receipt = {'scope': 'Developer host file callback contracts; no native VMA/concurrency/device conclusion',
               'sources': {name: sha(root / name) for name in files}, 'tool_sha256': sha(Path(__file__)),
               'reference_sha256': sha(args.reference), 'ops_reference_sha256': sha(args.ops_reference),
               'entry_reference_sha256': sha(args.entry_reference),
               'symbols_sha256': sha(args.symbols), 'source_sha256': sha(c_file), 'binary_sha256': sha(binary),
               'native_dependencies': list(deps), 'result': run.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
