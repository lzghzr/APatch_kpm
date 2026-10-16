#!/usr/bin/env python3
"""Developer：核对新表容量、原表读取范围及BTF降级边界；不调用原生注册接口。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    offsets = (root / 'nomount/nm_offsets.c').read_text()
    prefix = offsets.split('static struct inode* nm_file_inode', 1)[0]
    prefix = prefix.replace('__attribute__((section(".data.re_offsets"), used))', '')
    c = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define nm_log_info(...) ((void)0)
static int btf_error = -ENODATA;
static bool btf_unavailable = true, allocation_error;
static unsigned int allocations, releases;
static size_t requested;
static int calculate_btf_operation_sizes(bool* unavailable) {
  *unavailable = btf_unavailable;
  return btf_error;
}
static void* nm_zalloc(unsigned long size) {
  requested = size;
  if (allocation_error) return NULL;
  void* result = calloc(1, size); assert(result); allocations++; return result;
}
static void nm_free(void* ptr) { releases++; free(ptr); }
'''
    c += (root / 'nomount/nm_structs.h').read_text() + prefix
    c += (root / 'nomount/nm_operations.c').read_text()
    c += r'''
static void complete_copy_sizes(void) {
  struct_offset.file_ops_size = 216;
  struct_offset.inode_ops_size = 256;
  struct_offset.super_ops_size = 232;
  struct_offset.dentry_ops_size = 128;
  struct_offset.key_type_size = -1;
}
int main(void) {
  assert(NM_OWNED_OPERATIONS_CAPACITY == 512);
  assert(nm_owned_operation_size(NM_KEY_TYPE) == -1);
  assert(nm_prepare_operation_sizes() == -ENOENT && nm_owned_operation_fallback);
  // 缺复制尺寸时完整准备仍失败；只允许独立创建零表。
  for (int kind = NM_INODE_OPS; kind <= NM_KEY_TYPE; kind++) {
    unsigned int before = allocations;
    void* table = nm_new_operations(kind, NULL);
    if (kind == NM_SUPER_OPS) {
      assert(PTR_ERR(table) == -EINVAL && allocations == before);
      continue;
    }
    assert(!IS_ERR_OR_NULL(table) && requested == 512);
    for (unsigned int i = 0; i < 512; i++) assert(((unsigned char*)table)[i] == 0);
    assert(nm_operation_size(kind) == -1);
    nm_discard_operations(table);
  }
  assert(nm_operation_size(NM_KEY_TYPE) == -1);
  complete_copy_sizes();
  assert(!nm_prepare_operation_sizes());
  assert(nm_owned_operation_size(NM_KEY_TYPE) == 512 && struct_offset.key_type_size == -1);
  volatile int16_t* sizes[] = {&struct_offset.file_ops_size, &struct_offset.inode_ops_size,
                              &struct_offset.super_ops_size, &struct_offset.dentry_ops_size};
  for (unsigned int i = 0; i < 4; i++) {
    int saved = *sizes[i]; *sizes[i] = -1;
    assert(nm_prepare_operation_sizes() == -ENOENT);
    *sizes[i] = saved;
  }
  // 真实不可访问页：未知尺寸不得读取；已知尺寸复制恰好止于原表尾部。
  long page = sysconf(_SC_PAGESIZE); assert(page > 512);
  void* pages = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED && !mprotect((char*)pages + page, page, PROT_NONE));
  struct_offset.key_type_size = -1;
  unsigned int before = allocations;
  assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, (char*)pages + page)) == -EINVAL);
  assert(allocations == before);
  unsigned char* original = (void*)((char*)pages + page - 128);
  memset(original, 0xa5, 128); struct_offset.key_type_size = 128;
  void* clone = nm_new_operations(NM_KEY_TYPE, original);
  assert(!IS_ERR_OR_NULL(clone) && requested == 128 && !memcmp(clone, original, 128));
  nm_discard_operations(clone);
  clone = nm_new_operations(NM_KEY_TYPE, NULL);
  assert(!IS_ERR_OR_NULL(clone) && requested == 128); nm_discard_operations(clone);
  assert(!munmap(pages, 2 * page));
  struct_offset.key_type_size = -1;
  struct_offset.mutex_size = 32; struct_offset.mutex_no_lockdep = 1;
  struct_offset.key_callbacks = 24; struct_offset.key_preparse_data = 40;
  assert(!nm_validate_control_layout());
  struct_offset.key_callbacks = 512 - sizeof(struct nm_key_callbacks);
  assert(!nm_validate_control_layout());
  struct_offset.key_callbacks += 8; assert(nm_validate_control_layout() == -EINVAL);
  struct_offset.key_callbacks = 24; struct_offset.mutex_no_lockdep = 0;
  assert(nm_validate_control_layout() == -EOPNOTSUPP); struct_offset.mutex_no_lockdep = 1;
  // 有效BTF错误及未确认来源的ENODATA均不得启用容量降级。
  const int errors[] = {-ENOENT, -EINVAL, -ENODATA};
  for (unsigned int i = 0; i < 3; i++) {
    btf_error = errors[i]; btf_unavailable = false;
    assert(nm_prepare_operation_sizes() == errors[i] && !nm_owned_operation_fallback);
    assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, NULL)) == -EINVAL);
  }
  btf_error = 0; assert(nm_prepare_operation_sizes() == -ENOENT && !nm_owned_operation_fallback);
  struct_offset.key_type_size = 136; assert(!nm_prepare_operation_sizes());
  assert(nm_owned_operation_size(NM_KEY_TYPE) == 136);
  btf_error = -ENODATA; btf_unavailable = true; struct_offset.key_type_size = -1;
  assert(!nm_prepare_operation_sizes());
  struct_offset.key_type_size = 0;
  assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, NULL)) == -EINVAL);
  struct_offset.key_type_size = -2;
  assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, NULL)) == -EINVAL);
  struct_offset.key_type_size = 4104;
  assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, NULL)) == -EINVAL);
  struct_offset.key_type_size = -1; allocation_error = true;
  assert(PTR_ERR(nm_new_operations(NM_KEY_TYPE, NULL)) == -ENOMEM);
  assert(PTR_ERR(nm_new_operations((enum nm_ops_kind)-1, NULL)) == -EINVAL);
  assert(allocations == releases);
  puts("PASS: owned capacity, exact-copy guard page, BTF source policy and control bounds");
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = args.output / 'capacity.c'
    fixture.write_text(c)
    binary = args.output / 'capacity'
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer', '-g', str(fixture), '-o', str(binary)]
    result = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    names = ['nomount/nm_structs.h', 'nomount/nm_offsets.c', 'nomount/nm_operations.c',
             'nomount/nm_btf.c', 'nomount/tools/test_operation_capacity.py']
    receipt = {'scope': 'Developer host capacity/copy contract checks; BTF routing stub, no native registration or full init',
               'sources': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names},
               'result': result.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(result.stdout.strip())


if __name__ == '__main__':
    main()
