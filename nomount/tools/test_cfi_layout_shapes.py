#!/usr/bin/env python3
"""执行 NoMount 生产探测器，验证 CFI、载荷边界及缓存回调的新指令形态。"""
import argparse
from pathlib import Path
import subprocess

from test_directory_abis import function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    offsets = (root / 'nomount/nm_offsets.c').read_text()
    utils = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    c = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
static uintptr_t cfi_address;
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  assert(!strcmp(name, "__cfi_slowpath")); return cfi_address;
}
'''
    c += utils + (root / 'nomount/nm_structs.h').read_text()
    for name in ('nm_load', 'nm_store', 'nm_rule_entry_save', 'nm_move', 'nm_move32', 'nm_load_at', 'nm_zero64', 'nm_cfi_gate',
                 'nm_add_at', 'nm_store_at', 'nm_load_unscaled', 'nm_pair_store_at', 'nm_max_signed64',
                 'nm_find_key_callback_slot_legacy', 'nm_find_key_callback_slot', 'nm_compare',
                 'nm_find_key_preparse_data_legacy', 'nm_find_key_preparse_data', 'nm_forward_null',
                 'nm_sub_from', 'nm_find_super_cache'):
        c += function(offsets, name) + '\n'
    c += r'''
int main(void) {
  long page = sysconf(_SC_PAGESIZE);
  void* pages = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED && !mprotect((char*)pages + page, page, PROT_NONE));
  // 来自 cip135-st19 目标的三个入口；只执行探测器，不执行 ARM64 指令。
  const u32 gate[] = {0x9000be69, 0x91179129, 0xcb080129, 0x93c90929, 0xf100653f, 0x54000682};
  u32* edge = (void*)((char*)pages + page - sizeof(gate));
  memcpy(edge, gate, sizeof(gate)); assert(nm_cfi_gate(edge, 8, 9, 12));
  edge[2] = 0xcb090109; assert(nm_cfi_gate(edge, 8, 9, 12));
  for (unsigned direction = 0; direction < 2; direction++) {
    u32 words[6]; memcpy(words, gate, sizeof(words));
    words[2] = direction ? 0xcb080129 : 0xcb090109;
    for (unsigned i = 0; i < 6; i++) {
      memcpy(edge, words, sizeof(words)); edge[i] = 0xd503201f;
      assert(!nm_cfi_gate(edge, 8, 9, 12));
    }
  }
  const u32 invalid_sub[] = {0xcb090129, 0xcb080109, 0x4b080129, 0xcb080529, 0xcb08012a};
  for (unsigned i = 0; i < sizeof(invalid_sub) / sizeof(*invalid_sub); i++) {
    memcpy(edge, gate, sizeof(gate)); edge[2] = invalid_sub[i];
    assert(!nm_cfi_gate(edge, 8, 9, 12));
  }
  const u32 prep[] = {0xf800865e, 0xa9be7bfd, 0xa9014ff4, 0x910003fd, 0xf9401813,
                      0xd1402268, 0xb140211f, 0x54000249, 0xf9401408, 0xb4000208};
  edge = (void*)((char*)pages + page - sizeof(prep));
  memcpy(edge, prep, sizeof(prep)); assert(nm_find_key_preparse_data(edge) == 40);
  for (unsigned i = 0; i < 10; i++) {
    memcpy(edge, prep, sizeof(prep)); edge[i] = 0xd503201f;
    assert(nm_find_key_preparse_data(edge) < 0);
  }
  const u32 invalid_cmn[] = {0x3140211f, 0xf140211f, 0xb100211f, 0xb140213f, 0xb140211e};
  for (unsigned i = 0; i < sizeof(invalid_cmn) / sizeof(*invalid_cmn); i++) {
    memcpy(edge, prep, sizeof(prep)); edge[6] = invalid_cmn[i];
    assert(nm_find_key_preparse_data(edge) < 0);
  }
  memcpy(edge, prep, sizeof(prep)); edge[4] ^= 1U << 10;
  assert(nm_find_key_preparse_data(edge) == -EINVAL);
  memcpy(edge, prep, sizeof(prep)); edge[9] ^= 1U << 5;
  assert(nm_find_key_preparse_data(edge) < 0);
  memcpy(edge, prep, sizeof(prep)); edge[7] ^= 1;
  assert(nm_find_key_preparse_data(edge) < 0);
  const u32 key[] = {0xf800865e, 0xd10283ff, 0xa9077bfd, 0xa90857f6, 0xa9094ff4,
                     0x9101c3fd, 0xb0013d48, 0xaa0003f3, 0x92f0000a, 0xf942e908,
                     0xaa0403f4, 0xaa0003f5, 0xaa0303f6, 0xf81f83a8, 0xf8490e68,
                     0xa901ffff, 0xa902ffff, 0xa903ffff, 0xa9048be1, 0xf9400509,
                     0xa905abe9, 0xf9400d08};
  edge = (void*)((char*)pages + page - sizeof(key));
  memcpy(edge, key, sizeof(key)); assert(nm_find_key_callback_slot(edge) == 24);
  for (unsigned i = 0; i < 22; i++) {
    memcpy(edge, key, sizeof(key)); edge[i] = 0xd503201f;
    assert(nm_find_key_callback_slot(edge) < 0);
  }
  const unsigned key_index[] = {10, 11, 12, 15, 16, 17, 18, 19, 20, 21};
  const u32 key_mutation[] = {0xaa0303f4, 0xaa0103f5, 0xaa0403f6, 0xa902ffff, 0xa903ffff,
                             0xa901ffff, 0xa9048be2, 0xf9400909, 0xa905afe9, 0xf9400d28};
  for (unsigned i = 0; i < sizeof(key_index) / sizeof(*key_index); i++) {
    memcpy(edge, key, sizeof(key)); edge[key_index[i]] = key_mutation[i];
    assert(nm_find_key_callback_slot(edge) < 0);
  }
  // 按目标 SUB/CMN 的 N/Z/C/V 语义检查上下界，不把溢出比较当作有符号比较。
  const u64 lengths[] = {0, 1, 32767, 32768, 32769, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(lengths) / sizeof(*lengths); i++) {
    u64 value = lengths[i] - 32768, result = value + 32768;
    bool carry = result < value, branch_ls = !carry || result == 0;
    assert(!branch_ls == (lengths[i] > 0 && lengths[i] < 32768));
  }
  const u32 cache[] = {0xd1113408, 0x39400108, 0x37280068, 0xaa1f03e0, 0xd65f03c0,
                       0xf800865e, 0xa9bd7bfd, 0xf9000bf5, 0xa9024ff4, 0x910003fd,
                       0xd50339bf, 0xd111c008, 0xaa0003f3, 0xf9400108, 0xaa0103f4,
                       0xb40001c8, 0xf9407515, 0xb40001b5, 0xd2976a00, 0xaa1503e1,
                       0xf2bd5460, 0xf2db2120, 0xf2fd5fc0, 0x97fd105d, 0xd1128260,
                       0xaa1403e1, 0xd63f02a0};
  edge = (void*)((char*)pages + page - sizeof(cache));
  memcpy(edge, cache, sizeof(cache)); cfi_address = (uintptr_t)&edge[23] + inst_get_bl_label(edge[23]);
  assert(nm_find_super_cache(edge) == 232);
  for (unsigned i = 0; i < 27; i++) {
    memcpy(edge, cache, sizeof(cache)); edge[i] = 0xd503201f;
    assert(nm_find_super_cache(edge) < 0);
  }
  memcpy(edge, cache, sizeof(cache)); cfi_address += 4; assert(nm_find_super_cache(edge) < 0);
  cfi_address = 0; assert(nm_find_super_cache(edge) < 0);
  cfi_address = (uintptr_t)&edge[23] + inst_get_bl_label(edge[23]);
  const unsigned index[] = {20, 21, 22, 24, 25, 26};
  const u32 mutation[] = {0x72bd5460, 0xf2bb2120, 0xf2fd5fc1, 0xd1128660, 0xaa1303e1, 0xd63f0280};
  for (unsigned i = 0; i < sizeof(index) / sizeof(*index); i++) {
    memcpy(edge, cache, sizeof(cache)); edge[index[i]] = mutation[i];
    assert(nm_find_super_cache(edge) < 0);
  }
  assert(inst_is_adds_imm(0xb140211f) && inst_get_adds_imm_sf(0xb140211f) == 1);
  assert(inst_get_adds_imm_rd(0xb140211f) == 31 && inst_get_adds_imm_rn(0xb140211f) == 8);
  assert(inst_get_adds_imm_imm(0xb140211f) == 32768);
  assert(!inst_is_adds_imm(0xf140211f) && !inst_is_adds_imm(0xb1c0211f));
  assert(inst_get_adds_imm_imm(0xf140211f) == -1);
  assert(!munmap(pages, page * 2));
  puts("PASS: CFI directions, 10/22/27-word target shapes, rejection mutations and guarded ends");
  return 0;
}
'''
    source = args.output / 'shapes.c'
    source.write_text(c)
    binary = args.output / 'shapes'
    result = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function',
                             '-fsanitize=address,undefined', '-g', str(source), '-o', str(binary)],
                            capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    print(result.stdout.strip())


if __name__ == '__main__':
    main()
