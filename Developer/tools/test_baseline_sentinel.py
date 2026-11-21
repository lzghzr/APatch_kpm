#!/usr/bin/env python3
"""Developer: actual ReKernel template tables reject initialization before any hook."""
import argparse
from pathlib import Path
import re
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
root = Path(__file__).resolve().parents[2]
for module in ('re_kernel', 're_kernel_x'):
    offsets = (root / module / 're_offsets.c').read_text()
    declaration = re.search(r'struct struct_offset \{.*?\};', offsets, re.S)[0]
    tables = re.findall(r'volatile struct struct_offset struct_offset.*?= \{.*?\};', offsets, re.S)
    table = tables[-1]
    table = table.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source = (root / module / 're_kernel.c').read_text()
    start = source.index('static long inline_hook_init(')
    start = source.index('{', start) + 1
    end = source.index('  kfunc_lookup_name(__alloc_skb);', start)
    guard = source[start:end]
    fixture = '#include <assert.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <errno.h>\n' + '''
#define CONFIG_KPM_BASELINES
static int binder_transaction_buffer_release_ver4 __attribute__((unused)), binder_transaction_buffer_release_ver5 __attribute__((unused)), binder_transaction_buffer_release_ver6 __attribute__((unused));
#define logkm(...) ((void)0)
#define lookup_name(f) ((void)0)
''' + declaration + '\n' + table + '\nstatic long init_guard(void) {\n' + guard + 'return 0;\n}\n' + '''
int main(void) {
  assert(struct_offset.cred_uid == -1 && struct_offset.binder_release_abi == 6);
  assert(init_guard() == -EINVAL);
  struct_offset.cred_uid = 4;
  for (int abi = 3; abi <= 6; abi++) {
    struct_offset.binder_release_abi = abi; assert(init_guard() == 0);
  }
  struct_offset.binder_release_abi = 2; assert(init_guard() == -EINVAL);
  puts("unconfigured template rejection; configured ABI checks: PASS");
}
'''
    p = a.output / (module + '.c'); p.write_text(fixture)
    b = a.output / module
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-fsanitize=address,undefined', str(p), '-o', str(b)], check=True)
    subprocess.run([str(b)], check=True)
