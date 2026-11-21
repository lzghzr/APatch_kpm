#!/usr/bin/env python3
"""Developer: exercise the production tty_audit_fork scan at its first element."""
import argparse
from pathlib import Path
import re
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
root = Path(__file__).resolve().parents[2]
src = (root / 'cgroupv2_freeze/cfv2_offsets.c').read_text()
start = src.index('  uint32_t *tty_audit_fork_src')
end = src.index('  // 获取 signal_struct->flags', start)
body = src[start:end]
inst = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
inst = re.sub(r'^#include .*\n', '', inst, flags=re.M)
fixture = '''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint32_t u32;
struct { int task_struct_signal; } struct_offset;
static uint32_t words[32];
static void* tty_audit_fork = words;
''' + inst + '\nstatic long scan(void) {\n' + body + '  return 0;\n}\n' + '''
int main(void) {
  for (int i = 0; i < 32; i++) words[i] = 0xd503201f;
  words[0] = 0xf943f408;
  struct_offset.task_struct_signal = 0;
  assert(scan() != 0);
  words[0] = 0xd5384100; words[1] = 0xf943f408;
  assert(scan() == 0 && struct_offset.task_struct_signal == 0x7e8);
  words[0] ^= 1; struct_offset.task_struct_signal = 0;
  assert(scan() != 0);
  words[0] = 0xd65f03c0;
  assert(scan() != 0);
  puts("tty first-element and current-base guard: PASS");
}
'''
p = a.output / 'test.c'
p.write_text(fixture)
b = a.output / 'test'
subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                '-fsanitize=address,undefined', str(p), '-o', str(b)], check=True)
subprocess.run([str(b)], check=True)
