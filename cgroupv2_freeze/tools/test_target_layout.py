#!/usr/bin/env python3
"""Developer: execute cgroup layout derivation on the selected 4.4 image and bad anchors."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--image', type=Path, required=True)
ap.add_argument('--symbols', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
r = Path(__file__).resolve().parents[2]
symbols = {n: off for off, typ, n in json.loads(a.symbols.read_text())}
data = a.image.read_bytes()
names = ['css_task_iter_start', 'cgroup_kn_lock_live', 'cgroup_init_cftypes', 'cgroup_seqfile_show',
         'cgroup_file_write', 'task_clear_jobctl_trapping', 'tty_audit_fork', 'zap_other_threads',
         'freezing_slow_path', 'schedule_timeout_interruptible', 'cgroup_subtree_control_show',
         'cgroup_clone_children_read']
declarations = []
for n in names:
    raw = data[symbols[n]:symbols[n] + 0x40 * 4]
    assert len(raw) == 0x40 * 4
    words = [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]
    declarations.append('static uint32_t words_' + n + '[] = {' + ','.join(hex(w) for w in words) + '};')
inst = (r / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
inst = re.sub(r'^#include .*\n', '', inst, flags=re.M)
offsets = (r / 'cgroupv2_freeze/cfv2_utils.h').read_text().split('struct struct_offset', 1)[1].split('#endif', 1)[0]
code = (r / 'cgroupv2_freeze/cfv2_offsets.c').read_text()
code = code[code.index('static int cftype_show_offset'):]
fixture = '''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define logkm(...) ((void)0)
#define TASK_INTERRUPTIBLE 1
#define CGRP_CPUSET_CLONE_CHILDREN 1
#define IZERO 1
#define UZERO 2
#define EINVAL 22
#define ENOENT 2
#define kfunc(n) n
struct task_struct; struct signal_struct; struct seq_file;
struct cftype { char bytes[200]; };
struct struct_offset /* OFFSETS */
struct struct_offset struct_offset;
static uint64_t css_task_iter_start_ver5=UZERO, cgroup_kn_lock_live_ver5=UZERO;
/* INST */
/* WORDS */
static void* lookup(const char* name) {
/* LOOKUP */
  return NULL;
}
#define kallsyms_lookup_name lookup
#define lookup_name(n) n=(typeof(n))lookup(#n); if(!n) return -ENOENT
static void *css_task_iter_start, *cgroup_kn_lock_live, *cgroup_init_cftypes;
/* PRODUCTION */
static void reset(void) {
  memset(&struct_offset, 0xff, sizeof(struct_offset));
  css_task_iter_start=lookup("css_task_iter_start");
  cgroup_kn_lock_live=lookup("cgroup_kn_lock_live");
  cgroup_init_cftypes=lookup("cgroup_init_cftypes");
}
int main(void) {
  reset();
  assert(calculate_offsets() == 0);
  assert(cftype_show_offset == 136 && cftype_write_offset == 184 && cftype_stride == 192);
  assert(struct_offset.task_struct_jobctl == 1440 && struct_offset.task_struct_signal == 2024);
  assert(struct_offset.signal_struct_group_exit_task == 96 && struct_offset.signal_struct_flags == 108);
  assert(struct_offset.task_struct_state == 32 && struct_offset.task_struct_flags == 52);
  assert(struct_offset.seq_file_private == 128 && struct_offset.cgroup_flags == 184);
  assert(struct_offset.subprocess_info_path == 40);
  /* BAD ANCHORS */
  puts("selected Nokia layout and wrong-base/width/callback rejection: PASS");
}
'''
bad = []
for name, index, replacement in [
    ('task_clear_jobctl_trapping', 2, 'saved ^ (1u << 5)'),
    ('tty_audit_fork', 1, 'saved ^ (1u << 5)'),
    ('zap_other_threads', 8, 'saved ^ (1u << 5)'),
    ('freezing_slow_path', 4, 'saved ^ (1u << 30)'),
    ('schedule_timeout_interruptible', 4, 'saved ^ (1u << 5)'),
    ('cgroup_subtree_control_show', 4, 'saved ^ (1u << 5)'),
    ('cgroup_clone_children_read', 1, 'saved ^ (1u << 5)'),
    ('cgroup_file_write', 13, 'saved ^ (1u << 5)'),
    ('cgroup_seqfile_show', 9, 'saved ^ (1u << 5)'),
    ('cgroup_init_cftypes', 33, '(saved & ~(0xfffu << 10)) | (0x100u << 10)'),
]:
    bad.append(f'{{ uint32_t saved=words_{name}[{index}]; words_{name}[{index}]={replacement}; '
               f'reset(); assert(calculate_offsets()!=0); words_{name}[{index}]=saved; }}')
fixture = (fixture.replace('/* OFFSETS */', offsets).replace('/* INST */', inst)
           .replace('/* WORDS */', '\n'.join(declarations))
           .replace('/* LOOKUP */', '\n'.join('  if (!strcmp(name,"'+n+'")) return words_'+n+';' for n in names))
           .replace('/* PRODUCTION */', code).replace('/* BAD ANCHORS */', '\n'.join(bad)))
p = a.output / 'test.c'; p.write_text(fixture)
b = a.output / 'test'
subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                '-fsanitize=address,undefined', str(p), '-o', str(b)], check=True)
subprocess.run([str(b)], check=True)
(a.output / 'result.json').write_text(json.dumps({'target':'B2N-416G_boot.img / 4.4.192-perf+',
    'fields':{'jobctl':1440,'signal':2024,'state':32,'task_flags':52,'signal_flags':108,'group_exit_task':96,
    'seq_private':128,'cgroup_flags':184,'helper_path':40,'cftype_show':136,'cftype_write':184,'cftype_stride':192},
    'negative_cases':len(bad), 'scope':'Developer production decoder host selfcheck; native callbacks not executed'},indent=2)+'\n')
