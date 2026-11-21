#!/usr/bin/env python3
"""Developer: production signal hook and bounded offset regression, with ASan/UBSan."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--image', type=Path)
    ap.add_argument('--symbols', type=Path)
    ap.add_argument('--expected', help='jobctl,signal,oom offsets in hex')
    args = ap.parse_args()
    if any((args.image, args.symbols, args.expected)) and not all((args.image, args.symbols, args.expected)):
        ap.error('image, symbols and expected must be supplied together')
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    src = (root / 'dont_kill_freeze/dont_kill_freeze.c').read_text()
    hook = src[src.index('static char android_display'):src.index('static long calculate_offsets')]
    offsets = src[src.index('static long calculate_offsets'):src.index('static long inline_hook_init')]
    inst = (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    inst = re.sub(r'^#include .*\n', '', inst, flags=re.M)
    declarations = ''
    target_test = ''
    if args.image:
        syms = {n: a for a, t, n in json.loads(args.symbols.read_text())}
        data = args.image.read_bytes()
        for name, count in [('task_clear_jobctl_trapping', 16), ('out_of_memory', 160)]:
            raw = data[syms[name]:syms[name] + count * 4]
            assert len(raw) == count * 4
            declarations += 'static uint32_t image_' + name + '[] = {' + ','.join(
                hex(int.from_bytes(raw[i:i+4], 'little')) for i in range(0, len(raw), 4)) + '};\n'
        expected = [int(x, 0) for x in args.expected.split(',')]
        target_test = f'''
  job_entry = image_task_clear_jobctl_trapping;
  oom_entry = image_out_of_memory;
  task_struct_jobctl_offset = task_struct_signal_offset = signal_struct_oom_score_adj_offset = UZERO;
  assert(calculate_offsets() == 0);
  assert(task_struct_jobctl_offset == {expected[0]} && task_struct_signal_offset == {expected[1]}
         && signal_struct_oom_score_adj_offset == {expected[2]});
'''
    fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define UZERO (1UL << 32)
#define SIGKILL 9
#define JOBCTL_TRAP_FREEZE (1UL << 23)
#define logkm(...) ((void)0)
#define task_uid(t) ((struct uid){(t)->uid})
#define get_task_comm(t) ((t)->comm)
#define MIN_SYSTEM_UID 1000
#define MAX_SYSTEM_UID 2000
#define MIN_USERAPP_UID 10000
struct uid { unsigned val; };
struct signal_struct { short oom; };
struct task_struct { unsigned long jobctl; struct signal_struct* signal; unsigned uid; char comm[16]; };
struct kernel_siginfo { int si_signo, si_errno, si_code; };
typedef struct { uintptr_t arg0, arg1, arg2; long ret; bool skip_origin; } hook_fargs4_t;
static struct signal_struct sig;
static struct task_struct caller, dst;
#define current (&caller)
static bool cgroup_freezing(struct task_struct* t) { return false; }
static uint64_t task_struct_jobctl_offset, task_struct_signal_offset, signal_struct_oom_score_adj_offset;
static uint64_t last_uid = UZERO, oom_score_adj_max = UZERO;
static uint32_t job[16], oom[160];
static uint32_t* job_entry = job;
static uint32_t* oom_entry = oom;
#define lookup_name(f) f = (typeof(f))(!strcmp(#f, "out_of_memory") ? oom_entry : job_entry)
/* CODE */
int main(void) {
  task_struct_jobctl_offset = __builtin_offsetof(struct task_struct, jobctl);
  task_struct_signal_offset = __builtin_offsetof(struct task_struct, signal);
  signal_struct_oom_score_adj_offset = 0;
  caller.uid = 1000; strcpy(caller.comm, "system_server");
  dst.uid = 10001; dst.jobctl = JOBCTL_TRAP_FREEZE; dst.signal = &sig;
  for (uintptr_t i = 0; i <= 2; i++) {
    hook_fargs4_t a = {SIGKILL, i, (uintptr_t)&dst, 123, false};
    do_send_sig_info_before(&a, NULL);
    assert(!a.skip_origin && a.ret == 123 && last_uid == UZERO);
  }
  struct kernel_siginfo info = {SIGKILL, 0, 0};
  hook_fargs4_t a = {SIGKILL, (uintptr_t)&info, (uintptr_t)&dst, 123, false};
  do_send_sig_info_before(&a, NULL); assert(a.skip_origin && a.ret == -EPERM);
  info.si_code = 128; a.skip_origin = false; a.ret = 123;
  do_send_sig_info_before(&a, NULL); assert(!a.skip_origin && a.ret == 123);
  info.si_code = 0; caller.uid = 0;
  do_send_sig_info_before(&a, NULL); assert(!a.skip_origin);
  caller.uid = 1000; dst.jobctl = 0;
  do_send_sig_info_before(&a, NULL); assert(!a.skip_origin && last_uid == dst.uid);
  for (int i = 0; i < 16; i++) job[i] = 0xd503201f;
  for (int i = 0; i < 160; i++) oom[i] = 0xd503201f;
  job[1] = 0xf942c008; job[2] = 0x37a800a8;
  oom[3] = 0xf943fa88; oom[4] = 0x79c78508; oom[5] = 0x310fa11f;
  task_struct_jobctl_offset = task_struct_signal_offset = signal_struct_oom_score_adj_offset = UZERO;
  assert(calculate_offsets() == 0 && task_struct_jobctl_offset == 0x580
         && task_struct_signal_offset == 0x7f0 && signal_struct_oom_score_adj_offset == 0x3c2);
  oom[4] ^= 1U << 5; task_struct_signal_offset = signal_struct_oom_score_adj_offset = UZERO;
  assert(calculate_offsets() != 0);
  oom[4] ^= 1U << 5; oom[5] ^= 1U << 5;
  assert(calculate_offsets() != 0);
  job[2] ^= 1U << 19; task_struct_jobctl_offset = UZERO;
  assert(calculate_offsets() != 0);
  /* TARGET */
  puts("signal special-pointer, policy and offset regressions: PASS");
}
'''
    source = args.output / 'test.c'
    source.write_text(fixture.replace('/* CODE */', inst + declarations + hook + offsets).replace('/* TARGET */', target_test))
    binary = args.output / 'test'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                    '-fsanitize=address,undefined', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
