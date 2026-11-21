#!/usr/bin/env python3
"""Developer: 聚合清零的 memset 包装与加载期槽值门禁（cgroupv2_freeze）。

夹具取生产源码：公共 `kpm_runtime.c` 的 `memset` 包装体，以及 `cgroupv2_freeze.c` 里
`inline_hook_init` 的前导段。覆盖 memset 槽值、原生 freezer 拒载，以及每个
冻结回调依赖的原生 API 缺失时的拒载。
"""
import argparse
from pathlib import Path
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
module = Path(__file__).resolve().parents[1]
makefile = (module / 'Makefile').read_text()
sources = next(line.split(':=', 1)[1].split() for line in makefile.splitlines() if line.startswith('objs :='))
assert sources.count('../kpm_runtime.c') == 1
assert '$(objs) -r' in makefile
shared = (module.parent / 'kpm_runtime.c').read_text()
assert '#include <linux/string.h>' not in shared
assert 'void* memset(' not in (module.parent / 'kpm_utils.h').read_text()
wrapper = shared[shared.index('void* memset('):]
assert wrapper.count('void* memset(') == 1
init = (module / 'cgroupv2_freeze.c').read_text()
prologue = init[init.index('static long inline_hook_init'):init.index('  lookup_name(cgroup_addrm_files);')]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define __user
#define logkm(...) ((void)0)

static unsigned char* seen_dest;
static int seen_c, slot_calls;
static size_t seen_n;
static void* native_memset(void* dest, int c, size_t n) {
  seen_dest = dest; seen_c = c; seen_n = n; slot_calls++;
  return (void*)((uintptr_t)dest + 7);
}
// KP 导出的是槽变量，槽值由 KP 初始化；这里用同名槽模拟「填了」与「没填」。
static void* (*kf_memset)(void*, int, size_t);
#define kfunc(func) kf_##func

/* MEMSET_WRAPPER */

/* INIT_PROLOGUE */
  return 0;
}

static void reset(void) { slot_calls = 0; seen_dest = (void*)0x1; seen_c = -1; seen_n = 0; }

int main(void) {
  unsigned char buf[9];
  // 1. 槽值缺失：逐字节回退清零，返回原 dest，不经过槽位。
  kf_memset = NULL;
  reset(); memset(buf, 0, sizeof(buf));
  for (unsigned int i = 0; i < sizeof(buf); i++) assert(buf[i] == 0);
  assert(slot_calls == 0);

  // 2. 槽值缺失 + 非零字节：逐字节填充同样生效。
  memset(buf, 0xa5, sizeof(buf));
  for (unsigned int i = 0; i < sizeof(buf); i++) assert(buf[i] == 0xa5);
  assert(slot_calls == 0);

  // 3. 槽值存在：直通 KP 导出，参数与返回值原样传递。
  kf_memset = native_memset;
  reset(); void* ret = memset(buf, 0x5a, 5);
  assert(slot_calls == 1 && seen_dest == buf && seen_c == 0x5a && seen_n == 5);
  assert((uintptr_t)ret == (uintptr_t)buf + 7);

  // 4. 加载期：memset 槽值缺失 → 无论有无原生 freezer 都拒载。
  kf_memset = NULL; kf_freeze_write = NULL;
  assert(inline_hook_init(NULL, NULL, NULL) == -ENOENT);
  kf_memset = NULL; kf_freeze_write = (void (*)(void))1;
  assert(inline_hook_init(NULL, NULL, NULL) == -ENOENT);

  // 5. 加载期：槽值存在且内核自带 freezer → 按「不支持」拒载（不是 EMFILE）。
  kf_memset = native_memset; kf_freeze_write = (void (*)(void))1;
  assert(inline_hook_init(NULL, NULL, NULL) == -EOPNOTSUPP);
  assert(-EOPNOTSUPP != -24);

  // 6. 加载期：槽值存在且没有原生 freezer → 通过前导段继续初始化。
  kf_memset = native_memset; kf_freeze_write = NULL;
  assert(inline_hook_init(NULL, NULL, NULL) == 0);
  assert(css_task_iter_start_v4 == css_task_iter_start);
  assert(cgroup_kn_lock_live_v4 == cgroup_kn_lock_live);

  // 7. 每项 freezer API 单独缺失时都必须在继续初始化前拒载。
  const char* required[] = {
      "proc_pid_wchan", "signal_wake_up_state", "css_task_iter_start", "css_task_iter_next",
      "css_task_iter_end", "css_next_descendant_pre", "cgroup_kn_lock_live", "cgroup_kn_unlock",
      "schedule", "wake_up_process", "of_css", "seq_printf", "kstrtoint", "strim",
  };
  for (size_t i = 0; i < sizeof(required) / sizeof(*required); i++) {
    missing_symbol = required[i];
    assert(inline_hook_init(NULL, NULL, NULL) == -ENOENT);
  }

  puts("memset wrapper, native freezer gate, and 14 missing-API cases: PASS");
  return 0;
}
'''

stubs = r'''
static void (*kf_freeze_write)(void);
static const char* missing_symbol;
static void native_api(void) {}
static void (*proc_pid_wchan)(void), (*signal_wake_up_state)(void);
static void (*css_task_iter_start)(void), (*css_task_iter_start_v4)(void);
static void (*css_task_iter_next)(void), (*css_task_iter_end)(void), (*css_next_descendant_pre)(void);
static void (*cgroup_kn_lock_live)(void), (*cgroup_kn_lock_live_v4)(void), (*cgroup_kn_unlock)(void);
static void (*kf_schedule)(void), (*kf_wake_up_process)(void), (*kf_of_css)(void);
static void (*kf_seq_printf)(void), (*kf_kstrtoint)(void), (*kf_strim)(void);

static void* kallsyms_lookup_name(const char* name) {
  if (!strcmp(name, "cgroup_freeze_write"))
    return (void*)kf_freeze_write;
  return missing_symbol && !strcmp(name, missing_symbol) ? NULL : (void*)native_api;
}
#define lookup_name(func)                                      \
  do {                                                         \
    func = (typeof(func))kallsyms_lookup_name(#func);             \
    if (!func)                                                 \
      return -ENOENT;                                          \
  } while (0)
#define kfunc_lookup_name(func) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func)
'''

p = a.output / 'test.c'
p.write_text(fixture.replace('/* MEMSET_WRAPPER */', wrapper)
             .replace('/* INIT_PROLOGUE */', stubs + prologue))
b = a.output / 'test'
subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-fno-builtin',
                '-fsanitize=address,undefined', str(p), '-o', str(b)], check=True)
subprocess.run([str(b)], check=True)
