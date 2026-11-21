#!/usr/bin/env python3
"""Developer: 事件驱动补挂的夹具。

切片生产源码的 `cfv2_is_cg2_mount_ok()`、`cfv2_arm_cg2_signal()`、`cfv2_mount_thread()`，注入假
kern_path/do_mount/path_put/msleep，验证四条：
① ret != 0 → 不置标志；② type != "cgroup2" → 不置标志；③ 成功的 cgroup2 → 置标志一次（重复调用不再改）；
④ 线程在标志为真后只调用一次 mount，且 -EBUSY 也算结束（不重试）。
"""
import argparse
from pathlib import Path
import subprocess

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
src = (Path(__file__).resolve().parents[1] / 'cgroupv2_freeze.c').read_text()
start = src.index('#define CFV2_SYSFS_CGROUP')
end = src.index('// do_mount 的 after 钩子：全部动作就是这一行调用')
sl = src[src.index('#define CFV2_SYSFS_CGROUP'):src.index('// do_mount 的 after 钩子：全部动作就是这一行调用')]
sl += src[src.index('// 独立线程：等 init 把 cgroup2 挂上'):src.index('#include "cfv2_offsets.c"')]

fixture = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EBUSY 16
struct hook_fargs4_t;  // 钩子本体不进夹具（只测纯判据、置信号与线程）
static int log_count;
#define logkm(fmt, ...) (log_count++, printf("[log] " fmt, ##__VA_ARGS__))
static int msleep_calls;
static void (*kf_msleep)(unsigned int);
static int strcmp_calls;
#define kfunc(f) kf_##f
static int kf_strcmp(const char* a, const char* b) { strcmp_calls++; return strcmp(a, b); }
static void real_msleep(unsigned int ms) { msleep_calls++; (void)ms; }

/* SLICE */

static int kp_calls = 0, mount_calls = 0, put_calls = 0;
static int kp_rc = 0;
static long mount_rc = 0;

static int fake_kern_path(const char* n, unsigned int f, struct cfv2_path* p) {
  kp_calls++;
  if (kp_rc) return kp_rc;
  p->mnt = (void*)1; p->dentry = (void*)2;
  return 0;
}
static long fake_do_mount(const char* dev, struct cfv2_path* p, const char* type, unsigned long fl, void* d) {
  mount_calls++;
  return mount_rc;
}
static void fake_path_put(const struct cfv2_path* p) { put_calls++; }

static void wire(void) {
  cfv2_kern_path = fake_kern_path;
  cfv2_do_mount = fake_do_mount;
  cfv2_path_put = fake_path_put;
  kf_msleep = real_msleep;
}

int main(void) {
  wire();

  // ① ret != 0 → 不置标志
  cfv2_cg2_mounted = false;
  assert(cfv2_arm_cg2_signal(-1, "cgroup2") == false && cfv2_cg2_mounted == false);

  // ② type 不是 cgroup2（含 NULL）→ 不置标志
  assert(cfv2_arm_cg2_signal(0, "cgroup") == false && cfv2_cg2_mounted == false);
  assert(cfv2_arm_cg2_signal(0, NULL) == false && cfv2_cg2_mounted == false);

  // ③ 成功的 cgroup2 → 置标志一次；重复调用不再改（返回 false）
  assert(cfv2_arm_cg2_signal(0, "cgroup2") == true && cfv2_cg2_mounted == true);
  assert(cfv2_arm_cg2_signal(0, "cgroup2") == false && cfv2_cg2_mounted == true);

  // ④ 线程：标志为真 → 只调用一次 mount；-EBUSY 也算结束（不重试）
  mount_rc = -16; kp_calls = mount_calls = put_calls = msleep_calls = log_count = 0;
  assert(cfv2_mount_thread(NULL) == 0);
  assert(mount_calls == 1 && kp_calls == 1 && put_calls == 1 && log_count == 1 && msleep_calls == 0);

  // ⑤ 线程：标志为假 → 等满 1200 档后跳过，完全不 mount
  cfv2_cg2_mounted = false;
  kp_calls = mount_calls = put_calls = msleep_calls = log_count = 0;
  assert(cfv2_mount_thread(NULL) == 0);
  assert(msleep_calls == 1200 && mount_calls == 0 && kp_calls == 0 && log_count == 1);

  // ⑥ 线程：成功路径只打 mounted
  cfv2_cg2_mounted = true;
  mount_rc = 0; kp_calls = mount_calls = put_calls = msleep_calls = log_count = 0;
  assert(cfv2_mount_thread(NULL) == 0);
  assert(mount_calls == 1 && log_count == 1 && msleep_calls == 0);

  printf("event-driven mount: 6 checks passed\n");
  return 0;
}
"""
p = a.output / 'test.c'
p.write_text(fixture.replace('/* SLICE */', sl))
b = a.output / 'test'
subprocess.run(['clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                '-fsanitize=address,undefined', str(p), '-o', str(b)], check=True)
subprocess.run([str(b)], check=True)
