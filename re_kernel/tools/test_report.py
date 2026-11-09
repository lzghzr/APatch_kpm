#!/usr/bin/env python3
"""执行 Re:Kernel 自有事件格式、冻结过滤、29～32 筛选及 nofault/旧读取路径。"""
import argparse
from pathlib import Path
import subprocess
from test_native_apis import function

HOST = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define dev_t kernel_dev_t
#define mode_t kernel_mode_t
#define off_t kernel_off_t
#include "re_kernel_host.h"
#undef dev_t
#undef mode_t
#undef off_t
#define kfunc(n) kf_##n
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
static bool rekernel_genl_registered = true, frozen = true;
static unsigned int sends, copies, duplicates, returns;
static int copy_error;
static char message[PACKET_SIZE];
static struct binder_transaction_data call;
static struct task_struct* src = (void*)10001;
static struct task_struct* dst = (void*)10002;
static kuid_t task_uid(struct task_struct* t) { return (kuid_t){(uid_t)(uintptr_t)t}; }
static bool frozen_task_group(struct task_struct* t) { return frozen; }
static struct binder_transaction_data* binder_current_transaction(void) { return &call; }
static int send_netlink_message(char* text) {
  assert(strlen(text) < sizeof(message)); strcpy(message, text); sends++; return 0;
}
static void* memdup_user(const void* src, size_t size) {
  duplicates++; void* p = malloc(size ? size : 1); assert(p); memcpy(p, src, size); return p;
}
static void kvfree(const void* p) { returns++; free((void*)p); }
static long nofault(void* dst, const void* src, size_t len) {
  copies++; if (copy_error) return copy_error; memcpy(dst, src, len); return 0;
}
static long (*kf_copy_from_user_nofault)(void*, const void*, size_t);
/* PRODUCTION */
static void reset(void) { sends = copies = duplicates = returns = 0; copy_error = 0; message[0] = 0; }
int main(void) {
  unsigned char parcel[INTERFACETOKEN_BUFF_SIZE + 10] = {0};
  memcpy(parcel + PARCEL_OFFSET, "a\0b\0c\0", 6);
  call.data.ptr.buffer = (uintptr_t)parcel; call.data_size = sizeof(parcel);
  for (unsigned int mode = 0; mode < 2; mode++) {
    kf_copy_from_user_nofault = mode ? nofault : NULL;
    for (unsigned int code = 28; code <= 33; code++) {
      reset(); call.code = code;
      binder_trans_handler(123, src, 456, dst, true);
      bool expected = code >= 29 && code <= 32;
      assert(sends == expected && copies == (expected && mode));
      assert(duplicates == (expected && !mode) && returns == duplicates);
      if (expected) {
        char expected_text[256];
        snprintf(expected_text, sizeof(expected_text), "type=Binder,bindertype=transaction,oneway=1,from_pid=123,from=10001,target_pid=456,target=10002,rpc_name=abc,code=%d;", code);
        assert(!strcmp(message, expected_text));
      }
    }
    call.code = 29;
    for (unsigned int size = 0; size <= INTERFACETOKEN_BUFF_SIZE; size++) {
      reset(); call.data_size = size;
      binder_trans_handler(123, src, 456, dst, true);
      assert(sends == 1 && returns == duplicates);
    }
    call.data_size = sizeof(parcel);
  }
  reset(); kf_copy_from_user_nofault = nofault; copy_error = -14;
  binder_trans_handler(123, src, 456, dst, true);
  assert(!sends && copies == 1 && !duplicates);
  reset(); frozen = false;
  binder_trans_handler(123, src, 456, dst, true); assert(!sends && !copies);
  frozen = true;
  binder_trans_handler(123, src, 123, dst, false); assert(!sends);
  binder_trans_handler(123, src, 456, src, false); assert(!sends);
  binder_trans_handler(123, src, 456, (void*)1000, false); assert(!sends);
  binder_trans_handler(123, src, 456, dst, false);
  assert(sends == 1 && !strcmp(message, "type=Binder,bindertype=transaction,oneway=0,from_pid=123,from=10001,target_pid=456,target=10002;"));
  reset(); binder_reply_handler(123, src, 456, (void*)1000, false);
  assert(sends == 1 && !strcmp(message, "type=Binder,bindertype=reply,oneway=0,from_pid=123,from=10001,target_pid=456,target=1000;"));
  reset(); binder_overflow_handler(123, src, 456, dst, true);
  assert(sends == 1 && !strcmp(message, "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=123,from=10001,target_pid=456,target=10002;"));
  reset(); rekernel_report(SIGNAL, 9, 123, src, 456, dst, false);
  assert(sends == 1 && !strcmp(message, "type=Signal,signal=9,killer_pid=123,killer=10001,dst_pid=456,dst=10002;"));
  reset(); frozen = false; rekernel_report(NETWORK, 6, 42, NULL, 10002, NULL, true);
  assert(sends == 1 && !strcmp(message, "type=Network,target=10002,proto=ipv6,data_len=42;"));
  reset(); rekernel_genl_registered = false; rekernel_report(NETWORK, 4, 42, NULL, 10002, NULL, true);
  assert(!sends);
  puts("Re:Kernel wire events, frozen/UID/code filters, short/truncated payloads, nofault/error and legacy reads: PASS");
}
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    source = (module / 're_kernel.c').read_text()
    enums = source[source.index('enum report_type'):source.index('// cgroup_freezing')]
    production = enums + '\n'.join(function(source, n) for n in ('rekernel_report', 'binder_reply_handler', 'binder_trans_handler', 'binder_overflow_handler'))
    (args.output / 're_kernel_host.h').write_bytes((module / 're_kernel.h').read_bytes())
    (args.output / 're_structs.h').write_bytes((module / 're_structs.h').read_bytes())
    path, binary = args.output / 'report.c', args.output / 'report'
    path.write_text(HOST.replace('/* PRODUCTION */', production))
    cmd = ['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-macro-redefined', '-idirafter', str(module.parent / 'KernelPatch/kernel/include'), '-I', str(args.output), '-fsanitize=address,undefined', '-g', str(path), '-o', str(binary)]
    build = subprocess.run(cmd, text=True, capture_output=True)
    (args.output / 'build.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(binary.resolve())], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    print(run.stdout.strip())

if __name__ == '__main__':
    main()
