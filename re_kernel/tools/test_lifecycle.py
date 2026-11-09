#!/usr/bin/env python3
"""执行生产初始化注册后半段及按安装状态回滚；不验证热卸载安全性。"""
import argparse
from pathlib import Path
import subprocess
from test_native_apis import function

HOST = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define kfunc(n) 1
#define kvar(n) ((void*)1)
static int tracepoint, genl, cleanup, hooks, calls;
static int fail_hook = -1, fail_offsets, fail_prepare, fail_start, fail_cleanup, fail_trace;
static bool trace;
static int ipv4_version=4, ipv6_version=6;
static void binder_transaction(void) {}
static void binder_transaction_before(void) {}
static void binder_transaction_after(void) {}
static void do_send_sig_info(void) {}
static void do_send_sig_info_before(void) {}
static void tcp_v4_do_rcv(void) {}
static void tcp_v6_do_rcv(void) {}
static void tcp_rcv_before(void) {}
static void rekernel_binder_transaction(void) {}
static int calculate_offsets(void) { return fail_offsets; }
static int prepare_rekernel_genl_server(void) { return fail_prepare; }
static int start_rekernel_genl_server(void) {
  assert(hooks==4 && !cleanup); if (fail_start) return -12; genl++; return 0;
}
static int binder_cleanup_hook_init(void) {
  assert(genl==1 && hooks==4 && !cleanup); if (fail_cleanup) return -2; cleanup++; return 0;
}
static void binder_cleanup_hook_exit(void) { if (cleanup) cleanup--; }
static int stop_rekernel_genl_server(void) { assert(!cleanup); genl=0; return 0; }
static int tracepoint_probe_register(void* tp, void* cb, void* data) {
  assert(tp==(void*)1 && cb==rekernel_binder_transaction && !data);
  if (fail_trace) return -2; tracepoint++; return 0;
}
static int tracepoint_probe_unregister(void* tp, void* cb, void* data) {
  assert(tp==(void*)1 && cb==rekernel_binder_transaction && !data && tracepoint==1);
  tracepoint--; return 0;
}
/* HOOK_DECL */
static int hook_wrap(void* fn, int count, void* before, void* after, void* data) {
  struct rekernel_hook* h=&rekernel_hooks[calls];
  assert(fn==h->func && count==h->args && before==h->before && after==h->after && data==h->data);
  if (calls++==fail_hook) return 7; hooks++; return 0;
}
static void hook_unwrap(void* fn, void* before, void* after) {
  assert(hooks>0);
  struct rekernel_hook* h=&rekernel_hooks[hooks-1];
  assert(fn==h->func && before==h->before && after==h->after && h->installed);
  hooks--;
}
/* PRODUCTION */
static void reset(void) {
  assert(!genl && !cleanup && !hooks && !trace && !tracepoint);
  calls=fail_offsets=fail_prepare=fail_start=fail_cleanup=fail_trace=0; fail_hook=-1;
}
int main(void) {
  for (int i=0;i<4;i++) {
    reset(); fail_hook=i; assert(initialize()==-EOPNOTSUPP);
    assert(!genl && !cleanup && !hooks && !trace && !tracepoint);
    stop_rekernel_hooks(); assert(!hooks);
  }
  reset(); fail_start=1; assert(initialize()==-12 && !hooks && !tracepoint && !genl);
  reset(); fail_cleanup=1; assert(initialize()==-2 && !hooks && !tracepoint && !genl);
  reset(); fail_offsets=-22; assert(initialize()==-22 && !calls && !genl && !tracepoint);
  reset(); fail_prepare=-107; assert(initialize()==-107 && !calls && !genl && !tracepoint);
  for (int i=0;i<2;i++) {
    reset(); fail_trace=i; assert(!initialize() && hooks==4 && genl==1 && cleanup==1);
    assert(tracepoint==!i); assert(!inline_hook_exit(NULL));
    assert(!genl && !cleanup && !hooks && !trace && !tracepoint);
    assert(!inline_hook_exit(NULL));
  }
  puts("init: four hook failure points, Genl/vendor failures, early rejection and symmetric owned cleanup: PASS");
}
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = (Path(__file__).resolve().parents[1] / 're_kernel.c').read_text()
    decl = source[source.index('struct rekernel_hook {'):source.index('static void stop_rekernel_hooks(')]
    init = function(source, 'inline_hook_init')
    init = 'static int initialize(void) {\n' + init[init.index('  rekernel_hooks[0]'):]
    production = function(source, 'stop_rekernel_hooks') + '\n' + init + '\n' + function(source, 'inline_hook_exit')
    production = production.replace('void* __user reserved', 'void* reserved')
    path, binary = args.output/'lifecycle.c', args.output/'lifecycle'
    path.write_text(HOST.replace('/* HOOK_DECL */', decl).replace('/* PRODUCTION */', production))
    build = subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-missing-field-initializers', '-fsanitize=address,undefined', '-g', str(path), '-o', str(binary)], text=True, capture_output=True)
    (args.output/'build.log').write_text(build.stdout+build.stderr)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(binary.resolve())], text=True, capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr)
    assert run.returncode == 0, run.stdout+run.stderr
    print(run.stdout.strip())

if __name__ == '__main__':
    main()
