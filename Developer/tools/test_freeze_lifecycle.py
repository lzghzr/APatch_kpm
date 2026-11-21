#!/usr/bin/env python3
"""Developer: production cleanup, partial installation and shared hook callback identities."""
import argparse
from pathlib import Path
import subprocess
import re


def function(text, name):
    match = re.search(r'static (?:int|long) ' + name + r'\([^)]*\)\s*\{', text)
    assert match, name
    start = match.start()
    opening = match.end() - 1
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#define __user
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define logkm(...) ((void)0)
#define kvar(n) ((void*)33)
#define kfunc(n) n
static int unregister_error, trace_error, unwraps, foreign_callbacks = 1;
static bool trace, binder_vendor_record_registered, binder_proc_hooked;
static bool rekernel_genl_registered, rekernel_genl_hooked;
static void* binder_vendor_record = (void*)10;
static void* binder_proc_transaction = (void*)11;
static int rekernel_genl_family_store;
/* FAMILY */
static void* genl_rcv_msg = (void*)12;
static void binder_vendor_transaction_record(void) {}
static void binder_proc_transaction_before(void) {}
static void rekernel_binder_transaction(void) {}
static void genl_rcv_msg_before(void) {}
static int tracepoint_probe_unregister(void* p, void* f, void* data) { return trace_error; }
static int genl_unregister_family(void* f) { return unregister_error; }
static void kfree(void* p) {}
static void hook_unwrap(void* p, void* before, void* after) {
  assert(p && before); unwraps++; assert(foreign_callbacks == 1);
}
struct rekernel_hook { void* func; int args; void* before; void* after; void* data; bool installed; };
static struct rekernel_hook rekernel_hooks[4];
/* FUNCTIONS */
static void reset(void) {
  unregister_error = trace_error = unwraps = 0;
  trace = binder_vendor_record_registered = binder_proc_hooked = false;
  rekernel_genl_registered = rekernel_genl_hooked = false;
  /* RESET_FAMILY */
  for (int i = 0; i < 4; i++)
    rekernel_hooks[i] = (struct rekernel_hook){(void*)(uintptr_t)(100+i), 2, (void*)200, NULL, NULL, false};
}
int main(void) {
  reset(); assert(inline_hook_exit(NULL) == 0 && unwraps == 0);
  for (int n = 0; n < 5; n++) {
    reset(); for (int i = 0; i < n; i++) rekernel_hooks[i].installed = true;
    assert(inline_hook_exit(NULL) == 0 && unwraps == n);
    assert(inline_hook_exit(NULL) == 0 && unwraps == n && foreign_callbacks == 1);
  }
  reset(); binder_vendor_record_registered = binder_proc_hooked = trace = true;
  rekernel_hooks[0].installed = true;
  trace_error = -EIO;
  assert(inline_hook_exit(NULL) == -EIO && binder_vendor_record_registered && trace && !binder_proc_hooked);
  assert(!rekernel_hooks[0].installed && unwraps == 2);
  trace_error = 0;
  assert(inline_hook_exit(NULL) == 0 && !binder_vendor_record_registered && !trace && unwraps == 2);
  reset(); rekernel_genl_registered = rekernel_genl_hooked = true;
  unregister_error = -EBUSY;
  assert(inline_hook_exit(NULL) == -EBUSY && rekernel_genl_registered && unwraps == 0);
  unregister_error = 0;
  assert(inline_hook_exit(NULL) == 0 && !rekernel_genl_registered && unwraps == 1);
  assert(inline_hook_exit(NULL) == 0 && unwraps == 1 && foreign_callbacks == 1);
  puts("production cleanup failure states and shared callbacks: PASS");
}
'''
    for module in ('re_kernel', 're_kernel_x'):
        src = (root / module / 're_kernel.c').read_text()
        # Prefer definitions over forward declarations.
        src = src.replace('static int binder_cleanup_hook_exit(void);', '')
        bodies = '\n'.join(function(src, n) for n in
                           ('binder_cleanup_hook_exit', 'stop_rekernel_hooks', 'stop_rekernel_genl_server', 'inline_hook_exit'))
        text = fixture.replace('/* FUNCTIONS */', bodies)
        if module == 're_kernel':
            text = text.replace('/* FAMILY */', 'static void* rekernel_genl_family = &rekernel_genl_family_store;')
            text = text.replace('/* RESET_FAMILY */', 'rekernel_genl_family = &rekernel_genl_family_store;')
        else:
            text = text.replace('/* FAMILY */', 'static int rekernel_genl_family;').replace('/* RESET_FAMILY */', '')
        source = a.output / (module + '.c')
        source.write_text(text)
        binary = a.output / module
        subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                        '-Wno-unused-parameter', '-fsanitize=address,undefined', str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
