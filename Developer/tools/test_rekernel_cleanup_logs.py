#!/usr/bin/env python3
"""执行 rek/rekx 各自的生产释放函数，核对公共完成日志和引用归还顺序。"""
import argparse
import json
from pathlib import Path
import re
import subprocess


def function(source, name):
    match = re.search(r'^static void ' + name + r'\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    start, end = match.start(), source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HOST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>
struct task_struct { unsigned int uid; };
struct binder_proc { int pid; struct task_struct* tsk; int tmp_ref; bool released; };
struct binder_transaction;
struct binder_buffer { struct binder_transaction* transaction; unsigned long long data_size; };
struct binder_transaction { struct binder_buffer* buffer; unsigned int code; };
struct rekernel_binder_context { struct binder_proc* cleanup_proc; struct binder_transaction* outdated; };
static struct { unsigned int binder_transaction_buffer; } struct_offset;
static unsigned int phase, completed, reference_returns, log_count;
static char last_log[256];
static struct { unsigned int val; } task_uid(struct task_struct* task) {
  assert(task); return (typeof(task_uid(task))){task->uid};
}
static struct binder_buffer* binder_transaction_buffer(struct binder_transaction* t) { return t->buffer; }
static unsigned int binder_transaction_code(struct binder_transaction* t) { return t->code; }
static struct binder_proc* binder_proc_alloc(struct binder_proc* proc) {
  assert(proc->tmp_ref > 0 && !proc->released); return proc;
}
static void binder_release_entire_buffer(struct binder_proc* proc, void* thread,
                                         struct binder_buffer* buffer, bool failure) {
  assert(!phase && proc->tmp_ref > 0 && !thread && failure);
  assert(!buffer->transaction); phase = 1;
}
static void binder_alloc_free_buf(struct binder_proc* proc, struct binder_buffer* buffer) {
  assert(phase == 1 && proc->tmp_ref > 0); phase = 2; free(buffer);
}
static void native_fixups(struct binder_transaction* t) { assert(phase == 2 && !t->buffer); phase = 3; }
static void (*binder_free_txn_fixups)(struct binder_transaction*) = native_fixups;
static void kfree(struct binder_transaction* t) {
  assert((phase == 2 || phase == 3) && !t->buffer); phase = 4; free(t);
}
enum { BINDER_STAT_TRANSACTION };
static void binder_stats_deleted(int type) {
  assert(phase == 4 && type == BINDER_STAT_TRANSACTION); phase = 5; completed++;
}
static void binder_proc_dec_tmpref(struct binder_proc* proc) {
  assert(phase == 5 && proc->tmp_ref == 1);
#ifdef CONFIG_DEBUG
  assert(log_count == 1); // 完成日志必须早于可能释放 proc 的引用归还。
#else
  assert(!log_count);
#endif
  proc->tmp_ref--; proc->released = true; reference_returns++;
}
static void capture_log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void capture_log(const char* fmt, ...) {
  assert(phase == 5 && completed == 1 && !reference_returns);
  va_list args; va_start(args, fmt); int n = vsnprintf(last_log, sizeof(last_log), fmt, args); va_end(args);
  assert(n > 0 && n < sizeof(last_log)); log_count++;
}
#define logkm(...) capture_log(__VA_ARGS__)
/* PRODUCTION */
int main(void) {
  struct_offset.binder_transaction_buffer = __builtin_offsetof(struct binder_transaction, buffer);
  for (int deferred = 0; deferred < 2; deferred++) for (int fixups = 0; fixups < 2; fixups++) {
    struct task_struct task = {.uid = 10050};
    struct binder_proc proc = {.pid = 4242, .tsk = &task, .tmp_ref = deferred ? 2 : 1};
    phase = completed = reference_returns = log_count = 0; last_log[0] = 0;
    binder_free_outdated(&proc, NULL); assert(!phase && !log_count);
    struct binder_transaction* t = malloc(sizeof(*t));
    struct binder_buffer* b = malloc(sizeof(*b)); assert(t && b);
    *b = (struct binder_buffer){.transaction = t, .data_size = 140};
    *t = (struct binder_transaction){.buffer = b, .code = 7};
    binder_free_txn_fixups = fixups ? native_fixups : NULL;
    if (deferred) {
      struct rekernel_binder_context context = {.cleanup_proc = &proc, .outdated = t};
      proc.tmp_ref--; // native outer 先归还自身引用，模块引用仍保护对象。
      binder_flush_outdated_context(&context);
      assert(!context.cleanup_proc && !context.outdated && !proc.tmp_ref && proc.released && reference_returns == 1);
      binder_flush_outdated_context(&context); assert(reference_returns == 1);
    } else {
      binder_free_outdated(&proc, t);
      assert(proc.tmp_ref == 1 && !proc.released && !reference_returns);
    }
    assert(phase == 5 && completed == 1);
#ifdef CONFIG_DEBUG
    assert(log_count == 1 && !strcmp(last_log, "free_outdated pid=4242,uid=10050,data_size=140,code=7,stage=done\n"));
#else
    assert(!log_count && !last_log[0]);
#endif
  }
  puts("NULL, optional fixups, native release order, post-free snapshots, deferred proc reference and exact done log: PASS");
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    functions, results = {}, []
    for module in ('re_kernel', 're_kernel_x'):
        source = (root / module / 're_kernel.c').read_text()
        functions[module] = '\n'.join(function(source, n) for n in ('binder_free_outdated', 'binder_flush_outdated_context'))
    assert functions['re_kernel'] == functions['re_kernel_x'], '公共释放与 pending flush 在两份模块中须保持同步'
    for module, production in functions.items():
        for debug in (False, True):
            name = module + ('-debug' if debug else '-release')
            source, binary = args.output/(name+'.c'), args.output/name
            source.write_text(HOST.replace('/* PRODUCTION */', production))
            flags = ['-DCONFIG_DEBUG'] if debug else []
            build = subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                                    '-Wno-sign-compare', '-fsanitize=address,undefined', '-g', *flags,
                                    str(source), '-o', str(binary)], capture_output=True, text=True, timeout=120)
            (args.output/(name+'-build.log')).write_text(build.stdout+build.stderr)
            assert build.returncode == 0, build.stderr
            run = subprocess.run([str(binary.resolve())], capture_output=True, text=True, timeout=120)
            (args.output/(name+'.log')).write_text(run.stdout+run.stderr)
            assert run.returncode == 0, run.stdout+run.stderr
            results.append({'module': module, 'debug': debug, 'stdout': run.stdout.strip(), 'exit_code': run.returncode})
            print(name+': '+run.stdout.strip())
    (args.output/'receipt.json').write_text(json.dumps({'scope':'Developer host selfcheck; no device dedup conclusion',
        'separate_functions_identical':True,'results':results},ensure_ascii=False,indent=2)+'\n')


if __name__ == '__main__':
    main()
