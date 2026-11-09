#!/usr/bin/env python3
"""执行生产策略解析器，核对无规则快路、保守规则语义和逐分支debug诊断。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from test_native_apis import function

HOST = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
/* CONSTANTS */
struct binder_proc { int pid; };
struct binder_buffer { size_t data_size; unsigned char data[PARCEL_OFFSET + REKERNEL_RPC_NAME_SIZE * 2 + 8]; };
static bool rules, read_error;
static unsigned int reads, lookups, log_count;
static unsigned char lookup_strategy = REKERNEL_FREE_ASYNC_BY_CODE;
static char message[256];
static bool free_async_has_rules(void) { return rules; }
static void* binder_proc_alloc(struct binder_proc* p) { return p; }
static int binder_buffer_read(void* alloc, void* dest, struct binder_buffer* b, size_t offset, size_t bytes) {
  assert(alloc && !offset && bytes <= b->data_size && bytes <= sizeof(b->data));
  reads++; if (read_error) return -EFAULT; memcpy(dest, b->data, bytes); return 0;
}
static unsigned char free_async_lookup(const char* rpc, unsigned int code) {
  assert(!strcmp(rpc, "test.raw.IRemote") && code == 1); lookups++; return lookup_strategy;
}
static void capture(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void capture(const char* fmt, ...) {
  va_list args; va_start(args, fmt); int n = vsnprintf(message, sizeof(message), fmt, args); va_end(args);
  assert(n > 0 && (size_t)n < sizeof(message)); log_count++;
}
#define logkm(...) capture(__VA_ARGS__)
/* PRODUCTION */
static void check(struct binder_buffer* buffer, unsigned char expected, const char* reason,
                  unsigned int expected_reads, unsigned int expected_lookups) {
  struct binder_proc proc = {.pid = 4321}; reads = lookups = log_count = 0; message[0] = 0;
  assert(binder_free_async_strategy(&proc, buffer, 1) == expected);
  assert(reads == expected_reads && lookups == expected_lookups);
#ifdef CONFIG_DEBUG
  char expected_message[256];
  snprintf(expected_message, sizeof(expected_message),
    "free_async_strategy pid=4321,code=1,data_size=%llu,rules_present=%u,strategy=%u,reason=%s\n",
    (unsigned long long)buffer->data_size, (unsigned int)rules, expected, reason);
  assert(log_count == 1 && !strcmp(message, expected_message));
#else
  assert(!log_count && !message[0]);
#endif
}
int main(void) {
  struct binder_buffer buffer = {.data_size = 4};
  read_error = true; rules = false;
  check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "no_rules", 0, 0);
  rules = true; check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "short_payload", 0, 0);
  buffer.data_size = PARCEL_OFFSET + 4;
  check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "read_failed", 1, 0);
  read_error = false; check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "empty_token", 1, 0);
  const char* name = "test.raw.IRemote";
  buffer.data_size = PARCEL_OFFSET + (strlen(name) + 1) * 2;
  for (unsigned int i = 0; name[i]; i++) buffer.data[PARCEL_OFFSET + i * 2] = name[i];
  for (unsigned int strategy = REKERNEL_FREE_ASYNC_SKIP; strategy <= REKERNEL_FREE_ASYNC_BY_DATA; strategy++) {
    lookup_strategy = strategy; check(&buffer, strategy, "rpc_lookup", 1, 1);
  }
  buffer.data[PARCEL_OFFSET + 1] = 1;
  check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "invalid_token", 1, 0);
  buffer.data[PARCEL_OFFSET + 1] = 0; buffer.data_size -= 2;
  check(&buffer, REKERNEL_FREE_ASYNC_BY_CODE, "invalid_token", 1, 0);
  puts("strategy resolver: empty rules/short payload/read failure/empty and malformed token/rule result, exact debug event and release silence: PASS");
}
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args(); args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    header, source = (module/'re_kernel.h').read_text(), (module/'re_kernel.c').read_text()
    constants = '\n'.join(re.search(r'^#define '+n+r' .+$', header, re.M)[0] for n in ('PARCEL_OFFSET','REKERNEL_RPC_NAME_SIZE'))
    constants += '\n'+re.search(r'enum rekernel_free_async_strategy\s*\{.*?\};',header,re.S)[0]
    production = '\n'.join(function(source,n) for n in ('binder_free_async_decision','binder_free_async_strategy'))
    results=[]
    for debug in (False,True):
        name='debug' if debug else 'release'; path,binary=args.output/(name+'.c'),args.output/name
        path.write_text(HOST.replace('/* CONSTANTS */',constants).replace('/* PRODUCTION */',production))
        cmd=['clang','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function',
             '-fsanitize=address,undefined','-g',*(['-DCONFIG_DEBUG'] if debug else []),str(path),'-o',str(binary)]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        (args.output/(name+'-build.log')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
        r=subprocess.run([str(binary.resolve())],capture_output=True,text=True,timeout=120)
        (args.output/(name+'.log')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stdout+r.stderr
        results.append({'debug':debug,'exit_code':r.returncode,'stdout':r.stdout.strip()});print(name+': '+r.stdout.strip())
    (args.output/'receipt.json').write_text(json.dumps({'scope':'Developer host evidence, not device branch observation','results':results},indent=2)+'\n')

if __name__=='__main__':main()
