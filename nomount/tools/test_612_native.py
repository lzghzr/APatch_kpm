#!/usr/bin/env python3
"""执行实际原生符号绑定，验证旧名优先、noprof回退及缺失拒绝。"""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRELUDE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define __user
#define kfunc(n) kf_##n
#define kfunc_def(n) (*kf_##n)
#define nm_log_error(...) ((void)0)
struct rcu_head;struct nm_dir_context;typedef void(*rcu_callback_t)(struct rcu_head*);
static unsigned availability,seen,called;
static void* old_malloc(unsigned long size,unsigned int flags){assert(size==129&&flags==0x41);called|=1;return(void*)17;}
static void* new_malloc(unsigned long size,unsigned int flags){assert(size==129&&flags==0x41);called|=2;return(void*)17;}
static void* old_zalloc(unsigned long size){assert(size==513);called|=4;return(void*)18;}
static void* new_zalloc(unsigned long size){assert(size==513);called|=8;return(void*)18;}
static void unused_native(void){}
static uintptr_t kallsyms_lookup_name_by_suffix(const char*name){
 const char*names[]={"__kmalloc","__kmalloc_noprof","vzalloc","vzalloc_noprof"};
 void*functions[]={old_malloc,new_malloc,old_zalloc,new_zalloc};
 for(unsigned n=0;n<4;n++)if(!strcmp(name,names[n])){seen|=1U<<n;return availability&(1U<<n)?(uintptr_t)functions[n]:0;}
 return(uintptr_t)unused_native;
}
static int nm_find_vmalloc_range(const void*a,uintptr_t b,uintptr_t c,uintptr_t*d){assert(0);return -EINVAL;}
'''
TEST = r'''
int main(void){
 availability=15;assert(!nm_prepare_native()&&seen==5);
 assert(kfunc(nm_kmalloc)(129,0x41)==(void*)17&&kfunc(nm_vzalloc)(513)==(void*)18&&called==5);
 availability=10;seen=called=0;assert(!nm_prepare_native()&&seen==15);
 assert(kfunc(nm_kmalloc)(129,0x41)==(void*)17&&kfunc(nm_vzalloc)(513)==(void*)18&&called==10);
 availability=12;seen=0;assert(nm_prepare_native()==-ENOENT&&!kfunc(nm_kmalloc));
 availability=3;seen=0;assert(nm_prepare_native()==-ENOENT&&!kfunc(nm_vzalloc));
 puts("allocator old-name preference, noprof fallback, typed calls and missing-symbol refusal PASS");return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    body = (ROOT / 'nomount/nm_native.c').read_text().split('#include "nm_memory.c"', 1)[0]
    source = args.output / 'native.c'
    source.write_text(PRELUDE + body + TEST)
    commands = [['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(source), '-o', str(args.output / 'native')], [str((args.output / 'native').resolve())]]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, text=True)
        (args.output / f'{index}.log').write_text(result.stdout + result.stderr)
        result.check_returncode()
    print('native allocator bindings PASS')


if __name__ == '__main__':
    main()
