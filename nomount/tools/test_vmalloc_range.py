#!/usr/bin/env python3
"""核对目标 kvfree 内联范围、原生依赖拒绝与 RCU 释放分派；不执行目标指令。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'config', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    raw = a.image.read_bytes()
    config = json.loads(a.config.read_text())
    assert hashlib.sha256(raw).hexdigest() == config['kernel_sha256']
    symbols = {n: o for o, t, n in json.loads(a.symbols.read_text())}
    at = symbols['kvfree']
    words = struct.unpack_from('<14I', raw, at)
    for index, name in [(11, 'vfree'), (13, 'kfree')]:
        w = words[index]
        assert w & 0xfc000000 == 0x94000000
        d = w & 0x3ffffff
        if d & (1 << 25):
            d -= 1 << 26
        assert at + index * 4 + d * 4 == symbols[name]
    assert 'is_vmalloc_addr' not in symbols
    offsets = (root / 'nomount/nm_offsets.c').read_text()
    parser = 'static int nm_find_vmalloc_range' + offsets.split('static int nm_find_vmalloc_range', 1)[1]
    native = (root / 'nomount/nm_native.c').read_text().split('#include "nm_memory.c"')[0]
    required = re.findall(r'  NM_NATIVE_LOOKUP\(\w+, (\w+)\);', native)
    c = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define __user
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define nm_log_error(...) ((void)0)
struct rcu_head;
struct nm_dir_context;
typedef void (*rcu_callback_t)(struct rcu_head*);
'''
    c += (root / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    c += parser
    c += 'static uint32_t fixture[14];\nstatic const uint32_t words[]={' + ','.join(map(str, words)) + '};\n'
    c += r'''
static const char* missing;
static bool inline_only, hide_vfree;
static bool native_classify(const void* p){return p==(void*)32;}
static uintptr_t call_target(unsigned int i){return (uintptr_t)&fixture[i]+inst_get_bl_label(fixture[i]);}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name){
 if(missing&&!strcmp(missing,name))return 0;
 if(!strcmp(name,"is_vmalloc_addr"))return inline_only?0:(uintptr_t)native_classify;
 if(!strcmp(name,"kvfree"))return (uintptr_t)fixture;
 if(!strcmp(name,"kfree"))return call_target(13);
 if(!strcmp(name,"vfree"))return hide_vfree?0:call_target(11);
 return 1;
}
'''
    c += native
    c += (root / 'nomount/nm_memory.c').read_text()
    c += '''static unsigned int slab_frees,vm_frees;
static void slab_free(const void* p){assert(p==(void*)32);slab_frees++;}
static void vm_free(const void* p){assert((uintptr_t)p==nm_vmalloc_range[0]);vm_frees++;}
'''
    c += r'''
static void base(void){memcpy(fixture,words,sizeof(words));missing=NULL;hide_vfree=false;}
int main(void){
 base();assert(!nm_prepare_native());assert(kf_nm_is_vmalloc_addr((void*)32));
 assert(!kf_nm_is_vmalloc_addr((void*)33));
'''
    for name in required:
        c += f'base();missing="{name}";assert(nm_prepare_native()==-ENOENT);\n'
    c += r'''
 base();inline_only=true;assert(!nm_prepare_native());
 uintptr_t low=nm_vmalloc_range[0],high=nm_vmalloc_range[1];
 assert(low==0xffffffc010000000ULL&&high==0xfffffffebffeffffULL);
 assert(!kf_nm_is_vmalloc_addr((void*)(low-1))&&kf_nm_is_vmalloc_addr((void*)low));
 assert(kf_nm_is_vmalloc_addr((void*)high)&&!kf_nm_is_vmalloc_addr((void*)(high+1)));
 base();hide_vfree=true;assert(nm_prepare_native()==-ENOENT);
 for(unsigned i=0;i<14;i++){base();fixture[i]=0xd503201f;assert(nm_prepare_native()==-EOPNOTSUPP);}
 base();fixture[3]=(fixture[3]&~0xfc00U)|0xfc00U;assert(nm_prepare_native()==-EOPNOTSUPP);
 base();fixture[4]&=~(1U<<31);assert(nm_prepare_native()==-EOPNOTSUPP);
 uintptr_t range[2]={1,2};assert(nm_find_vmalloc_range(NULL,1,1,range)==-ENOENT);
 base();assert(nm_find_vmalloc_range(fixture,0,call_target(13),range)==-ENOENT);
 // 保护页紧随窗口；所有分支只读取14条，原生调用目标只比较，不执行。
 long page=sysconf(_SC_PAGESIZE);char* mem=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(mem!=MAP_FAILED&&!mprotect(mem+page,page,PROT_NONE));
 uint32_t* edge=(void*)(mem+page-sizeof(words));memcpy(edge,words,sizeof(words));
 uintptr_t vf=(uintptr_t)&edge[11]+inst_get_bl_label(edge[11]),kf=(uintptr_t)&edge[13]+inst_get_bl_label(edge[13]);
 assert(!nm_find_vmalloc_range(edge,vf,kf,range)&&range[0]==low&&range[1]==high);
 assert(!munmap(mem,page*2));
 // 实际释放分派使用生产nm_memory.c；只用宿主计数桩代替原生释放。
 base();assert(!nm_prepare_native());kf_nm_kfree=slab_free;kf_nm_vfree_atomic=vm_free;
 nm_free_rcu(NULL);nm_free_rcu((void*)32);nm_free_rcu((void*)nm_vmalloc_range[0]);
 assert(slab_frees==1&&vm_frees==1);
 puts("PASS: native classifier, inline bounds, dependencies, 14 refusal mutations, guarded window and RCU free dispatch");return 0;
}
'''
    a.output.mkdir(parents=True, exist_ok=False)
    source = a.output / 'range.c'
    source.write_text(c)
    r = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-g', str(source), '-o', str(a.output / 'range')], capture_output=True, text=True)
    (a.output / 'compile.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    r = subprocess.run([str(a.output / 'range')], capture_output=True, text=True)
    (a.output / 'run.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    receipt = {'scope': 'Developer parser/native binding fixtures; no target execution, native allocator or RCU result',
               'kernel_sha256': config['kernel_sha256'], 'window_offset': at, 'window_words': words,
               'required_missing_rejected': required, 'result': r.stdout.strip()}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(r.stdout.strip())


if __name__ == '__main__':
    main()
