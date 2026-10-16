#!/usr/bin/env python3
"""执行冻结完整Oracle，追加私有内存分配及RCU释放契约。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = '39c7e474b86464dd6defd3bbe5677c4ce493d278'
ORACLES = {'int': '47dfe87e82325a113223c07e146fabb41335d24b161d8bd7b6d746fe45413fef', 'bool': '35e5acb99a3747ad601fdeea7223c3ebe71af9b3b6aad892d342da336ad870f0'}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for abi, digest in ORACLES.items():
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        assert sha(original.encode()) == digest
        source = original.replace('#define NM_KPM_VERSION "0.4.2"', '#define NM_KPM_VERSION "0.4.3"').replace('kfunc(nm_vzalloc)(', 'nm_zalloc(').replace('kfunc(nm_vfree)(', 'nm_free(')
        for name in ['nm_rules_rcu_free', 'nm_directory_node_rcu_free', 'nm_inode_info_rcu_free', 'nm_directory_proxy_rcu_free']:
            from test_directory_abis import function
            before = function(source, name)
            source = source.replace(before, before.replace('nm_free(', 'nm_free_rcu('))
        # 完整历史Oracle使用合法的slab未命中场景，保持原有单点分配失败模型。
        # 新增用例另行覆盖slab成功、回退成功、两后端同时失败和释放来源。
        fixtures = r'''
static void* memory_slab_miss(unsigned long size,unsigned int flags){assert(size>=64&&size<=1024&&!flags);return NULL;}
static void memory_vmap_free(const void* p){kf_nm_vfree(p);}
static bool memory_vmap(const void* p){return true;}
static void* (*kf_nm_kmalloc)(unsigned long,unsigned int)=memory_slab_miss;
static void (*kf_nm_kvfree)(const void*)=memory_vmap_free;
static bool (*kf_nm_is_vmalloc_addr)(const void*)=memory_vmap;
static void (*kf_nm_vfree_atomic)(const void*)=memory_vmap_free;
static void memory_unexpected_slab_free(const void* p){assert(0);}
static void (*memory_native_kfree)(const void*)=memory_unexpected_slab_free;
'''
        memory = (root / 'nomount/nm_memory.c').read_text()
        # 原生kfree夹具在后面的载荷Oracle定义；此处补其同语义分配接口。
        source = source.replace('static unsigned long inode_fixture_lookup(const char*);', fixtures + memory.replace('kfunc(nm_kfree)', 'memory_native_kfree') + '\nstatic unsigned long inode_fixture_lookup(const char*);', 1)
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        cursor = 0
        for assertion in before:
            cursor = after.index(assertion, cursor) + 1
        source = source.replace('int main(void){assert(!previous_hotpath_main());', 'static int previous_memory_main(void){assert(!previous_hotpath_main());', 1)
        source += r'''
static int slab_calls,vm_calls,ordinary_frees,atomic_frees,slab_frees,slab_fail,vm_fail;
static unsigned long requested;
static void* vm_pointer;
static void* memory_slab(unsigned long size,unsigned int flags){assert(!flags);slab_calls++;requested=size;if(slab_fail)return NULL;void* p=aligned_alloc(64,size);assert(p);memset(p,0xa5,size);return p;}
static void* memory_vm(unsigned long size){vm_calls++;if(vm_fail)return NULL;vm_pointer=calloc(1,size);return vm_pointer;}
static bool memory_is_vm(const void* p){return p==vm_pointer;}
static void memory_ordinary_free(const void* p){ordinary_frees++;free((void*)p);if(p==vm_pointer)vm_pointer=NULL;}
static void memory_atomic_free(const void* p){assert(p==vm_pointer);atomic_frees++;free((void*)p);vm_pointer=NULL;}
static void memory_slab_free(const void* p){assert(p!=vm_pointer);slab_frees++;free((void*)p);}
static void check_memory(void){
 kf_nm_kmalloc=memory_slab;kf_nm_vzalloc=memory_vm;kf_nm_kvfree=memory_ordinary_free;kf_nm_is_vmalloc_addr=memory_is_vm;kf_nm_vfree_atomic=memory_atomic_free;memory_native_kfree=memory_slab_free;
 assert(!nm_zalloc(0)&&!slab_calls&&!vm_calls);nm_free(NULL);nm_free_rcu(NULL);assert(!ordinary_frees&&!atomic_frees&&!slab_frees);
 unsigned long sizes[]={1,32,64,65,128,513,1023,1024};
 for(unsigned int i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++){unsigned char* p=nm_zalloc(sizes[i]);assert(p&&requested>=sizes[i]&&requested<=1024&&!(requested&(requested-1))&&!((uintptr_t)p%64));for(unsigned long j=0;j<requested;j++)assert(!p[j]);nm_free(p);}
 assert(slab_calls==8&&!vm_calls&&ordinary_frees==8);
 unsigned char* p=nm_zalloc(1025);assert(p&&slab_calls==8&&vm_calls==1);nm_free(p);assert(ordinary_frees==9);
 slab_fail=1;p=nm_zalloc(32);assert(p&&slab_calls==9&&vm_calls==2);nm_free_rcu(p);assert(atomic_frees==1&&!slab_frees);
 vm_fail=1;assert(!nm_zalloc(64)&&slab_calls==10&&vm_calls==3);assert(!nm_zalloc(4096)&&slab_calls==10&&vm_calls==4);
 slab_fail=vm_fail=0;p=nm_zalloc(32);assert(p);nm_free_rcu(p);assert(slab_frees==1&&atomic_frees==1&&ordinary_frees==9);
 puts("private memory: slab zero/alignment/boundaries, fallback and total failure, process and RCU free pairing: PASS");
}
int main(void){assert(!previous_memory_main());check_memory();return 0;}
'''
        out = args.output / abi
        out.mkdir()
        c = out / 'contracts.c'
        c.write_text(source)
        command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(out / 'contracts')]
        built = subprocess.run(command, capture_output=True, text=True)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        built.check_returncode()
        run = subprocess.run([str(out / 'contracts')], capture_output=True, text=True)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        run.check_returncode()
        results.append(dict(abi=abi, oracle_sha256=digest, assertions_preserved=len(before), generated_sha256=sha(source.encode()), stdout=run.stdout))
    (args.output / 'receipt.json').write_text(json.dumps(dict(scope='Developer host native allocator fixtures; not target runtime or independent audit',results=results),indent=2)+'\n')
    print('int/bool full Oracle and private allocator: PASS')

if __name__ == '__main__':
    main()
