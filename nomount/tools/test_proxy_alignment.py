#!/usr/bin/env python3
"""保留完整内存 Oracle 的断言，代入当前私有代理定义并检查128字节表对齐。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def definition(source, name):
    match = re.search(r'(?m)^struct ' + name + r' \{.*?^\};', source, flags=re.S)
    assert match, name
    return match[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    parent = json.loads((args.oracle_output / 'receipt.json').read_text())
    production = (root / 'nomount/nm_directory.c').read_text()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for item in parent['results']:
        abi = item['abi']
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        assert sha(original.encode()) == item['generated_sha256']
        source = original
        for name in ('nm_directory_proxy', 'nm_dentry_proxy'):
            source = source.replace(definition(source, name), definition(production, name), 1)
        # vzalloc夹具按页对齐；slab夹具按请求的二次幂对齐。原有失败计数与断言保持。
        source = source.replace('return calloc(1,size);', 'void* p=aligned_alloc(4096,(size+4095)&~4095UL);if(p)memset(p,0,size);return p;', 1)
        source = source.replace('aligned_alloc(64,size)', 'aligned_alloc(size,size)', 1)
        before = re.findall(r'\bassert\s*\([^;]+\);', original)
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        cursor = 0
        for assertion in before:
            cursor = after.index(assertion, cursor) + 1
        source = source.replace('int main(void){assert(!previous_memory_main());', 'static int previous_alignment_main(void){assert(!previous_memory_main());', 1)
        source += r'''
static void check_proxy_alignment(void){
 assert(_Alignof(struct nm_directory_proxy)==128&&offsetof(struct nm_directory_proxy,tables)==128);
 assert(_Alignof(struct nm_dentry_proxy)==128&&offsetof(struct nm_dentry_proxy,tables)==128);
 struct struct_offset saved=struct_offset;
 const unsigned sizes[]={192,256};
 for(unsigned n=0;n<2;n++){
  struct_offset.inode_ops_size=sizes[n];struct_offset.file_ops_size=288;
  unsigned span=nm_directory_file_table_offset();
  struct nm_directory_proxy* proxy=nm_zalloc(offsetof(struct nm_directory_proxy,tables)+span+288);
  assert(proxy&&!((uintptr_t)proxy%128)&&!((uintptr_t)proxy->tables%128));
  ((struct nm_inode_lookup_ops*)proxy->tables)->lookup=nm_directory_lookup;
  nm_set_operation_callback(proxy->tables+span,struct_offset.fop_iterate,nm_directory_iterate);
  assert(nm_directory_proxy(proxy->tables)==proxy);
  assert(nm_directory_file_proxy(proxy->tables+span)==proxy);
  nm_free(proxy);
 }
 const unsigned dsizes[]={128,192};
 for(unsigned n=0;n<2;n++){
  struct_offset.dentry_ops_size=dsizes[n];nm_dentry_proxies=NULL;
  unsigned char original[192];memset(original,0xa5,sizeof(original));
  void* table=nm_cached_dentry_table(original);assert(!IS_ERR(table));
  struct nm_dentry_proxy* proxy=nm_dentry_proxy(table);
  assert(proxy&&!((uintptr_t)proxy%128)&&!((uintptr_t)table%64));
  if(dsizes[n]==128)assert(!((uintptr_t)table%128));
  assert(!memcmp(proxy->original,original,dsizes[n]));
  assert(((unsigned char*)table)[dsizes[n]-1]==0xa5);
  assert(nm_cached_dentry_table(original)==table);
  nm_free(proxy);nm_dentry_proxies=NULL;
 }
 struct_offset=saved;
 puts("current proxy definitions: 128-byte headers, two table geometries, inverse lookup and full snapshot: PASS");
}
int main(void){assert(!previous_alignment_main());check_proxy_alignment();return 0;}
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
        assert 'runtime error:' not in run.stderr and 'ERROR: AddressSanitizer' not in run.stderr
        results.append(dict(abi=abi, parent_sha256=sha(original.encode()), assertions_preserved=len(before), generated_sha256=sha(source.encode()), stdout=run.stdout))
    (args.output / 'receipt.json').write_text(json.dumps(dict(scope='Developer host fixtures with current private proxy definitions; original assertions preserved; no native kernel execution', results=results), indent=2) + '\n')
    print('PASS: int/bool complete memory Oracle, current proxy definitions and alignment cases')


if __name__ == '__main__':
    main()
