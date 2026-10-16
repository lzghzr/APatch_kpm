#!/usr/bin/env python3
"""核对拓扑缓存接口的目标声明和 BTF 调用 ABI，保留既有目录布局 Oracle。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('headers','target-header','dcache-header','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True,exist_ok=False)
    subprocess.run([sys.executable,str(root/'nomount/tools/test_virtual_directory_layout.py'),
                    '--headers',str(args.headers),'--target-header',str(args.target_header),
                    '--output',str(args.output/'virtual-layout-contract')],check=True)
    header=args.dcache_header.read_text()
    declarations=[re.search(r'extern\s+[^;{}]*?\b'+name+r'\s*\([^;{}]*?;',header,re.S)[0]
                  for name in ('d_hash_and_lookup','shrink_dcache_parent')]
    source='struct dentry;struct qstr;\n'+'\n'.join(declarations)+r'''
_Static_assert(__builtin_types_compatible_p(typeof(&d_hash_and_lookup),struct dentry* (*)(struct dentry*,struct qstr*)),"d_hash_and_lookup ABI");
_Static_assert(__builtin_types_compatible_p(typeof(&shrink_dcache_parent),void (*)(struct dentry*)),"shrink_dcache_parent ABI");
'''
    c=args.output/'native.c';c.write_text(source)
    compiled=subprocess.run(['/usr/bin/clang','--target=aarch64-none-elf','-Wall','-Werror','-c',str(c),'-o',str(args.output/'native.o')],text=True,capture_output=True)
    (args.output/'native.log').write_text(compiled.stdout+compiled.stderr);compiled.check_returncode()
    spec=importlib.util.spec_from_file_location('btf_host',root/'re_kernel/tools/test_btf.py')
    host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    b=host.Btf();pointer=b.add('',2,0);integer=b.add('u32',1,4,struct.pack('<I',32))
    def function(name,args,result):
        proto=b.add('',13,result,b''.join(struct.pack('<II',b.name('arg'+str(i)),t) for i,t in enumerate(args)),len(args))
        return b.add(name,12,proto)
    lookup=function('d_hash_and_lookup',[pointer,pointer],pointer)
    shrink=function('shrink_dcache_parent',[pointer],0)
    blob=b.data();records,strings=host.index_btf(blob)
    source=(args.output/'virtual-layout-contract/btf.c').read_text().split('int main(int argc,char** argv)',1)[0]
    source=re.sub(r'static const u32 records\[\] = \{[^}]*\};','static const u32 records[] = {'+','.join(map(str,records))+'};',source)
    source=re.sub(r'static const u32 string_start=\d+,string_length=\d+;',f'static const u32 string_start={strings},string_length={len(blob)-strings};',source)
    source+=r'''
int main(int argc,char** argv) {
 assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);
 assert(!calculate_btf_topology_abi());
 struct kpm_btf btf={&object,host_find,host_type,host_name,host_size};
 struct btf_type* function=(void*)kpm_btf_type(&btf,"d_hash_and_lookup",12);
 struct btf_type* proto=(void*)host_type(&object,function->size);u32 count=proto->info;
 proto->info=(13U<<24)|1;assert(calculate_btf_topology_abi()==-EOPNOTSUPP);proto->info=count;
'''
    source+=f'u32 result=proto->size;proto->size={integer};assert(calculate_btf_topology_abi()==-EOPNOTSUPP);proto->size=result;\n'
    source+=r'''
 u32 name=function->name_off;function->name_off=0;assert(calculate_btf_topology_abi()==-ENOENT);function->name_off=name;
 function=(void*)kpm_btf_type(&btf,"shrink_dcache_parent",12);proto=(void*)host_type(&object,function->size);
'''
    source+=f'proto->size={integer};assert(calculate_btf_topology_abi()==-EOPNOTSUPP);proto->size=0;\n'
    source+=r'''
 assert(!calculate_btf_topology_abi());free(blob);
 puts("target dcache function declarations and topology BTF ABI boundaries: PASS");return 0;
}
'''
    c=args.output/'btf.c';c.write_text(source);(args.output/'synthetic.btf').write_bytes(blob)
    compiled=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'btf')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(compiled.stdout+compiled.stderr);compiled.check_returncode()
    run=subprocess.run([str(args.output/'btf'),str(args.output/'synthetic.btf')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'Developer target declarations and synthetic BTF; not native dcache or namespace behavior',
             'sources':{'nomount/nm_btf.c':sha(root/'nomount/nm_btf.c')},'tool_sha256':sha(Path(__file__)),
             'dcache_header_sha256':sha(args.dcache_header),'native_reference_source_sha256':sha(args.output/'native.c'),
             'virtual_layout_receipt_sha256':sha(args.output/'virtual-layout-contract/receipt.json'),
             'synthetic_btf_sha256':sha(args.output/'synthetic.btf'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__=='__main__':main()
