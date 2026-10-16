#!/usr/bin/env python3
"""验证原生内存依赖缺失拒绝，并记录已有7目标的函数符号。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

TARGETS = {
 'B2N-416G': 'local/zram-kernel-compat-20261011-01/B2N-416G_boot.img/symbols.json',
 'boot_los23.2': 'local/nomount-port-20261012/inspection-02/symbols.json',
 'boot_67.2.A.3.178': 'local/zram-kernel-compat-20261011-01/boot_67.2.A.3.178.img/symbols.json',
 'kernel_android13-5.10': 'local/zram-kernel-compat-20261011-01/kernel_android13-5.10/symbols.json',
 'kernel_android13-5.15': 'local/zram-kernel-compat-20261011-01/kernel_android13-5.15/symbols.json',
 'kernel_android14-5.15': 'local/zram-kernel-compat-20261011-01/kernel_android14-5.15/symbols.json',
 'kernel_android14-6.1': 'local/zram-kernel-compat-20261011-01/kernel_android14-6.1/symbols.json',
}
SYMBOLS = ['__kmalloc', 'kvfree', 'is_vmalloc_addr', 'vfree_atomic', 'path_get']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    a.output.mkdir(parents=True, exist_ok=False)
    native = (root / 'nomount/nm_native.c').read_text().split('#include "nm_memory.c"')[0]
    required = re.findall(r'  NM_NATIVE_LOOKUP\(\w+, (\w+)\);', native)
    source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#define __user
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define pr_err(...) ((void)0)
struct rcu_head;
struct nm_dir_context;
typedef void (*rcu_callback_t)(struct rcu_head*);
static const char* missing;
static unsigned long kallsyms_lookup_name_by_suffix(const char* name){return missing&&!strcmp(missing,name)?0:1;}
''' + native
    source += '\nint main(void){assert(!nm_prepare_native());\n'
    for symbol in required:
        source += 'missing="' + symbol + '";assert(nm_prepare_native()==-ENOENT);\n'
    source += 'missing=NULL;assert(!nm_prepare_native());return 0;}\n'
    c = a.output / 'native.c'
    c.write_text(source)
    subprocess.run(['/usr/bin/clang','-Wall','-Werror',str(c),'-o',str(a.output/'native')],check=True)
    subprocess.run([str(a.output/'native')],check=True)
    targets = []
    for name, path in TARGETS.items():
        raw = (root / path).read_bytes()
        rows = json.loads(raw)
        addresses = {symbol:[hex(address) for address, kind, entry in rows if entry==symbol and kind.lower()=='t'] for symbol in SYMBOLS}
        assert all(addresses.values()), (name,addresses)
        targets.append(dict(target=name,symbols_input=path,input_sha256=hashlib.sha256(raw).hexdigest(),addresses=addresses))
    (a.output/'receipt.json').write_text(json.dumps(dict(scope='Developer dependency rejection and exact target symbol presence; not function ABI/runtime proof',required_missing_rejected=required,targets=targets),indent=2)+'\n')
    print(str(len(required))+' missing native dependencies rejected; target symbols 7/7: PASS')

if __name__=='__main__':
    main()
