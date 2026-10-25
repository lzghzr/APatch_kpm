#!/usr/bin/env python3
"""在已验证的 v22 双 ABI 夹具中接入本批生产函数；原 assert 表达式与顺序保持。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from test_directory_abis import function
from test_file_control import run


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-output',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[2]
    run([sys.executable,'-B',str(root/'nomount/tools/test_v22_sync.py'),'--oracle-output',str(a.oracle_output),'--output',str(a.output/'v22-base')],a.output/'base.log')
    rows=[]
    for abi in ('int','bool'):
        source=(a.output/'v22-base'/abi/'contracts.c').read_text();original=source
        block=re.search(r'#ifndef __NM_STRUCTS_H\b.*?#endif',source,re.S);assert block
        header=(root/'nomount/nm_structs.h').read_text()
        source=source[:block.start()]+header[header.index('#ifndef '):]+source[block.end():]
        before=function(source,'nm_validate_file_offsets')
        source=source.replace(before,function((root/'nomount/nm_offsets.c').read_text(),'nm_validate_file_offsets'),1)
        current=(root/'nomount/nm_file.c').read_text()
        names=['nm_ioctl','nm_compat_ioctl','nm_fsync','nm_validate_file_control_offsets','nm_new_file_operations']
        source=source.replace(function(source,'nm_new_file_operations'),'\n'.join(function(current,n) for n in names),1)
        assertions=re.findall(r'\bassert\s*\([^;]+\);',original)
        assert re.findall(r'\bassert\s*\([^;]+\);',source)==assertions
        out=a.output/abi;out.mkdir();(out/'contracts.c').write_text(source)
        run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-invalid-noreturn','-fno-builtin','-I',str(root/'nomount'),'-fsanitize=address,undefined','-g',str(out/'contracts.c'),str(a.output/'v22-base/cli.c'),'-o',str(out/'contracts')],out/'compile.log')
        run([str((out/'contracts').resolve())],out/'run.log')
        rows.append({'abi':abi,'assertions_unchanged_from_v22_generated_fixture':len(assertions),'result':'PASS'})
    (a.output/'receipt.json').write_text(json.dumps({'scope':'Developer affected production functions in frozen host fixtures; retains explicit prior v22 version/input migration; not current full-source or concurrency proof','results':rows},indent=2)+'\n')
    print(json.dumps(rows,indent=2))


if __name__=='__main__':main()
