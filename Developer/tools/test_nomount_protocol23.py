#!/usr/bin/env python3
"""协议 22/23 四格、冻结 CLI Oracle 迁移和真实 common.sh 只读探测。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

from test_nomount_v230 import ROOT
import nomount_cli_fixture as oracle


def load_adapter():
    spec=importlib.util.spec_from_file_location('zip_adapter',ROOT/'nomount/tools/build_zip.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def build(body, header, post, output):
    from nomount_libc_fixture import compose
    source=compose(oracle.PRE,header,body,post)
    output.with_suffix('.c').write_text(source)
    result=subprocess.run(['/usr/bin/clang','-fno-builtin','-fsanitize=address,undefined','-g',str(output.with_suffix('.c')),'-o',str(output)],capture_output=True,text=True)
    output.with_suffix('.compile.log').write_text(result.stdout+result.stderr);result.check_returncode()


def invoke(binary, args, version, **extra):
    env=dict(os.environ,CLI_MODE='ready',CLI_DRIVER_VERSION=version,**extra)
    return subprocess.run([str(binary),*args],env=env,text=True,capture_output=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--old-zip',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    # Deliberate contract migration: the rejected version fixture moves 23 -> 24.
    # All pre-existing assertions and test branches are retained; 23 is positively exercised below.
    original=oracle.POST
    post=original.replace('"23":"22 (KPM fixture)"', '"24":getenv("CLI_DRIVER_VERSION")')
    assert post!=original
    post=post.replace('if(p->cmd==NM_CMD_GET_VERSION){', '''if(p->cmd==NM_CMD_GET_VERSION){
 if(getenv("CLI_PROBE_ERROR")){p->status=-5;return -1;}
 if(getenv("CLI_PROBE_SIZE")){p->data_size=atoi(getenv("CLI_PROBE_SIZE"));return 0;}
 ''',1)
    post=post.replace(' requests++;', ''' requests++;
 if(p->cmd==NM_CMD_GET_ISOLATED_STATE){p->buffer[0]='0';p->buffer[1]='\\n';p->data_size=2;return 0;}
 ''',1)
    assert re.findall(r'\bassert\s*\([^;]+\);',original)==re.findall(r'\bassert\s*\([^;]+\);',post)
    oracle.POST=post
    for version in ('22','23'):
        os.environ['CLI_DRIVER_VERSION']=version
        sys.argv=['nomount_cli_fixture.py','--output',str(out/('oracle-'+version))]
        oracle.main()
    del os.environ['CLI_DRIVER_VERSION']
    adapter=load_adapter();upstream=ROOT/'nomount/upstream/nomount/userspace/src'
    new=out/'new-cli';old=out/'old-cli'
    build(adapter.adapt_cli((upstream/'nm.c').read_text()),(upstream/'nm.h').read_text(),post,new)
    with zipfile.ZipFile(args.old_zip) as z:
        build(z.read('sources/nm.c').decode(),z.read('sources/nm.h').decode(),post,old)
    cases=[]
    for version in ('22','23'):
        for name,binary in [('old',old),('new',new)]:
            r=invoke(binary,['rule','add','/v','/r'],version,CLI_EXPECT_ADD='0' if name=='old' and version=='23' else '1')
            expected=1 if name=='old' and version=='23' else 0
            assert r.returncode==expected,(name,version,r.stdout,r.stderr)
            cases.append({'cli':name,'kpm_version':version,'exit':r.returncode,'output':r.stdout+r.stderr})
    for version in ('21','24','230','23x','2','', ' 23','23\ninvalid'):
        r=invoke(new,['rule','add','/v','/r'],version,CLI_EXPECT_ADD='0')
        assert r.returncode==1 and 'v22 or v23 required' in r.stdout,(version,r)
        cases.append({'rejected':version,'exit':r.returncode})
    for extra in ({'CLI_PROBE_SIZE':'0'},{'CLI_PROBE_SIZE':'1'},{'CLI_PROBE_SIZE':'4069'},{'CLI_PROBE_ERROR':'1'}):
        r=invoke(new,['rule','add','/v','/r'],'23',CLI_EXPECT_ADD='0',**extra);assert r.returncode==1
        cases.append({'probe_error':extra,'exit':r.returncode})
    common=ROOT/'nomount/module/common.sh'
    for version in ('22','23','24'):
        env=dict(os.environ,CLI_MODE='ready',CLI_DRIVER_VERSION=version)
        result=subprocess.run(['/bin/sh','-c','. "$1"; NM_BIN="$2"; nm_check_api','check',str(common),str(new)],env=env,text=True,capture_output=True)
        assert result.returncode==(1 if version=='24' else 0),(version,result.stdout,result.stderr)
        cases.append({'common_driver':version,'exit':result.returncode})
    (out/'receipt.json').write_text(json.dumps({'old_zip':str(args.old_zip),'oracle_contract_change':'wrong_version fixture 23 -> 24; original assertions retained; full 19 cases run against 22 and 23','cases':cases},ensure_ascii=False,indent=2)+'\n')
    print('PASS 38 preserved CLI cases +',len(cases),'matrix/unknown/malformed/common checks')


if __name__=='__main__':main()
