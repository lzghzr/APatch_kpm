#!/usr/bin/env python3
"""协议回归共用的冻结 CLI 夹具；由 test_nomount_protocol23.py 配置后调用。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#define SYS_GETCWD 17
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_EXIT 93
#define SYS_ADD_KEY 217
static long sys1(long,long);
static long sys3(long,long,long,long);
static long sys5(long,long,long,long,long,long);
'''
POST = r'''
static unsigned requests,added;
static long sys1(long n,long a){assert(n==SYS_EXIT);if(getenv("CLI_EXPECT_ADD"))assert(added==(unsigned)atoi(getenv("CLI_EXPECT_ADD")));exit((int)a);}
static long sys3(long n,long a,long b,long c){
 if(n==SYS_WRITE)return fwrite((void*)b,1,c,a==2?stderr:stdout);
 assert(n==SYS_GETCWD);__builtin_memcpy((void*)a,"/cwd",5);return 5;
}
static long sys5(long n,long a,long b,long c,long d,long e){
 assert(n==SYS_ADD_KEY&&!strcmp((char*)a,"nomount")&&d==sizeof(unsigned long));
 struct nm_payload*p=(void*)*(unsigned long*)c;const char*mode=getenv("CLI_MODE");
 assert(p->magic==NOMOUNT_MAGIC_SIG);p->status=0;
 if(p->cmd==NM_CMD_GET_VERSION){const char*v=!strcmp(mode,"wrong_version")?"23":"22 (KPM fixture)";
 unsigned len=0;while(v[len])len++;__builtin_memcpy(p->buffer,v,len);p->data_size=len;return 0;}
 requests++;
 if(!strcmp(mode,"error")||(!strcmp(mode,"later_error")&&requests==2)){p->status=-5;return -1;}
 if(p->cmd==NM_CMD_ADD_RULE||p->cmd==NM_CMD_DEL_RULE){
  unsigned off=0;while(off<p->data_size){
   if(p->cmd==NM_CMD_ADD_RULE){struct nm_rule_hdr*h=(void*)(p->buffer+off);
    assert(h->v_len&&h->r_len);if(!strcmp(mode,"default_deny"))assert(!h->uid&&!h->uid_end&&h->deny_start==100&&h->deny_end==200);
    off+=sizeof(*h)+h->v_len+h->r_len;
   }else{struct nm_del_hdr*h=(void*)(p->buffer+off);assert(h->v_len);off+=sizeof(*h)+h->v_len;}
   added++;
  }
  assert(off==p->data_size);p->arg1=off;return 0;
 }
 assert(p->arg1==requests-1);p->data_size=0;
 if(requests==1&&strcmp(mode,"empty")){
  if(p->cmd==NM_CMD_GET_UIDS){unsigned ids[]={1000,12345};__builtin_memcpy(p->buffer,ids,sizeof(ids));p->data_size=sizeof(ids);}
  else {assert(p->cmd==NM_CMD_GET_LIST);const char v[]="/system/a\"\\\n",r[]="/data/b\t\x1f";
   struct nm_rule_hdr h={.v_len=sizeof(v)-1,.r_len=sizeof(r)-1,.uid=100,.uid_end=200,.deny_start=150,.deny_end=160};
   __builtin_memcpy(p->buffer,&h,sizeof(h));__builtin_memcpy(p->buffer+sizeof(h),v,h.v_len);
   __builtin_memcpy(p->buffer+sizeof(h)+h.v_len,r,h.r_len);p->data_size=sizeof(h)+h.v_len+h.r_len;
  }
 }
 p->arg1=!strcmp(mode,"terminal")?~0U:requests;return 0;
}
int main(int argc,char**argv){
 _Static_assert(sizeof(struct nm_payload)==4096&&sizeof(struct nm_rule_hdr)==24&&sizeof(struct nm_del_hdr)==18,"wire ABI");
 long sp[argc+2];sp[0]=argc;for(int i=0;i<argc;i++)sp[i+1]=(long)argv[i];sp[argc+1]=0;c_main(sp);
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('build_zip', ROOT / 'nomount/tools/build_zip.py')
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    upstream = ROOT / 'nomount/upstream/nomount/userspace/src'
    from nomount_libc_fixture import compose
    source = compose(PRE, (upstream / 'nm.h').read_text(),
                     adapter.adapt_cli((upstream / 'nm.c').read_text()), POST)
    c = args.output / 'cli.c'
    c.write_text(source)
    binary = args.output / 'cli'
    result = subprocess.run(['/usr/bin/clang', '-fno-builtin', '-fsanitize=address,undefined', '-g', str(c), '-o', str(binary)], capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    cases = []
    for cmd in (['rule', 'list', '--json'], ['uid', 'list']):
        for mode in ('ready', 'terminal', 'empty', 'error', 'later_error', 'wrong_version'):
            result = subprocess.run([str(binary), *cmd], env=dict(os.environ, CLI_MODE=mode), text=True, capture_output=True)
            (args.output / f'{cmd[0]}-{mode}.log').write_text(result.stdout + result.stderr)
            assert result.returncode == (1 if mode in ('error', 'later_error', 'wrong_version') else 0)
            if not result.returncode:
                values = json.loads(result.stdout)
                assert len(values) == (0 if mode == 'empty' else 1 if cmd[0] == 'rule' else 2)
                if values and cmd[0] == 'rule':
                    assert values[0]['virtual'] == '/system/a"\\\n' and values[0]['deny_end'] == 160
            cases.append([cmd, mode, result.returncode])
    for cmd, mode, expected in [(['rule', 'add', '/v', '/r', '--uid-excluded', '100-200'], 'default_deny', 0),
                                (['rule', 'add', '/v', '/r', '--uid-range', '100-200', '--uid-excluded', '50-150'], 'ready', 1),
                                (['rule', 'add', '/v', '/r', '--whiteout', '--opaque'], 'ready', 1),
                                (['rule', 'add', 'relative', '/real'], 'ready', 0),
                                (['rule', 'add', '/v', '/r'], 'error', 1),
                                (['rule', 'del', '/v'], 'ready', 0)]:
        result = subprocess.run([str(binary), *cmd], env=dict(os.environ, CLI_MODE=mode), text=True, capture_output=True)
        assert result.returncode == expected, (cmd, result.stdout, result.stderr)
        cases.append([cmd, mode, result.returncode])
    paths = [path for i in range(300) for path in (f'/virtual/{i}', '/backing/' + 'x' * 900)]
    result = subprocess.run([str(binary), 'rule', 'add', *paths], env=dict(os.environ, CLI_MODE='ready', CLI_EXPECT_ADD='300'), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    cases.append(['multi-payload-300-pairs', 'ready', result.returncode])
    (args.output / 'receipt.json').write_text(json.dumps(cases, indent=2) + '\n')
    print(f'{len(cases)} CLI wire/list/serialization/error cases PASS')
