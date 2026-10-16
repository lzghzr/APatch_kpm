#!/usr/bin/env python3
"""执行冻结上游CLI的生产解析／输出代码；系统调用由宿主夹具提供。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    upstream = root / 'nomount/nomount'
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=upstream).decode().strip()
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=upstream)
    header = (upstream / 'userspace/src/nm.h').read_text()
    body = (upstream / 'userspace/src/nm.c').read_text()
    # 仅替换架构入口／系统调用，原版参数解析和序列化函数保持字节相同。
    prefix = r'''
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
    source = prefix + header.split('/* --- DEFS --- */', 1)[1]
    source += body.replace('#include "nm.h"', '')
    source += r'''
static int requests;
static long sys1(long n,long a){assert(n==SYS_EXIT);exit((int)a);}
static long sys3(long n,long a,long b,long c){
 if(n==SYS_WRITE){assert(a==1);return fwrite((void*)b,1,c,stdout);}
 assert(n==SYS_GETCWD);assert(b>=2);*(char*)a='/';*((char*)a+1)=0;return 2;
}
static long sys5(long n,long a,long b,long c,long d,long e){
 assert(n==SYS_ADD_KEY && !strcmp((char*)a,"nomount") && !strcmp((char*)b,"trigger") && d==sizeof(unsigned long) && e==-1);
 struct nm_payload* p=(void*)*(unsigned long*)c;
 assert(p->magic==NOMOUNT_MAGIC_SIG && p->arg1==(unsigned int)requests);
 const char* mode=getenv("CLI_MODE");requests++;
 if(!strcmp(mode,"first_error") || (!strcmp(mode,"later_error")&&requests>1)){p->status=-5;return -1;}
 p->status=0;p->data_size=0;
 if(p->cmd==NM_CMD_GET_VERSION){const char text[]="0.4.1";__builtin_memcpy(p->buffer,text,5);p->data_size=5;}
 else if(p->cmd==NM_CMD_GET_ISOLATED_STATE){p->buffer[0]='1';p->buffer[1]='\n';p->data_size=2;}
 else if(requests==1 && strcmp(mode,"empty")){
  if(p->cmd==NM_CMD_GET_UIDS){unsigned int ids[]={1000,12345};__builtin_memcpy(p->buffer,ids,sizeof(ids));p->data_size=sizeof(ids);}
  else{
   assert(p->cmd==NM_CMD_GET_LIST);
   const char v[]="/system/a\"\\\n\x01";const char r[]="/data/b\"\\\t\x1f";
   unsigned short vl=sizeof(v)-1,rl=sizeof(r)-1;struct nm_rule_hdr h={0,12345,vl,rl};
   if(!strcmp(mode,"long_json"))h.v_len=h.r_len=1800;
   __builtin_memcpy(p->buffer,&h,sizeof(h));
   if(h.v_len==1800){for(int i=0;i<3600;i++)p->buffer[sizeof(h)+i]=i%2?'"':'\n';}
   else{__builtin_memcpy(p->buffer+sizeof(h),v,vl);__builtin_memcpy(p->buffer+sizeof(h)+vl,r,rl);}
   p->data_size=sizeof(h)+h.v_len+h.r_len;
  }
 }
 if(p->cmd==NM_CMD_GET_LIST || p->cmd==NM_CMD_GET_UIDS)p->arg1=requests;
 return 0;
}
int main(int argc,char** argv){
 _Static_assert(sizeof(struct nm_payload)==4096,"payload");
 _Static_assert(offsetof(struct nm_payload,buffer)==28,"buffer");
 _Static_assert(sizeof(struct nm_rule_hdr)==12 && sizeof(struct nm_del_hdr)==6,"records");
 long* sp=malloc((argc+2)*sizeof(long));assert(sp);sp[0]=argc;
 for(int i=0;i<argc;i++)sp[i+1]=(long)argv[i];sp[argc+1]=0;c_main(sp);
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    c = args.output / 'cli.c'
    c.write_text(source)
    binary = args.output / 'cli'
    built = subprocess.run(['/usr/bin/clang', '-fno-builtin', '-Wno-unused-function', '-fsanitize=address,undefined', '-g', str(c), '-o', str(binary)], capture_output=True, text=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    results = []
    for command in (['rule', 'list'], ['rule', 'list', '--json'], ['uid', 'list']):
        for mode, expected in [('first_error', 1), ('later_error', 1), ('empty', 0), ('ready', 0)]:
            run = subprocess.run([str(binary), *command], env=dict(os.environ, CLI_MODE=mode, ASAN_OPTIONS='detect_leaks=0'), capture_output=True, text=True)
            assert run.returncode == expected and not run.stderr, (command, mode, run.stdout, run.stderr)
            if command != ['rule', 'list']:
                value = json.loads(run.stdout)
                if mode in ('first_error', 'empty'): assert value == []
                elif command == ['uid', 'list']: assert value == [1000, 12345]
                else:
                    assert value == [{'virtual': '/system/a"\\\n\x01', 'real': '/data/b"\\\t\x1f', 'uid': 12345}]
            results.append({'command': command, 'mode': mode, 'exit': run.returncode})
    for command, expected in [(['version'], '0.4.1\n'), (['uid', 'block_isolated'], '1\n')]:
        run = subprocess.run([str(binary), *command], env=dict(os.environ, CLI_MODE='ready', ASAN_OPTIONS='detect_leaks=0'), capture_output=True, text=True)
        assert run.returncode == 0 and run.stdout == expected and not run.stderr
        results.append({'command': command, 'mode': 'ready', 'exit': 0})
    run = subprocess.run([str(binary), 'rule', 'list', '--json'], env=dict(os.environ, CLI_MODE='long_json', ASAN_OPTIONS='detect_leaks=0'), capture_output=True, text=True)
    value = json.loads(run.stdout)
    assert not run.returncode and not run.stderr and value[0]['virtual'] == '\n"'*900 and value[0]['real'] == '\n"'*900
    results.append({'command': ['rule', 'list', '--json'], 'mode': 'long_json', 'exit': 0})
    receipt = {'scope': 'Developer CLI host syscall fixtures; not native keyring or Android proof', 'upstream_commit': commit,
               'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in [upstream / 'userspace/src/nm.c', upstream / 'userspace/src/nm.h', Path(__file__)]},
               'generated_source_sha256': sha(source.encode()), 'cases': results}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Upstream CLI: 15 cases PASS (errors, JSON escaping and flush, protocol probes)')


if __name__ == '__main__':
    main()
