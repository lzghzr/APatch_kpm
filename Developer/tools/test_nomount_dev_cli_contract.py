#!/usr/bin/env python3
"""上游 dev CLI 的迁移反例：真实目录扫描与故障注入；只调用宿主文件系统。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from test_nomount_v230 import ROOT

UPSTREAM='611f2420abfd49c716e7e1ca685a7b6143eb2cae'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 h=subprocess.check_output(['git','-C',str(ROOT/'nomount/upstream/nomount'),'show',UPSTREAM+':userspace/src/nm.h'],text=True)
 start=h.index('static noinline int nm_send_payload(');end=h.index('\n/* --- module walk helpers --- */',start)
 h=h[:start]+'''static unsigned payload_calls;
static int nm_send_payload(struct nm_payload*p){payload_calls++;return -5;}
'''+h[end:]
 source=h+r'''
#include <assert.h>
#include <stdio.h>
int main(int argc,char**argv){
 assert(argc==2);struct nm_workspace ws={0};
 struct nm_walk ctx={.payload=&ws.payload};ctx.cursor=ws.payload.buffer;ctx.end=ctx.cursor+sizeof(ws.payload.buffer);
 char missing[PATH_MAX];assert(!nm_path_join(missing,sizeof(missing),argv[1],"missing"));
 int missing_rc=walk_load(&ctx,missing,"system/missing");assert(missing_rc==0);
 int rc=walk_load(&ctx,argv[1],"system/etc");assert(rc==-1&&payload_calls==1&&ctx.count<128);
 printf("{\"unreadable_directory_rc\":%d,\"first_payload_error_rc\":%d,\"files_total\":128,\"records_before_stop\":%d,\"payload_calls\":%u}\n",missing_rc,rc,ctx.count,payload_calls);
 return 0;
}
'''
 (out/'probe.c').write_text(source)
 cmd=['/usr/bin/clang','-Wno-macro-redefined','-Wno-deprecated-declarations','-fsanitize=address,undefined',str(out/'probe.c'),'-o',str(out/'probe')]
 r=subprocess.run(cmd,text=True,capture_output=True);(out/'compile.log').write_text(r.stdout+r.stderr);r.check_returncode()
 files=out/'files';files.mkdir()
 for i in range(128):(files/f'{i:03}.conf').write_text('fixture')
 r=subprocess.run([str(out/'probe'),str(files)],text=True,capture_output=True);(out/'run.log').write_text(r.stdout+r.stderr);r.check_returncode()
 receipt={'upstream_commit':UPSTREAM,'boundary':'production walk_load; nm_send_payload only is injected as EIO; host files, no device','observed':json.loads(r.stdout)}
 (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,ensure_ascii=False))
if __name__=='__main__':main()
