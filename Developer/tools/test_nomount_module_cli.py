#!/usr/bin/env python3
"""Run adapted upstream module CLI on host directories; keyring and Android-only boundaries are fixtures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'nomount/tools'))
import build_zip

PRE=r'''
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>
static int fixture_stat(const char*p,struct stat*s){
 if(!strcmp(p,"/system")||!strcmp(p,"/vendor")){memset(s,0,sizeof(*s));s->st_mode=S_IFDIR|0755;return 0;}
 return stat(p,s);
}
static int fixture_lstat(const char*p,struct stat*s){int rc=lstat(p,s);const char*n=strrchr(p,'/');
 if(!rc&&n&&!strcmp(n+1,"char-whiteout"))s->st_mode=S_IFCHR|0600;return rc;}
static DIR*fixture_opendir(const char*p){
 if(getenv("SCAN_FAIL")&&strstr(p,"/badscan")){errno=EACCES;return NULL;}return opendir(p);
}
static ssize_t fixture_getxattr(const char*p,const char*n,void*v,size_t z){
 if(getenv("XATTR_SCAN_FAIL")&&strstr(p,"/badscan")){errno=EIO;return -1;}
 ssize_t rc=getxattr(p,"user.nomount-fixture-opaque",v,z,0,0);if(rc<0&&errno==ENOATTR)errno=ENODATA;return rc;
}
/* Native boundary moved from path APIs to openat/fstatat/fgetxattr upstream. */
static int fixture_openat(int fd,const char*p,int flags){
 if(getenv("SCAN_FAIL")&&strstr(p,"badscan")){errno=EACCES;return -1;}return openat(fd,p,flags);
}
static int fixture_fstatat(int fd,const char*p,struct stat*s,int flags){
 int rc=fstatat(fd,p,s,flags);const char*n=strrchr(p,'/');n=n?n+1:p;
 if(!rc&&!strcmp(n,"char-whiteout"))s->st_mode=S_IFCHR|0600;return rc;
}
static struct dirent*fixture_readdir(DIR*d){
 struct dirent*e=readdir(d);if(e&&!strcmp(e->d_name,"char-whiteout"))e->d_type=DT_CHR;return e;
}
static ssize_t fixture_fgetxattr(int fd,const char*n,void*v,size_t z){
 char path[PATH_MAX];if(fcntl(fd,F_GETPATH,path)<0)return -1;return fixture_getxattr(path,n,v,z);
}
#define openat(...) fixture_openat(__VA_ARGS__)
#define fstatat(...) fixture_fstatat(__VA_ARGS__)
#define readdir(...) fixture_readdir(__VA_ARGS__)
#define fgetxattr(...) fixture_fgetxattr(__VA_ARGS__)
#define stat(...) fixture_stat(__VA_ARGS__)
#define lstat(...) fixture_lstat(__VA_ARGS__)
#define opendir(...) fixture_opendir(__VA_ARGS__)
#define getxattr(...) fixture_getxattr(__VA_ARGS__)
#undef PATH_MAX
struct nm_payload;
static int fixture_send(struct nm_payload*);
'''
POST=r'''
static unsigned batches;
static int fixture_send(struct nm_payload*p){
 if(p->magic!=NOMOUNT_MAGIC_SIG)abort();
 if(p->cmd==NM_CMD_GET_VERSION){const char*v=getenv("VERSION");if(!v)v="23";
 p->data_size=strlen(v);memcpy(p->buffer,v,p->data_size);return 0;}
 if(p->cmd==NM_CMD_GET_ISOLATED_STATE){p->buffer[0]='0';p->data_size=1;return 0;}
 if(p->cmd==NM_CMD_ADD_RULE||p->cmd==NM_CMD_DEL_RULE){
  FILE*f=fopen(getenv("CAPTURE"),"ab");if(!f)abort();
  uint32_t head[]={p->cmd,p->data_size};fwrite(head,4,2,f);fwrite(p->buffer,1,p->data_size,f);fclose(f);
  batches++;p->arg1=p->data_size;
  return getenv("FAIL_BATCH")&&batches==(unsigned)atoi(getenv("FAIL_BATCH"))?-5:0;
 }
 if(p->cmd==NM_CMD_GET_LIST){
  if(getenv("LIST_ERROR")&&p->arg1==1)return -5;
  if(p->arg1){p->data_size=0;p->arg1=~0U;return 0;}
  p->arg1=1;p->data_size=0;
  if(getenv("RULE_PAGE")){FILE*f=fopen(getenv("RULE_PAGE"),"rb");if(!f)abort();p->data_size=fread(p->buffer,1,sizeof(p->buffer),f);fclose(f);}
  if(getenv("LIST_MALFORMED")){p->data_size=1;p->buffer[0]=0;}
  return 0;
 }
 return -22;
}
'''

def function_span(s,name):
 m=re.search(r'(?m)^static [^\n]*\b'+name+r'\([^;]*?\)\s*\{',s);assert m,name
 i=m.end();depth=1
 while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return m.start(),i

def build(out):
 h=build_zip.adapt_cli_header((ROOT/'nomount/upstream/nomount/userspace/src/nm.h').read_text())
 a,b=function_span(h,'nm_send_payload');h=h[:a]+'static int nm_send_payload(struct nm_payload*p){return fixture_send(p);}\n'+h[b:]
 h=h[h.index('/* --- DEFS --- */'):].replace('#endif // #ifndef NM_H','')
 h=h.replace('static const char *modules_dir = "/data/adb/modules";', 'const char *modules_dir = getenv("MODULES");')
 c=build_zip.adapt_cli((ROOT/'nomount/upstream/nomount/userspace/src/nm.c').read_text()).replace('#include "nm.h"','')
 (out/'cli.c').write_text(PRE+h+c+POST)
 r=subprocess.run(['/usr/bin/clang','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=address,undefined','-g',str(out/'cli.c'),'-o',str(out/'cli')],capture_output=True,text=True)
 (out/'compile.log').write_text(r.stdout+r.stderr);r.check_returncode()

def records(path):
 data=path.read_bytes() if path.exists() else b'';off=0;items=[]
 while off<len(data):
  cmd,size=struct.unpack_from('<II',data,off);off+=8;end=off+size
  while off<end:
   if cmd==2:
    flags,uid,uid_end,deny,deny_end,vlen,rlen=struct.unpack_from('<IIIIIHH',data,off);off+=24
   else:
    uid,uid_end,deny,deny_end,vlen=struct.unpack_from('<IIIIH',data,off);off+=18;flags=0;rlen=0
   v=data[off:off+vlen].decode();off+=vlen;r=data[off:off+rlen].decode();off+=rlen
   items.append(dict(cmd=cmd,flags=flags,uid=uid,uid_end=uid_end,deny=deny,deny_end=deny_end,v=v,r=r))
  assert off==end
 return items

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);build(out)
 modules=out/'modules';modules.mkdir();cases=[]
 def file(path,text='data'):
  path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);return path
 def call(label,args,expected=0,**env):
  cap=out/(label+'.bin');r=subprocess.run([str(out/'cli'),*args],env=dict(os.environ,MODULES=str(modules),CAPTURE=str(cap),**env),capture_output=True,text=True,timeout=30)
  (out/(label+'.log')).write_text(r.stdout+r.stderr);assert r.returncode==expected,(label,r.returncode,r.stdout,r.stderr)
  rows=records(cap);cases.append({'case':label,'exit':r.returncode,'rules_attempted':len(rows)});return r,rows
 mod=modules/"example' quote";file(mod/'module.prop','name=中文 🧩 "quoted"\n')
 for i in range(128):file(mod/f'system/etc/{i:03}.conf')
 r,rows=call('plain',['module','load',str(mod)]);assert len(rows)==128 and len({v['v'] for v in rows})==128
 for fail in ('1','2'):
  r,rows=call('fail-'+fail,['module','load',str(mod)],1,FAIL_BATCH=fail)
  assert len(rows)==128 and len({v['v'] for v in rows})==128
 file(mod/'system/badscan/x');file(mod/'vendor/end')
 r,rows=call('scan-fail',['module','load',str(mod),'--targets= system  vendor '],1,SCAN_FAIL='1');assert len(rows)==129 and any(v['v']=='/vendor/end' for v in rows)
 r,rows=call('xattr-scan-fail',['module','load',str(mod),'--targets=system vendor'],1,XATTR_SCAN_FAIL='1');assert len(rows)==130 and any(v['v']=='/system/badscan/x' for v in rows) and any(v['v']=='/vendor/end' for v in rows)
 file(mod/'system/empty/.replace');file(mod/'system/opaque/.replace');file(mod/'system/opaque/x');file(mod/'system/remove/.remove');file(mod/'system/char-whiteout')
 file(mod/'system/xopaque/x');subprocess.run(['xattr','-w','user.nomount-fixture-opaque','y',str(mod/'system/xopaque')],check=True)
 file(mod/'system/xempty/seed').unlink();subprocess.run(['xattr','-w','user.nomount-fixture-opaque','y',str(mod/'system/xempty')],check=True)
 file(mod/'system/vendor/mapped')
 external=out/'external';file(external/'x');(mod/'system/alias').symlink_to(external,target_is_directory=True)
 (mod/'system/alias2').symlink_to(external,target_is_directory=True)
 (mod/'system/relative').symlink_to('etc/000.conf');(mod/'system/broken').symlink_to('gone')
 file(mod/'system/space newline\nquoted"file')
 r,rows=call('features',['module','load',str(mod),'--uid-excluded','100-200'])
 bypath={v['v']:v for v in rows}
 for v in ('/system/empty','/system/remove','/system/char-whiteout','/system/xempty'):assert bypath[v]['flags']==4
 for v in ('/system/opaque','/system/xopaque'):assert bypath[v]['flags']==8
 for v in ('/system/alias/x','/system/alias2/x','/system/relative','/system/broken','/vendor/mapped'):assert v in bypath
 assert all(v['uid']==0 and v['deny']==100 and v['deny_end']==200 for v in rows)
 r,deleted=call('unload',['module','unload',str(mod),'--uid-excluded','100-200']);assert set(bypath)<={v['v'] for v in deleted}
 assert all(v['deny']==100 and v['deny_end']==200 for v in deleted)
 (mod/'system/cycle').symlink_to('.',target_is_directory=True)
 r,rows=call('cycle',['module','load',str(mod)],1);assert '/vendor/end' in {v['v'] for v in rows};assert len(rows)<200
 call('cycle-unload',['module','unload',str(mod)],1);(mod/'system/cycle').unlink()
 for i in range(65):file(modules/f'mod{i:03}'/'system/etc/x');file(modules/f'mod{i:03}'/'module.prop',f'name=Module {i}\n')
 page=out/'page';v=b'/system/relative';real=str(mod/'system/relative').encode();page.write_bytes(struct.pack('<IIIIIHH',0,0,0,0,0,len(v),len(real))+v+real)
 r,_=call('list',['module','list','--json'],RULE_PAGE=str(page));data=json.loads(r.stdout);data['links']=[dict(link,modId=m['modId']) for m in data['mods'] for link in m['links']];assert len(data['mods'])==66
 assert any(m['realName']=='中文 🧩 "quoted"' for m in data['mods'])
 link=next(v for v in data['links'] if v['virtual']=='/system/relative');assert link['real']==str((mod/'system/etc/000.conf').resolve())
 assert any(v['virtual']=='/system/alias' and v['dir'] for v in data['links'])
 longid='module-'+('x'*90);file(modules/longid/'module.prop','name=Long ID\n');(modules/longid/'system').symlink_to(external,target_is_directory=True)
 r,_=call('list-long-id',['module','list','--json','--only='+longid,'--targets= \tsystem\n vendor ']);data=json.loads(r.stdout);data['links']=[dict(link,modId=m['modId']) for m in data['mods'] for link in m['links']]
 assert [m['modId'] for m in data['mods']]==[longid] and any(v['modId']==longid and v['virtual']=='/system' for v in data['links'])
 r,rows=call('target-whitespace',['module','load',str(mod),'--targets= \tvendor\n ']);assert {v['v'] for v in rows}=={'/vendor/end'}
 call('list-error',['module','list','--json'],1,RULE_PAGE=str(page),LIST_ERROR='1')
 call('list-malformed',['module','list','--json'],1,LIST_MALFORMED='1')
 call('unknown-protocol',['module','load',str(mod)],1,VERSION='24')
 (out/'receipt.json').write_text(json.dumps({'scope':'Developer host production CLI; native keyring, Android xattr and stat boundaries are fixtures','cases':cases},ensure_ascii=False,indent=2)+'\n');print('PASS',len(cases),'module CLI cases')
if __name__=='__main__':main()
