#!/usr/bin/env python3
"""v22 的生产业务/协议宿主贯通；迁移冻结夹具输入，原 Oracle 文件保持不动。

--oracle-output 指定 contracts-final-03 生成物；按其回执核对身份。仅 GET_VERSION
回复的那条旧断言迁移为 NM_CONTROL_VERSION，逐项记入回执供合并审计。
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from test_directory_abis import function
from build_zip import adapt_cli

ROOT = Path(__file__).resolve().parents[2]
CHANGED = {
    'nm_rules.c': ['nm_alloc_rule', 'nm_select_rule', 'nm_build_leaf_rule_array', 'nm_publish_leaf_rule', 'nm_remove_leaf_rule'],
    'nm_topology.c': ['nm_topology_remove_locked'],
    'nm_control.c': ['nm_control_rules', 'nm_control_list', 'nm_execute_payload'],
    'nm_virtual_directory.c': ['nm_materialize_virtual_directory', 'nm_virtual_directory_llseek', 'nm_virtual_directory_iterate'],
    'nm_directory.c': ['nm_directory_lookup', 'nm_dentry_validate'],
    'nm_backing_subtree.c': ['nm_inherit_backing_directory'],
    'nm_backing_inode.c': ['nm_take_backing_child_rule', 'nm_lookup_backing_directory'],
    'nm_offsets.c': ['nm_publish_dentry_ops'],
}
EXTRA_BEFORE = {'nm_remove_leaf_rule': ['nm_remove_leaf_rule_scope'],
                'nm_topology_remove_locked': ['nm_topology_remove_scope_locked']}
EXTRA_AFTER = {'nm_alloc_rule': ['nm_validate_rule_scope', 'nm_alloc_scoped_rule']}

FIXTURE = r'''
extern int v22_cli_call(int,const char**,const char*,char*,unsigned long);
static unsigned v22_cli_mutations;
void v22_kernel_exchange(void* frame) {
  memcpy(&control_user,frame,sizeof(control_user));
  if(control_user.cmd!=NM_CMD_GET_VERSION&&control_user.cmd!=NM_CMD_GET_LIST)v22_cli_mutations++;
  (void)control_transport(8);memcpy(frame,&control_user,sizeof(control_user));
}
static int v22_add(const char* path,const char* real,u32 flags,u32 uid,u32 end,u32 lo,u32 hi) {
  control_request(NM_CMD_ADD_RULE);control_append(path,real,flags,uid);
  struct nm_rule_hdr h;memcpy(&h,control_user.buffer,sizeof(h));h.uid_end=end;h.deny_start=lo;h.deny_end=hi;
  memcpy(control_user.buffer,&h,sizeof(h));return control_send();
}
static int v22_del(const char* path,u32 uid,u32 end,u32 lo,u32 hi) {
  control_request(NM_CMD_DEL_RULE);control_delete(path,uid);
  struct nm_del_hdr h;memcpy(&h,control_user.buffer,sizeof(h));h.uid_end=end;h.deny_start=lo;h.deny_end=hi;
  memcpy(control_user.buffer,&h,sizeof(h));return control_send();
}
static struct nomount_rule* v22_selected(const char* path,u32 uid) {
  struct nm_topology_leaf* entry=nm_topology_find(path,strlen(path));assert(entry);
  return nm_select_rule(entry->leaf,uid);
}
static void check_v22(void) {
  const char* path="/system/app/v22";
  assert(!v22_add(path,"/file",0,0,0,0,0));
  assert(!v22_add(path,"/file2",0,1000,5000,3000,4000));
  assert(v22_selected(path,999)->r_path.dentry==tree_dentry[6]);
  assert(v22_selected(path,1000)->r_path.dentry==tree_dentry[7]);
  assert(v22_selected(path,2999)->r_path.dentry==tree_dentry[7]);
  assert(v22_selected(path,3000)->r_path.dentry==tree_dentry[6]);
  assert(v22_selected(path,4000)->r_path.dentry==tree_dentry[6]);
  assert(v22_selected(path,4001)->r_path.dentry==tree_dentry[7]);
  assert(v22_selected(path,5000)->r_path.dentry==tree_dentry[7]);
  assert(v22_selected(path,5001)->r_path.dentry==tree_dentry[6]);
  struct nm_rule_array* held=nm_topology_find(path,strlen(path))->leaf->rules;
  assert(v22_add(path,"/file",0,2000,6000,0,0)==-EEXIST);
  assert(v22_add(path,"/file",0,1000,5000,2000,2500)==-EEXIST);
  assert(nm_topology_find(path,strlen(path))->leaf->rules==held);
  assert(v22_add(path,"/file",0,5000,1000,0,0)==-EINVAL);
  assert(v22_add(path,"/file",0,1000,5000,0,3000)==-EINVAL);
  assert(v22_add(path,"/file",0,1000,5000,5001,6000)==-EINVAL);
  assert(v22_del(path,1000,4999,3000,4000)==-ENOENT);
  assert(v22_del(path,1000,5000,3000,3999)==-ENOENT);
  assert(!v22_add(path,"/file",0,1000,5000,3000,4000));
  assert(v22_selected(path,1000)->r_path.dentry==tree_dentry[6]);
  control_request(NM_CMD_GET_LIST);assert(!control_send()&&control_count()==2);
  unsigned at=0,scoped=0;
  while(at<control_user.data_size){
    struct nm_rule_hdr h;memcpy(&h,control_user.buffer+at,sizeof(h));
    if(h.uid==1000){assert(h.uid_end==5000&&h.deny_start==3000&&h.deny_end==4000);scoped++;}
    at+=sizeof(h)+h.v_len+h.r_len;
  }
  assert(scoped==1);
  assert(!v22_del(path,1000,5000,3000,4000));
  assert(!v22_del(path,0,0,0,0));
  path="/system/app/deny";
  assert(!v22_add(path,"/file",0,0,0,100,200));
  assert(v22_selected(path,99)&&!v22_selected(path,100)&&!v22_selected(path,200)&&v22_selected(path,201));
  assert(!v22_del(path,0,0,100,200));
  path="/system/app/all";
  assert(!v22_add(path,"/file",0,0,~0U,0,0));
  assert(v22_selected(path,0)&&v22_selected(path,~0U));
  assert(!v22_del(path,0,~0U,0,0));
  // v21 添加头只有12字节；截断记录拒绝且游标停在原处。
  control_request(NM_CMD_ADD_RULE);control_user.data_size=12;
  assert(control_send()==-EINVAL&&!control_user.arg1&&!nm_topology_leaves);
  assert(v22_add("/system/app/bad","/file",NM_FLAG_OPAQUE,0,0,0,0)==-ENOTDIR);
  assert(v22_add("/system/app/bad","/A",NM_FLAG_OPAQUE|NM_FLAG_WHITEOUT,0,0,0,0)==-EINVAL);
  // 同一 backing/node 的 opaque 与合并视图不得共用旧 inode。
  set_uid(1000);assert(!v22_add("/system/app/opaque","/A",NM_FLAG_OPAQUE,0,0,0,0));
  assert(!v22_add("/system/app/opaque/visible","/file",0,0,0,0,0));
  assert(!v22_add("/system/app/opaque/missing/file","/file",0,0,0,0,0));
  struct inode* opaque=tree_lookup(0,"opaque",-1,parent);assert(opaque);
  struct nm_inode_info* info=nm_inode_private(opaque);assert(info->flags&NM_FLAG_OPAQUE);
  int before=tree_queries;
  assert(!tree_lookup(1,"original",0,opaque)&&tree_queries==before);
  assert(tree_lookup(2,"visible",0,opaque));
  struct inode* automatic=tree_lookup(5,"missing",0,opaque);assert(automatic);
  assert(!((struct nm_inode_info*)nm_inode_private(automatic))->r_path.dentry);
  assert(nm_dentry_revalidate((void*)view_dentry[5],0)==1);
  assert(tree_lookup(6,"file",5,automatic)&&tree_queries==before);
  _Alignas(16) unsigned char vf[512]={0};
  struct nm_file_inode_ops* fio=(void*)(vf+struct_offset.file_inode_ops);
  fio->f_inode=opaque;fio->f_op=nm_virtual_directory_fops;
  *(struct nm_path*)nm_file_path(vf)=(struct nm_path){.dentry=(void*)view_dentry[0]};
  struct nm_dir_context ctx={0}; /* V22_ACTOR */
  reset_emit();assert(!nm_virtual_directory_iterate((void*)vf,&ctx));
  assert(has_name(".")&&has_name("..")&&has_name("visible")&&!has_name("original"));
  assert(tree_queries==before&&nm_virtual_position(ctx.pos,false));
  assert(nm_virtual_directory_llseek((void*)vf,ctx.pos,0)==ctx.pos);
  assert(!nm_inherit_backing_directory(opaque,(void*)view_dentry[1])&&tree_queries==before);
  struct nm_inode_info candidate=*info;candidate.flags&=~NM_FLAG_OPAQUE;
  assert(!nm_cached_directory_test(opaque,&candidate));
  assert(!v22_add("/system/app/opaque","/A",0,0,0,0,0));
  assert(!nm_dentry_revalidate((void*)view_dentry[0],0));
  struct inode* merged=tree_lookup(3,"opaque",-1,parent);
  assert(merged&&merged!=opaque&&!( ((struct nm_inode_info*)nm_inode_private(merged))->flags&NM_FLAG_OPAQUE));
  assert(tree_lookup(4,"original",3,merged)&&tree_queries==before+1);
  control_request(NM_CMD_CLEAR_ALL);assert(!control_send());
  for(int i=0;i<7;i++)tree_release(i);
  assert(!nm_topology_leaves&&!nm_topology_anchors&&!manager_depth&&!rcu_depth);
  char output[16384];
  const char* add[]={"nm","rule","add","--uid-range","1000-5000","--uid-excluded","3000-4000","/system/app/cli","/file"};
  unsigned mutations=v22_cli_mutations;
  assert(v22_cli_call(9,add,"21",output,sizeof(output))==1&&v22_cli_mutations==mutations&&!nm_topology_leaves);
  assert(v22_cli_call(9,add,"23",output,sizeof(output))==1&&v22_cli_mutations==mutations&&!nm_topology_leaves);
  assert(v22_cli_call(9,add,"22bad",output,sizeof(output))==1&&v22_cli_mutations==mutations&&!nm_topology_leaves);
  assert(!v22_cli_call(9,add,NULL,output,sizeof(output)));
  assert(v22_selected("/system/app/cli",1000)&&!v22_selected("/system/app/cli",3000));
  const char* excluded[]={"nm","rule","add","--uid-excluded","100-200","/system/app/default","/file"};
  assert(!v22_cli_call(7,excluded,NULL,output,sizeof(output)));
  assert(v22_selected("/system/app/default",99)&&!v22_selected("/system/app/default",150));
  const char* opaq[]={"nm","rule","add","--opaque","/system/app/opaque","/A"};
  assert(!v22_cli_call(6,opaq,NULL,output,sizeof(output)));
  const char* list[]={"nm","rule","list","--json"};
  assert(!v22_cli_call(4,list,NULL,output,sizeof(output)));
  assert(strstr(output,"\"opaque\": true")&&strstr(output,"\"uid_end\": 5000")&&strstr(output,"\"deny_end\": 4000"));
  printf("V22_CLI_JSON_BEGIN\n%sV22_CLI_JSON_END\n",output);
  const char* del[]={"nm","rule","del","--uid-range","1000-5000","--uid-excluded","3000-4000","/system/app/cli"};
  assert(!v22_cli_call(8,del,NULL,output,sizeof(output))&&!nm_topology_find("/system/app/cli",15));
  control_request(NM_CMD_CLEAR_ALL);assert(!control_send()&&!nm_topology_leaves);
  puts("v22 scopes, overlap/deny/delete/list, old-header rejection and opaque lookup/enumeration/cache: PASS");
}
'''

CLI_PREFIX = r'''
#include <assert.h>
#include <stdlib.h>
#include <setjmp.h>
#define SYS_GETCWD 17
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_EXIT 93
#define SYS_ADD_KEY 217
static long sys1(long,long);
static long sys3(long,long,long,long);
static long sys5(long,long,long,long,long,long);
'''
CLI_GLUE = r'''
_Static_assert(sizeof(struct nm_payload)==4096,"CLI payload");
_Static_assert(sizeof(struct nm_rule_hdr)==24&&sizeof(struct nm_del_hdr)==18,"CLI v22 records");
_Static_assert(__builtin_offsetof(struct nm_rule_hdr,v_len)==20,"CLI v22 field positions");
extern void v22_kernel_exchange(void*);
static jmp_buf cli_jump;
static int cli_exit;
static char* cli_output;
static unsigned long cli_used,cli_capacity;
static const char* cli_fake;
static long sys1(long n,long a){assert(n==SYS_EXIT);cli_exit=a;longjmp(cli_jump,1);}
static long sys3(long n,long a,long b,long c){
 if(n==SYS_WRITE){assert(a==1&&cli_used+c<cli_capacity);__builtin_memcpy(cli_output+cli_used,(void*)b,c);cli_used+=c;cli_output[cli_used]=0;return c;}
 assert(n==SYS_GETCWD&&b>=2);__builtin_memcpy((void*)a,"/",2);return 2;
}
static long sys5(long n,long a,long b,long c,long d,long e){
 assert(n==SYS_ADD_KEY&&d==sizeof(unsigned long)&&e==-1);
 struct nm_payload* p=(void*)*(unsigned long*)c;
 if(cli_fake&&p->cmd==NM_CMD_GET_VERSION){p->status=0;p->data_size=__builtin_strlen(cli_fake);__builtin_memcpy(p->buffer,cli_fake,p->data_size);return 0;}
 v22_kernel_exchange(p);return 0;
}
int v22_cli_call(int argc,const char** argv,const char* fake,char* out,unsigned long capacity){
 long* sp=malloc((argc+2)*sizeof(long));assert(sp);sp[0]=argc;
 for(int i=0;i<argc;i++)sp[i+1]=(long)argv[i];sp[argc+1]=0;
 cli_fake=fake;cli_output=out;cli_capacity=capacity;cli_used=0;out[0]=0;
 if(!setjmp(cli_jump))c_main(sp);
 free(sp);return cli_exit;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    reference = json.loads((args.oracle_output / 'receipt.json').read_text())
    upstream = ROOT / 'nomount/upstream/nomount/userspace/src'
    cli_source = CLI_PREFIX + (upstream/'nm.h').read_text().split('/* --- DEFS --- */',1)[1]
    cli_source += adapt_cli((upstream/'nm.c').read_text()).replace('#include "nm.h"','') + CLI_GLUE
    cli_path = args.output/'cli.c'
    cli_path.write_text(cli_source)
    results = []
    for row in reference['results']:
        abi = row['abi']
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        assert hashlib.sha256(original.encode()).hexdigest() == row['generated_sha256']
        source = original
        for header, guard in [('nm_rules.h', '__NM_RULES_H'), ('nm_protocol.h', '__NM_PROTOCOL_H')]:
            current = (ROOT / 'nomount' / header).read_text()
            block = re.search(r'#ifndef ' + guard + r'\b.*?#endif', source, re.S)
            assert block, header
            source = source[:block.start()] + current[current.index('#ifndef '):] + source[block.end():]
        for file, names in CHANGED.items():
            current = (ROOT / 'nomount' / file).read_text()
            for name in names:
                before = function(source, name)
                replacement = '\n'.join(function(current, n) for n in EXTRA_BEFORE.get(name, []))
                replacement += '\n' + function(current, name)
                replacement += '\n' + '\n'.join(function(current, n) for n in EXTRA_AFTER.get(name, []))
                assert source.count(before) == 1
                source = source.replace(before, replacement, 1)
        fixtures = {
            'struct nm_rule_hdr h={flags,uid,strlen(virtual_path),real?strlen(real):0};':
                'struct nm_rule_hdr h={.flags=flags,.uid=uid,.uid_end=uid,.v_len=strlen(virtual_path),.r_len=real?strlen(real):0};',
            'struct nm_del_hdr h={uid,strlen(path)};':
                'struct nm_del_hdr h={.uid=uid,.uid_end=uid,.v_len=strlen(path)};',
        }
        for before, after in fixtures.items():
            assert source.count(before) == 1
            source = source.replace(before, after, 1)
        old_assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
        before = next(a for a in old_assertions if 'control_transport(4)' in a)
        after = before.replace('NM_KPM_VERSION', 'NM_CONTROL_VERSION')
        assert before != after and source.count(before) == 1
        source = source.replace(before, after, 1)
        migrated = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert len(migrated) == len(old_assertions)
        changes = [{'index': i, 'old': a, 'new': b, 'reason': 'v22 protocol version reply is distinct from KPM release version'}
                   for i, (a,b) in enumerate(zip(old_assertions, migrated)) if a != b]
        assert len(changes) == 1
        marker = 'static int oracle_main(void){'
        assert source.count(marker) == 1
        source = source.replace(marker, FIXTURE + '\n' + marker, 1)
        source = source.replace('/* V22_ACTOR */', 'ctx.' + ('actor_bool' if abi == 'bool' else 'actor') + '=fixture_actor;', 1)
        marker = ' control_request(999);assert(control_send()==-EINVAL);'
        assert source.count(marker) == 1
        source = source.replace(marker, ' check_v22();\n' + marker, 1)
        out = args.output / abi
        out.mkdir()
        path = out / 'contracts.c'
        path.write_text(source)
        binary = out / 'contracts'
        cmd = ['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(ROOT/'nomount'),
               '-fsanitize=address,undefined','-fno-builtin','-Wno-invalid-noreturn','-g',str(path),str(cli_path),'-o',str(binary)]
        built = subprocess.run(cmd, capture_output=True, text=True)
        (out/'compile.log').write_text(built.stdout+built.stderr)
        built.check_returncode()
        tested = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
        (out/'run.log').write_text(tested.stdout+tested.stderr)
        tested.check_returncode()
        value = re.search(r'V22_CLI_JSON_BEGIN\n(.*?)V22_CLI_JSON_END',tested.stdout,re.S)
        assert value
        listed = json.loads(value.group(1))
        assert len(listed)==3 and any(r.get('opaque') is True for r in listed)
        results.append({'abi':abi,'original_assertions':len(old_assertions),'assertions_unchanged':len(old_assertions)-1,
                        'assertion_migration':changes,'fixture_migration':fixtures,'result':'PASS'})
    (args.output/'receipt.json').write_text(json.dumps({'scope':'Developer Tier-3 v22 production functions in frozen host fixtures; not kernel concurrency/device proof',
                                                       'results':results},ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(results,ensure_ascii=False,indent=2))


if __name__ == '__main__':
    main()
