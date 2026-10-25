#!/usr/bin/env python3
"""执行所选镜像的生产VFS探测器、参考比较和拒绝反例；完整初始化覆盖单列。"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
root=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--images",nargs="+",required=True)
parser.add_argument("--corpus-root",type=Path,default=root)
parser.add_argument("--kptools",type=Path,required=True)
parser.add_argument("--output",type=Path,required=True)
args=parser.parse_args();corpus=args.corpus_root.resolve();base=args.output.resolve();base.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(root/'nomount/tools'));import inspect_target
sys.path.insert(0,str(root/'Developer/tools'));from verify_nomount_key_type_matrix import relocate_key_prefix
from test_directory_abis import function

COUNTS={
 'kernel_mi8-4.9':{'generic_shutdown_super':25,'full_name_hash':4,'vfs_open':18,'inode_init_always':19,'iterate_dir':12,'inode_permission':9,'address_space_init_once':24,'ext4_drop_inode':9},
 'kernel_mi9-4.14':{'generic_shutdown_super':27,'full_name_hash':6,'vfs_open':18,'inode_init_always':19,'iterate_dir':11,'inode_permission':6,'address_space_init_once':7,'ext4_drop_inode':9},
 'kernel_mi10-4.19':{'generic_shutdown_super':27,'full_name_hash':6,'vfs_open':9,'inode_init_always':19,'iterate_dir':11,'inode_permission':6,'address_space_init_once':7,'ext4_drop_inode':9},
 'kernel_mi11-5.4':{'generic_shutdown_super':35,'full_name_hash':6,'vfs_open':10,'inode_init_always':17,'iterate_dir':12,'inode_permission':13,'address_space_init_once':8,'ext4_drop_inode':12},
 'kernel_android12-5.10':{'generic_shutdown_super':45,'full_name_hash':9,'vfs_open':11,'inode_init_always':19,'iterate_dir':13,'inode_permission':15,'address_space_init_once':27,'ext4_drop_inode':11}}
def extra_cases(name,symbols,offsets):
 c='\n// 新目标反例，原Oracle另行完整执行。\n'
 c+='assert(inst_is_ldar(0x88dffd08U)&&inst_get_ldar_size(0x88dffd08U)==2&&inst_get_ldar_rt(0x88dffd08U)==8&&inst_get_ldar_rn(0x88dffd08U)==8);\n'
 c+='assert(inst_is_ldar(0xc8dffc41U)&&inst_is_ldar(0x08dffc83U)&&inst_is_ldar(0x48dffcc5U));\n'
 c+='assert(!inst_is_ldar(0x885f7d08U)&&!inst_is_ldar(0x885ffd08U)&&!inst_is_ldar(0x889ffd08U));\n'
 c+='for(unsigned bit=0;bit<32;bit++)if((0x3ffffc00U>>bit)&1)assert(!inst_is_ldar(0x88dffd08U^(1U<<bit)));\n'
 # 每次还原被改动指令，各阶段按生产入口取得自己的依赖。
 checks={'generic_shutdown_super':'nm_find_super_lifecycle(code)','full_name_hash':'nm_find_name_hash_arguments(code)',
         'vfs_open':'nm_check_rule_prefixes((void*)kallsyms_lookup_name("dentry_open"),code)',
         'inode_init_always':'nm_probe_saved_inode_storage(code,(uintptr_t)table,NULL,&data)',
         'iterate_dir':f'nm_check_directory_iteration(code,{offsets["fop_iterate_shared"]})',
         'inode_permission':'calculate_function_permission_abi()',
         'address_space_init_once':'nm_find_mapping_clear_size(code)',
         'ext4_drop_inode':'nm_find_inode_hash(code)'}
 for fn,count in COUNTS[name].items():
  actual=fn if fn in symbols else next(n for n in symbols if (n.startswith(fn+'.') or n.startswith(fn+'$')) and not n.endswith('.cfi_jt'))
  at=symbols[actual]
  setup=''
  if fn=='inode_init_always':
   # 从该窗口实际ADRP/ADD取no_open对象；不从相邻符号或名称猜地址。
   index={'kernel_mi8-4.9':7,'kernel_mi9-4.14':15,'kernel_mi10-4.19':15,'kernel_mi11-5.4':10,'kernel_android12-5.10':12}[name]
   add={'kernel_mi8-4.9':11,'kernel_mi9-4.14':16,'kernel_mi10-4.19':16,'kernel_mi11-5.4':11,'kernel_android12-5.10':13}[name]
   setup=f'uintptr_t table=((uintptr_t)&code[{index}]&~(uintptr_t)4095)+inst_get_adrp_label(code[{index}])+inst_get_add_imm_imm(code[{add}]);int data=-1;'
  c+=f'{{u32* code=(void*)(arena+{at}U);{setup}\n'
  for mutant in (0xd503201f,0xc8137c83):
   c+=f'for(unsigned i=0;i<{count};i++){{u32 saved=code[i];if(saved=={mutant}U)continue;code[i]={mutant}U;int rc={checks[fn]};code[i]=saved;\n'
   c+=f'if(rc>=0){{fprintf(stderr,"accepted {fn} %u mutant {mutant} rc=%d\\n",i,rc);return 3;}}}}\n'
  c+='}\n'
 c+='''long page=sysconf(_SC_PAGESIZE);assert(page>1024);
unsigned char* pages=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(pages!=MAP_FAILED&&!mprotect(pages+page,page,PROT_NONE));
'''
 for fn in ['full_name_hash','vfs_open','inode_init_always','iterate_dir','address_space_init_once','generic_shutdown_super']:
  count=COUNTS[name][fn]
  if fn=='inode_init_always':count=21 if name=='kernel_android12-5.10' else 20
  actual=fn if fn in symbols else next(n for n in symbols if (n.startswith(fn+'.') or n.startswith(fn+'$')) and not n.endswith('.cfi_jt'))
  at=symbols[actual]
  c+=f'{{u32* original=(void*)(arena+{at}U);u32* code=(void*)(pages+page-{count}*4);memcpy(code,original,{count}*4);\n'
  setup=''
  if fn=='inode_init_always':
   index={'kernel_mi8-4.9':7,'kernel_mi9-4.14':15,'kernel_mi10-4.19':15,'kernel_mi11-5.4':10,'kernel_android12-5.10':12}[name]
   add={'kernel_mi8-4.9':11,'kernel_mi9-4.14':16,'kernel_mi10-4.19':16,'kernel_mi11-5.4':11,'kernel_android12-5.10':13}[name]
   setup=f'uintptr_t table=((uintptr_t)&code[{index}]&~(uintptr_t)4095)+inst_get_adrp_label(code[{index}])+inst_get_add_imm_imm(code[{add}]);int data=-1;'
  elif fn=='address_space_init_once':
   native='__init_rwsem' if name in ['kernel_mi8-4.9','kernel_android12-5.10'] else 'memset'
   setup=f'override_value=kallsyms_lookup_name("{native}")+(uintptr_t)code-(uintptr_t)original;override_name="{native}";'
  c+=setup+f'assert({checks[fn]}>=0);override_name=NULL;}}\n'
 # 固定窗口的基础字段读取亦贴保护页；PAC仅增加已确认的一条入口指令。
 basic_guards=[('vfs_llseek',17 if name=='kernel_android12-5.10' else 16,'nm_find_file_objects(code)',offsets['file_inode_ops']),
               ('generic_file_mmap',9 if name=='kernel_android12-5.10' else 8,'nm_find_mapping(code)',offsets['file_mapping']),
               ('generic_fillattr',20 if name=='kernel_mi8-4.9' else 19 if name=='kernel_android12-5.10' else 18,'nm_find_kstat_prefix(code)',offsets['kstat_inode_first']),
               ('file_ns_capable',14,'nm_find_file_cred(code)',offsets['file_cred'])]
 for fn,count,check,expected in basic_guards:
  actual=fn if fn in symbols else next(n for n in symbols if (n.startswith(fn+'.') or n.startswith(fn+'$')) and not n.endswith('.cfi_jt'))
  c+=f'{{u32* code=(void*)(pages+page-{count}*4);memcpy(code,arena+{symbols[actual]}U,{count}*4);assert({check}=={expected});}}\n'
 c+='assert(!munmap(pages,page*2));\n'
 return c

source=(root/'nomount/nm_offsets.c').read_text();fields=re.findall(r'int16_t\s+(\w+)\s*;',source.split('};',1)[0])
prefix='''#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define nm_log_info(...) printf(__VA_ARGS__)
#define nm_log_error(...) printf(__VA_ARGS__)
static unsigned char* arena;
static const char* override_name;static uintptr_t override_value;
static unsigned long kallsyms_lookup_name(const char* name);
static unsigned long kallsyms_lookup_name_by_suffix(const char* name);
'''
prefix+=(root/'kpm_utils.h').read_text().split('// instruction\n',1)[1].rsplit('#endif',1)[0]+(root/'nomount/nm_structs.h').read_text()
prefix+=source.split('// int保留',1)[0].replace('__attribute__((section(".data.re_offsets"), used))','')
prefix+=function(source,'nm_validate_control_layout')+function(source,'validate_offsets')+function(source,'nm_validate_inode_offsets')+function(source,'nm_validate_directory_offsets')+function(source,'nm_validate_file_offsets')
prefix+=source.split('#include "nm_btf.c"\n',1)[1].split('#endif\n\nstatic int calculate_offsets',1)[0]
for name in ('offsets','rule_prefixes','file_offsets','inode_offsets','directory_offsets','control_layout','virtual_directory_abi','topology_abi','backing_directory_abi','backing_inode_abi','operation_sizes'):
 prefix+=f'static int calculate_btf_{name}(bool* unavailable){{*unavailable=true;return -ENODATA;}}\n'
prefix+=function(source,'calculate_offsets')
for fn in ('nm_prepare_rule_layout','nm_prepare_file_layout','nm_prepare_inode_layout','nm_prepare_directory_layout','nm_prepare_control_layout','nm_prepare_permission_abi','nm_prepare_virtual_directory_abi','nm_prepare_topology_abi','nm_prepare_backing_directory_abi'):prefix+=function(source,fn)
prefix+=(root/'nomount/nm_operations.c').read_text().split('// 原表按',1)[0]
literals=set(re.findall(r'"([A-Za-z_][A-Za-z0-9_.$]*)"',source))
receipts=[]
for name in args.images:
 out=base/name;out.mkdir(exist_ok=False)
 image=corpus/'kernel_img'/name;raw=inspect_target.unpack_target(image).data
 log=subprocess.check_output([str(args.kptools.resolve()),'-d','-i',str(image)],text=True,stderr=subprocess.STDOUT)
 (out/'symbols.log').write_text(log)
 syms={n:(int(o,16),t) for o,t,n in re.findall(r'(?m)^0x([0-9a-f]+) ([A-Za-z]) (\S+)$',log)};s={n:o for n,(o,t) in syms.items()}
 ref=json.loads((root/'local/nomount/configs'/(name+'-v4.json')).read_text());offsets=ref['offsets']
 assert hashlib.sha256(raw).hexdigest()==ref['kernel_sha256']
 prepared,native,reloc=relocate_key_prefix(raw,s,log,offsets)
 if native is None:
  ll=[n for n in s if n.startswith('block_llseek.') and n.endswith('.cfi_jt')]
  native=struct.unpack_from('<Q',raw,s['def_blk_fops']+8)[0]-s[ll[0] if ll else 'block_llseek']
 data=bytearray(raw)
 rng=re.search(r'relocation table range: \[0x([0-9a-f]+), 0x([0-9a-f]+)\)',log)
 if rng:
  for off,info,addend in struct.iter_unpack('<QQQ',raw[int(rng[1],16):int(rng[2],16)]):
   at=off-native
   if 0<=at<=len(data)-8 and info&0xffffffff in (0x101,0x403):
    if info&0xffffffff==0x101:addend+=native
    value=struct.unpack_from('<Q',data,at)[0]
    if value!=addend:struct.pack_into('<Q',data,at,(value+addend)&((1<<64)-1))
 (out/'Image').write_bytes(data);(out/'symbols.json').write_text(json.dumps(s));(out/'base.json').write_text(json.dumps({'native':native,'relocation':reloc}))
 def entry(n,suffix=True):
  if n in syms:return syms[n]
  found=[k for k in s if (k.startswith(n+'.') or k.startswith(n+'$')) and not k.endswith('.cfi_jt')]
  return syms[found[0]] if suffix and len(found)==1 else None
 c=prefix
 for fn,suffix in [('kallsyms_lookup_name',False),('kallsyms_lookup_name_by_suffix',True)]:
  c+=f'static unsigned long {fn}(const char* name){{\nif(override_name&&!strcmp(name,override_name))return override_value;\n'
  for n in sorted(literals):
   item=entry(n,suffix)
   if item:
    o,t=item;expr=f'{native+o}ULL' if t in ('A','a') else f'(uintptr_t)(arena+{o}U)'
    c+=f'if(!strcmp(name,"{n}"))return {expr};\n'
  c+='printf("MISSING %s\\n",name);return 0;}\n'
 extent=(len(data)+0x10000+4095)&~4095
 c+=f'''int main(int argc,char** argv){{assert(argc==2);arena=aligned_alloc(4096,{extent}U);assert(arena);memset(arena,0,{extent}U);
FILE* f=fopen(argv[1],"rb");assert(f&&fread(arena,1,{len(data)}U,f)=={len(data)}U);fclose(f);
'''
 tables={'def_blk_fops':offsets['file_ops_size'],'simple_dir_operations':offsets['file_ops_size'],'key_type_user':56,'sdcardfs_ci_dops':112}
 for sym in list(s):
  if sym=='inode_init_always.no_open_fops' or sym.startswith('no_open_fops.'):tables[sym]=offsets['file_ops_size']
 for sym,size in tables.items():
  if sym in s:
   c+=f'for(unsigned i=0;i<{size//8};i++){{uint64_t* p=(void*)(arena+{s[sym]}U+i*8);if(*p>={native}ULL&&*p<{native+len(data)}ULL)*p=(uintptr_t)arena+(*p-{native}ULL);}}\n'
 c+='memset((void*)&struct_offset,255,sizeof(struct_offset));nm_owned_operation_fallback=true;int rc;\n'
 phases=[('basic','calculate_function_offsets'),('rule','nm_prepare_rule_layout'),('file','nm_prepare_file_layout'),('inode_storage','calculate_function_inode_offsets'),('inode_callbacks','calculate_function_inode_callbacks'),('directory','calculate_function_directory_offsets'),('super','calculate_function_super_callbacks'),('directory_callbacks','calculate_function_directory_callbacks'),('control','nm_prepare_control_layout'),('extents','nm_prepare_operation_sizes'),('permission','nm_prepare_permission_abi')]
 for label,fn in phases:c+=f'rc={fn}();printf("PHASE {label} %d\\n",rc);\n'
 ready=['file_inode_ops','file_mapping','inode_superblock','inode_number','inode_nlink','inode_size','dentry_ops','kstat_inode_first',
        'name_hash_args','inode_private','file_private','file_position','file_flags','file_cred','file_ops_size',
        'fop_open','fop_release','fop_mmap','fop_splice_read','inode_file_ops','inode_data','inode_data_size','inode_blocks',
        'sop_drop_inode','sop_evict_inode','dentry_lock','fop_iterate','fop_iterate_shared','permission_abi','mutex_size','mutex_no_lockdep','key_callbacks','key_type_size','key_preparse_data']
 if name not in ('kernel_mi11-5.4','kernel_android12-5.10'):
  ready+=['inode_hash','iop_getattr','getattr_callback_args','getattr_function_args','getattr_context_kind','fillattr_abi']
 c+=''.join(f'assert(struct_offset.{n}=={offsets[n]});\n' for n in ready)
 c+=f'assert(nm_find_inode_hash((void*)kallsyms_lookup_name_by_suffix("ext4_drop_inode"))=={offsets["inode_hash"]});\n'
 c+='puts("OFFSETS");'+''.join(f'printf("{f} %d\\n",struct_offset.{f});' for f in fields)+extra_cases(name,s,offsets)+'free(arena);return 0;}\n'
 (out/'probe.c').write_text(c)
 r=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(out/'probe.c'),'-o',str(out/'probe')],capture_output=True,text=True);(out/'compile.log').write_text(r.stdout+r.stderr)
 if r.returncode:print(r.stderr[:1000]);r.check_returncode()
 r=subprocess.run([str(out/'probe'),str(out/'Image')],capture_output=True,text=True);(out/'run.log').write_text(r.stdout+r.stderr)
 if r.returncode:print(r.stderr+r.stdout[-1500:],flush=True)
 r.check_returncode()
 phases={label:int(value) for label,value in re.findall(r'^PHASE (\S+) (-?\d+)$',r.stdout,re.M)}
 for label in ['basic','rule','file','inode_storage','directory','permission','control','super']:assert phases[label]==0,(name,label,phases)
 receipts.append({'image':name,'kernel_sha256':ref['kernel_sha256'],'phases':phases,'verified_fields':{n:offsets[n] for n in ready},'hash_probe':offsets['inode_hash'],'mutation_windows':COUNTS[name]})
 print(name,phases,'verified fields',len(ready),flush=True)
(base/'matrix.json').write_text(json.dumps({'role':'Developer','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'source_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)),'scope':'VFS component preparation; remaining phases are explicitly not-covered; no native execution','targets':receipts},indent=2)+'\n')
