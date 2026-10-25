#!/usr/bin/env python3
"""Exercise production VFS routing, joint contracts and N1-N8 using two selected kernels."""
from pathlib import Path
import json,re,struct,subprocess,argparse
ROOT=Path(__file__).resolve().parents[2]; parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);OUT=parser.parse_args().output.resolve();OUT.mkdir(parents=True,exist_ok=False)
src=(ROOT/'nomount/nm_offsets.c').read_text(); kp=(ROOT/'KernelPatch/kernel/base/start.c').read_text()
def function(text,name):
 m=re.search(r'(?m)^(?:static )?[^\n;{}]*\b'+re.escape(name)+r'\([^;]*?\)\s*\{',text);assert m,name
 e=m.end();depth=1
 while depth:
  depth+=(text[e]=='{')-(text[e]=='}');e+=1
 return text[m.start():e]
roots=['calculate_function_operation_sizes','nm_find_set_acl_vfs','nm_find_super_cache_vfs','nm_find_dentry_real','nm_find_operation_alignment']
functions={}
def visit(name):
 if name in functions:return
 text=function(src,name);functions[name]=text
 for dep in re.findall(r'\b((?:nm_|calculate_function_)\w+)\s*\(',text):
  if dep!=name and dep not in ("nm_log_info","nm_log_error"):visit(dep)
for name in roots:visit(name)
# Order by source order, retaining exact function bodies and forward declarations.
funcs=sorted(functions,key=lambda n:src.index(functions[n]))
utils=(ROOT/'kpm_utils.h').read_text();utils=utils[utils.index('#define bits32'):utils.rindex('#endif')]
common='''#include <assert.h>
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
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
static unsigned char* arena;
static unsigned long kallsyms_lookup_name(const char*);
static unsigned long kallsyms_lookup_name_by_suffix(const char*);
'''+utils+'\n'+(ROOT/'nomount/nm_structs.h').read_text()+'\n'+src[:src.index('// 仅在确认BTF不可用')].replace('__attribute__((section(".data.re_offsets"), used))','')
common+='\nstatic enum nm_operation_anchor nm_operation_anchor;\n'+'\n'.join(functions[n].split('{',1)[0].strip()+';' for n in funcs)+'\n'+'\n'.join(functions[n] for n in funcs)
# Original KP lookup functions, not a reimplementation of the suffix predicate.
kpn=['suffix_contains_cfi','symbol_has_compiler_suffix','lookup_suffix_cb','lookup_suffix_cb_nomod','kallsyms_lookup_name_by_suffix']
common+='''
struct module;
struct suffix_lookup {const char* base;unsigned long addr;};
struct symbol {unsigned long at;char* name;};
static struct symbol* symbols;static size_t ns;
static int cfi_bypass=1;
#define VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
static unsigned kver=VERSION(5,4,0);
static uintptr_t override_cfi;
static const char* missing;static int sd_mode;static uintptr_t override_real;
static unsigned long kallsyms_lookup_name(const char* name){
 if(missing&&!strcmp(name,missing))return 0;
 if((sd_mode==1||sd_mode==2)&&!strcmp(name,"sdcardfs_ci_dops"))return 0;
 if((sd_mode==1||sd_mode==3)&&!strcmp(name,"sdcardfs_canonical_path"))return 0;
 if(sd_mode==2&&!strcmp(name,"sdcardfs_canonical_path"))return 1;
 if(sd_mode==3&&!strcmp(name,"sdcardfs_ci_dops"))return 1;
 if(override_real&&!strcmp(name,"d_set_d_op"))return override_real;
 if(override_cfi&&!strcmp(name,"__cfi_slowpath"))return override_cfi;
 for(size_t i=0;i<ns;i++)if(!strcmp(symbols[i].name,name))return (uintptr_t)arena+symbols[i].at;
 return 0;
}
static int each_impl(int (*fn)(void*,const char*,struct module*,unsigned long),void* ctx){
 for(size_t i=0;i<ns;i++){
  if(missing&&!strncmp(symbols[i].name,missing,strlen(missing)))continue;
  int r=fn(ctx,symbols[i].name,NULL,(uintptr_t)arena+symbols[i].at);if(r)return r;}
 return 0;
}
static int (*kallsyms_on_each_symbol)(int (*)(void*,const char*,struct module*,unsigned long),void*)=each_impl;
'''
for n in kpn:
 text=function(kp,n)
 if n=='kallsyms_lookup_name_by_suffix':text='static '+text
 common+='\n'+text+'\n'
results=[]
for target,key in [('kernel_mi10-4.19','mi10'),('kernel_mi11-5.4','mi11')]:
 dest=OUT/key;dest.mkdir()
 raw=(ROOT/'kernel_img'/target).read_bytes()
 evidence=json.loads((ROOT/'Developer/reports/data'/f'2026-10-21-nomount-{key}-native-tails.json').read_text())
 log=(ROOT/'local/nomount-symbol-gap-20261020-01/native'/target/'symbols.log').read_text()
 rows=[(int(a,16),k,n) for a,k,n in re.findall(r'^0x([0-9a-f]+) ([A-Za-z]) (\S+)$',log,re.M)]
 (dest/'symbols.tsv').write_text(''.join(f'{a:x} {n}\n' for a,k,n in rows))
 a,b=[int(x,16) for x in re.search(r'relocation table range: \[0x([0-9a-f]+), 0x([0-9a-f]+)\)',log).groups()]
 base=int(evidence['kernel_base'],16)
 rel=[(w-base,v) for w,i,v in struct.iter_unpack('<QQQ',raw[a:b]) if 0<=w-base<=len(raw)-8]
 (dest/'relocations.bin').write_bytes(b''.join(struct.pack('<QQ',*r) for r in rel))
 cfg=json.loads((ROOT/'local/nomount/configs'/(target+'-v4.json')).read_text())
 c=common+'''
static void clear_sizes(void){struct_offset.inode_ops_size=-1;struct_offset.super_ops_size=-1;struct_offset.dentry_ops_size=-1;}
static void refused(int rc,int expected){assert(rc==expected);assert(struct_offset.inode_ops_size==-1&&struct_offset.super_ops_size==-1&&struct_offset.dentry_ops_size==-1);}
int main(int argc,char** argv){assert(argc==4&&sizeof(void*)==8);
FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);
arena=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(arena!=MAP_FAILED);assert(fread(arena,1,size,f)==(size_t)size);fclose(f);
f=fopen(argv[2],"r");assert(f);symbols=calloc(300000,sizeof(*symbols));assert(symbols);char name[512];unsigned long at;
while(fscanf(f,"%lx %511s",&at,name)==2){assert(ns<300000);symbols[ns++]=(struct symbol){at,strdup(name)};}fclose(f);
f=fopen(argv[3],"rb");assert(f);uint64_t pair[2];
'''
 c+=f'while(fread(pair,sizeof(pair),1,f)==1){{uintptr_t v=pair[1];if(v>={base}ULL&&v<{base+len(raw)}ULL)v=(uintptr_t)arena+(v-{base}ULL);memcpy(arena+pair[0],&v,8);}}fclose(f);\n'
 c+='struct_offset=(struct struct_offset){'+','.join('.'+n+'='+str(v) for n,v in cfg['offsets'].items())+'};clear_sizes();\n'
 c+='''
uintptr_t chosen=kallsyms_lookup_name_by_suffix("super_cache_count");assert(chosen);printf("SYMBOL super_cache_count=%lx\\n",chosen-(uintptr_t)arena);
assert(!calculate_function_operation_sizes());
assert(struct_offset.inode_ops_size==256&&struct_offset.super_ops_size==272&&struct_offset.dentry_ops_size==192);
printf("POSITIVE %d/%d/%d anchor=%d\\n",struct_offset.inode_ops_size,struct_offset.super_ops_size,struct_offset.dentry_ops_size,nm_operation_anchor);
'''
 c+=f'assert(nm_operation_anchor=={"NM_OPERATION_ANCHOR_SDCARDFS" if key=="mi10" else "NM_OPERATION_ANCHOR_D_REAL"});\n'
 c+='''
// N1/N2: exactly one sdcardfs symbol is absent, even if the other needs a synthetic presence on a FUSE-only target.
for(int partial=2;partial<=3;partial++){sd_mode=partial;clear_sizes();refused(calculate_function_operation_sizes(),-ENOENT);}sd_mode=0;puts("N1 N2 PASS");
// N3: no dentry anchor remains.
sd_mode=1;missing="d_set_d_op";clear_sizes();refused(calculate_function_operation_sizes(),-ENOENT);missing=NULL;sd_mode=0;puts("N3 PASS");
// N4: a complete but zeroed sdcardfs table must not fall through to a valid d_set_d_op.
uintptr_t old_table=kallsyms_lookup_name("sdcardfs_ci_dops"),old_canonical=kallsyms_lookup_name("sdcardfs_canonical_path");
uintptr_t fake[14]={0};size_t old_ns=ns;symbols[ns++]=(struct symbol){(uintptr_t)fake-(uintptr_t)arena,"sdcardfs_ci_dops"};
symbols[ns++]=(struct symbol){old_canonical?old_canonical-(uintptr_t)arena:0,"sdcardfs_canonical_path"};
uintptr_t saved_table[14];if(old_table){memcpy(saved_table,(void*)old_table,sizeof(saved_table));memset((void*)old_table,0,sizeof(saved_table));}
clear_sizes();int broken=calculate_function_operation_sizes();assert(broken<0);assert(nm_operation_anchor!=NM_OPERATION_ANCHOR_D_REAL);
if(old_table)memcpy((void*)old_table,saved_table,sizeof(saved_table));ns=old_ns;puts("N4 PASS");
// N5: maximum 47-word supported PAC form, derived from the target's 45-word plain function.
uint32_t* original=(void*)kallsyms_lookup_name("d_set_d_op");assert(original&&inst_is_ret(original[44]));
u32 pac[47];pac[0]=0xd503233f;memcpy(pac+1,original,44*4);pac[45]=0xd50323bf;pac[46]=original[44];
long page=sysconf(_SC_PAGESIZE);unsigned char* guard=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
assert(guard!=MAP_FAILED&&!mprotect(guard+page,page,PROT_NONE));u32* edge=(void*)(guard+page-sizeof(pac));
memcpy(edge,pac,sizeof(pac));assert(nm_find_dentry_real(edge)==96);
for(unsigned i=0;i<47;i++){memcpy(edge,pac,sizeof(pac));edge[i]=0xd503201f;clear_sizes();refused(nm_find_dentry_real(edge),-EOPNOTSUPP);sd_mode=1;override_real=(uintptr_t)edge;refused(calculate_function_operation_sizes(),-EOPNOTSUPP);override_real=0;sd_mode=0;}
memcpy(edge,pac,sizeof(pac));edge[43]^=1U<<10;clear_sizes();refused(nm_find_dentry_real(edge),-EOPNOTSUPP);sd_mode=1;override_real=(uintptr_t)edge;refused(calculate_function_operation_sizes(),-EOPNOTSUPP);override_real=0;sd_mode=0;
// The actual plain target window is checked independently, all 45 consumed words.
edge=(void*)(guard+page-45*4);for(unsigned i=0;i<45;i++){memcpy(edge,original,45*4);edge[i]=0xd503201f;clear_sizes();refused(nm_find_dentry_real(edge),-EOPNOTSUPP);}
assert(!munmap(guard,2*page));puts("N5 PASS: 47 PAC + 45 native + REAL flag");
// N6: canonical/reserve-use super geometry cannot enter the independent canonical + four reserve real contract.
struct struct_offset saved=struct_offset;
struct_offset.iop_getattr=128;struct_offset.sop_drop_inode=32;struct_offset.sop_evict_inode=40;struct_offset.dop_init=40;struct_offset.dop_release=48;
clear_sizes();refused(nm_set_operation_extents_real(176,224,96),-EOPNOTSUPP);puts("N6 PASS");
// N7: no-umount_end super geometry cannot enter the old canonical/reserve-use contract.
struct_offset.iop_getattr=112;struct_offset.sop_drop_inode=40;struct_offset.sop_evict_inode=48;
clear_sizes();refused(nm_set_operation_extents(160,224,104),-EOPNOTSUPP);puts("N7 PASS");struct_offset=saved;
// Unknown init/release tuple and invalid anchor values are rejected, without version labels.
struct_offset.dop_init+=8;clear_sizes();refused(nm_set_operation_extents_real(160,224,96),-EOPNOTSUPP);
struct_offset=saved;clear_sizes();refused(nm_set_operation_extents_real(-1,224,96),-EOPNOTSUPP);
'''
 if key=='mi11':
  c+='''
// N8: perturb the native nr_cached_objects LDR immediate by one pointer slot, then execute the real dispatcher.
u32* cache=(void*)chosen;assert(nm_find_super_cache_vfs(cache)==224);u32 saved_load=cache[15];cache[15]+=1U<<10;
assert(nm_find_super_cache_vfs(cache)==232);clear_sizes();refused(calculate_function_operation_sizes(),-EOPNOTSUPP);cache[15]=saved_load;puts("N8 PASS");
'''
 else:
  c+='''
// The sibling tuple cannot masquerade as the 192 contract, even without relying on the selected target name.
struct_offset.iop_getattr=112;struct_offset.sop_drop_inode=40;struct_offset.sop_evict_inode=48;
clear_sizes();refused(nm_set_operation_extents_real(160,232,96),-EOPNOTSUPP);struct_offset=saved;puts("N8 tuple PASS (native injection on mi11)");
'''
 c+='''
// DEV-051: actual minimal prefix at a guard page, each NOP mutant must refuse before speculative legacy reads.
'''
 count=19 if key=='mi10' else 26
 c+=f'const unsigned count={count};\n'
 c+='''
guard=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(guard!=MAP_FAILED&&!mprotect(guard+page,page,PROT_NONE));
edge=(void*)(guard+page-count*4);u32* native=(void*)chosen;
for(unsigned i=0;i<count;i++){memcpy(edge,native,count*4);override_cfi=kallsyms_lookup_name("__cfi_slowpath")+(uintptr_t)edge-(uintptr_t)native;edge[i]=0xd503201f;assert(nm_find_super_cache_vfs(edge)<0);override_cfi=0;}
assert(!munmap(guard,2*page));printf("DEV051 PASS %u guarded mutants\\n",count);
for(size_t i=0;i<old_ns;i++)free(symbols[i].name);free(symbols);assert(!munmap(arena,size));return 0;}
'''
 (dest/'probe.c').write_text(c)
 command=['/usr/bin/clang','-std=gnu11','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-g',str(dest/'probe.c'),'-o',str(dest/'probe')]
 run=subprocess.run(command,capture_output=True,text=True);(dest/'compile.log').write_text(run.stdout+run.stderr)
 if run.returncode:print(run.stderr);run.check_returncode()
 run=subprocess.run([str(dest/'probe'),str(ROOT/'kernel_img'/target),str(dest/'symbols.tsv'),str(dest/'relocations.bin')],capture_output=True,text=True);(dest/'run.log').write_text(run.stdout+run.stderr)
 print(target,run.stdout,run.stderr,flush=True);run.check_returncode()
 results.append(dict(target=target,result=run.stdout,source_functions=funcs))
(OUT/'receipt.json').write_text(json.dumps(dict(scope='Developer host production dispatcher and N1-N8; no native ARM execution',results=results),indent=2)+'\n')
