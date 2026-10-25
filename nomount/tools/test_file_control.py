#!/usr/bin/env python3
"""执行生产 ioctl/compat_ioctl/fsync 转发及配置边界；不替代原生权限/并发测试。"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define CONFIG_KPM_BASELINES 1
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
#define kfunc(n) kf_##n
#define kfunc_def(n) (*kf_##n)
struct rcu_head { struct rcu_head* next; void (*func)(struct rcu_head*); };
static unsigned allocations, frees;
static void* nm_zalloc(unsigned long size){allocations++;return calloc(1,size);}
static void nm_free(const void* p){frees++;free((void*)p);}
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name){(void)name;return 0;}
'''
TEST = r'''
static _Alignas(16) unsigned char outer_bytes[4096], backing_bytes[4096], table_bytes[4096];
static struct file* outer=(void*)outer_bytes;
static struct file* backing=(void*)backing_bytes;
static unsigned native_calls, compat_calls, sync_calls;
static int result;
static long native_control(struct file* f,unsigned int cmd,unsigned long arg){
 assert(f==backing&&cmd==0xfedcba98U&&arg==0xfedcba9876543210UL);native_calls++;return result;
}
static long compat_control(struct file* f,unsigned int cmd,unsigned long arg){
 assert(f==backing&&cmd==0x1234U&&arg==0x87654321UL);compat_calls++;return result;
}
static int sync_control(struct file* f,long long start,long long end,int datasync){
 assert(f==backing&&start==0x123456789LL&&end==0x765432101LL&&datasync==1);sync_calls++;return result;
}
static unsigned profiles;
static void check_target(void){
 profiles++;
 memset(outer_bytes,0,sizeof(outer_bytes));memset(backing_bytes,0,sizeof(backing_bytes));memset(table_bytes,0,sizeof(table_bytes));
 assert(!nm_validate_file_offsets((const void*)&struct_offset));
 assert(!nm_validate_file_control_offsets((const void*)&struct_offset));
 nm_set_file_private(outer,backing);
 struct nm_file_inode_ops* objects=(void*)(backing_bytes+struct_offset.file_inode_ops);objects->f_op=table_bytes;
 int native=struct_offset.fop_mmap-(int)offsetof(struct nm_file_control_ops,mmap);
 int compat=native+offsetof(struct nm_file_control_ops,compat_ioctl);
 int sync=struct_offset.fop_release+offsetof(struct nm_file_sync_ops,fsync);
 unsigned n=native_calls,c=compat_calls,s=sync_calls;
 assert(nm_ioctl(outer,0xfedcba98U,0xfedcba9876543210UL)==-ENOTTY);
 assert(nm_compat_ioctl(outer,0x1234U,0x87654321UL)==-ENOTTY);
 assert(nm_fsync(outer,0x123456789LL,0x765432101LL,1)==-EINVAL);
 nm_set_fop(table_bytes,native,native_control);nm_set_fop(table_bytes,compat,compat_control);nm_set_fop(table_bytes,sync,sync_control);
 result=37;assert(nm_ioctl(outer,0xfedcba98U,0xfedcba9876543210UL)==37&&native_calls==n+1);
 result=-EPERM;assert(nm_ioctl(outer,0xfedcba98U,0xfedcba9876543210UL)==-EPERM&&native_calls==n+2);
 result=19;assert(nm_compat_ioctl(outer,0x1234U,0x87654321UL)==19&&compat_calls==c+1&&native_calls==n+2);
 result=-EFAULT;assert(nm_compat_ioctl(outer,0x1234U,0x87654321UL)==-EFAULT&&compat_calls==c+2);
 result=0;assert(!nm_fsync(outer,0x123456789LL,0x765432101LL,1)&&sync_calls==s+1);
 result=-EIO;assert(nm_fsync(outer,0x123456789LL,0x765432101LL,1)==-EIO&&sync_calls==s+2);
 nm_set_fop(table_bytes,compat,NULL);assert(nm_compat_ioctl(outer,0x1234U,0x87654321UL)==-ENOTTY&&native_calls==n+2);
 void* table=nm_new_file_operations();assert(!IS_ERR(table));
 assert(*(void**)((char*)table+native)==nm_ioctl);
 assert(*(void**)((char*)table+compat)==nm_compat_ioctl);
 assert(*(void**)((char*)table+sync)==nm_fsync);
 assert(*(void**)((char*)table+struct_offset.fop_mmap)==nm_mmap);
 assert(*(void**)((char*)table+struct_offset.fop_release)==nm_release);
 assert(!((struct nm_file_io_ops*)table)->write_iter);nm_discard_operations(table);
 nm_set_file_private(outer,NULL);
 assert(nm_ioctl(outer,0,0)==-ENOTTY&&nm_compat_ioctl(outer,0,0)==-ENOTTY&&nm_fsync(outer,0,1,0)==-EINVAL);
 assert(native_calls==n+2&&compat_calls==c+2&&sync_calls==s+2);
 struct struct_offset saved=struct_offset;
 struct_offset.fop_mmap=sizeof(struct nm_file_io_ops);assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
 struct_offset=saved;struct_offset.file_ops_size=sync;assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
 struct_offset=saved;struct_offset.fop_open=native;assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
 struct_offset=saved;struct_offset.fop_splice_read=compat;assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
 struct_offset=saved;struct_offset.fop_mmap++;assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
  struct_offset=saved;struct_offset.fop_mmap=-8;assert(nm_validate_file_offsets((const void*)&struct_offset)==-EINVAL);
  assert(nm_validate_file_control_offsets((const void*)&struct_offset)==-EINVAL);
  volatile int16_t* fields[]={&struct_offset.fop_open,&struct_offset.fop_release,&struct_offset.fop_mmap,&struct_offset.fop_splice_read};
  const int16_t negative[]={-8,-16,-24,-32768};
  for(unsigned i=0;i<4;i++)for(unsigned j=0;j<4;j++){
    struct_offset=saved;*fields[i]=negative[j];unsigned before=allocations;
    assert(nm_validate_file_offsets((const void*)&struct_offset)==-EINVAL);
    assert(PTR_ERR(nm_new_file_operations())==-EINVAL&&allocations==before);
  }
 struct_offset=saved;assert(allocations==frees);
}
'''


def run(command, log):
    p = subprocess.run(command, text=True, capture_output=True)
    log.write_text(p.stdout + p.stderr)
    p.check_returncode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--configs', type=Path, nargs='+', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    source = PRELUDE
    for name in ('nm_structs.h', 'nm_rules.h', 'nm_offsets.c', 'nm_operations.c', 'nm_file.c'):
        text = (ROOT/'nomount'/name).read_text()
        if name == 'nm_offsets.c':
            text = text.split('#ifndef CONFIG_KPM_BASELINES', 1)[0]
            text = text.replace('__attribute__((section(".data.re_offsets"), used))', '')
        source += text + '\n'
    source += TEST + '\nint main(void){\n'
    profiles = []
    for path in a.configs:
        config = json.loads(path.read_text())
        values = config['offsets']
        if any(values.get(key, -1) < 0 for key in ('file_ops_size', 'fop_mmap', 'fop_release')):
            continue
        source += 'struct_offset=(struct struct_offset){' + ','.join(f'.{k}={v}' for k,v in values.items()) + '};check_target();\n'
        profiles.append({'config': str(path), 'ioctl': values['fop_mmap']-16,
                         'compat_ioctl': values['fop_mmap']-8, 'fsync': values['fop_release']+8})
    assert profiles
    source += 'printf("%u target profiles: control forwarding and refusal boundaries PASS\\n",profiles);return 0;}\n'
    (a.output/'control.c').write_text(source)
    run(['/usr/bin/clang', '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function', '-I', str(ROOT/'nomount'),
         '-fsanitize=address,undefined', '-g', str(a.output/'control.c'), '-o', str(a.output/'control')], a.output/'compile.log')
    run([str((a.output/'control').resolve())], a.output/'run.log')
    receipt = {'scope': 'Developer Tier-3 actual file callback and builder source with host native stubs; not native permissions/concurrency proof',
               'profiles': profiles, 'assert_sites_per_profile': len(re.findall(r'\bassert\s*\([^;]+\);', TEST)),
               'negative_slot_constructor_cases_per_profile':16, 'existing_oracle_changes': [], 'result': 'PASS'}
    (a.output/'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
    print((a.output/'run.log').read_text(),end='')


if __name__ == '__main__':
    main()
