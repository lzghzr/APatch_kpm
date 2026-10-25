#!/usr/bin/env python3
"""保留1742条业务断言；以尺寸/extent边界输入检查动态自建表门控，不构造厂商ABI。"""
import argparse
import json
from pathlib import Path
from test_directory_abis import function
from test_inode_lock import assertions
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
STUBS = r'''
static int bounds_btf_rc, bounds_tail_rc, bounds_link;
static bool bounds_unavailable;
static unsigned bounds_tail_calls;
static int bounds_btf_sizes(bool*u){*u=bounds_unavailable;return bounds_btf_rc;}
static int bounds_function_sizes(void){return 0;}
static int bounds_btf_control(bool*u){*u=bounds_unavailable;return bounds_btf_rc;}
static int bounds_control_fields(void){return 0;}
static int bounds_callbacks(void){return 0;}
static int bounds_tail(void){bounds_tail_calls++;return bounds_tail_rc;}
static int bounds_registration(const uint32_t*s,uintptr_t c,int*l,int*a,int*o){*l=0;*a=*o=-1;return bounds_link;}
'''
TEST = r'''
static void check_owned_bounds(void){
 struct struct_offset saved=struct_offset;bool fallback=nm_owned_operation_fallback;
 volatile int16_t*fields[]={&struct_offset.inode_ops_size,&struct_offset.dentry_ops_size,&struct_offset.key_type_size};
 const enum nm_ops_kind kinds[]={NM_INODE_OPS,NM_DENTRY_OPS,NM_KEY_TYPE};
 struct_offset.file_ops_size=216;struct_offset.inode_ops_size=256;struct_offset.super_ops_size=232;
 struct_offset.dentry_ops_size=128;struct_offset.key_type_size=136;
 struct_offset.mutex_size=32;struct_offset.mutex_no_lockdep=1;struct_offset.key_callbacks=24;struct_offset.key_preparse_data=40;
 bounds_btf_rc=0;bounds_unavailable=false;bounds_tail_rc=-EOPNOTSUPP;
 for(unsigned i=0;i<3;i++){
  int prior=*fields[i];*fields[i]=NM_OWNED_OPERATIONS_CAPACITY;
  assert(nm_owned_operation_size(kinds[i])==512);
  assert(!bounds_prepare_sizes());
  void*p=nm_new_operations(kinds[i],NULL);assert(!IS_ERR_OR_NULL(p));
  assert(!memcmp(p,(unsigned char[512]){0},512));nm_discard_operations(p);
  if(kinds[i]==NM_KEY_TYPE)assert(!nm_validate_control_layout());
  const int oversized[]={NM_OWNED_OPERATIONS_CAPACITY+1,1024,4096};
  for(unsigned j=0;j<3;j++){
   *fields[i]=oversized[j];
   assert(nm_owned_operation_size(kinds[i])==-E2BIG);
   assert(bounds_prepare_sizes()==-E2BIG);
   assert(PTR_ERR(nm_new_operations(kinds[i],NULL))==-EINVAL);
   if(kinds[i]==NM_KEY_TYPE)assert(nm_validate_control_layout()==-E2BIG);
  }
  *fields[i]=prior;
 }
 // 控制准备晚于operation sizes；此处直接执行真实准备函数，尾部推导仅返回状态。
 nm_owned_operation_fallback=true;bounds_btf_rc=-ENODATA;bounds_unavailable=true;
 bounds_tail_calls=0;struct_offset.key_type_size=512;
 assert(!bounds_prepare_control()&&bounds_tail_calls==1&&nm_owned_operation_size(NM_KEY_TYPE)==512);
 struct_offset.key_type_size=136;
 assert(!bounds_prepare_control()&&bounds_tail_calls==2&&nm_owned_operation_size(NM_KEY_TYPE)==136);
 struct_offset.key_type_size=513;
 assert(bounds_prepare_control()==-E2BIG&&bounds_tail_calls==3);
 struct_offset.key_type_size=1024;
 assert(bounds_prepare_control()==-E2BIG&&bounds_tail_calls==4);
 // 明确的已知超界错误不能被“未覆盖尾部”降级吞掉。
 struct_offset.key_type_size=136;bounds_tail_rc=-E2BIG;
 assert(bounds_prepare_control()==-E2BIG);
 bounds_tail_rc=-EINVAL;assert(bounds_prepare_control()==-EINVAL);
 bounds_tail_rc=-EOPNOTSUPP;struct_offset.key_type_size=-1;
 assert(!bounds_prepare_control()&&nm_owned_operation_size(NM_KEY_TYPE)==512&&struct_offset.key_type_size==-1);
 // 原表复制按精确尺寸独立分配；不是向512字节容量复制/截断。
 unsigned char original[1024];memset(original,0xa5,sizeof(original));struct_offset.inode_ops_size=1024;
 void*copy=nm_new_operations(NM_INODE_OPS,original);
 assert(!IS_ERR_OR_NULL(copy)&&!memcmp(copy,original,sizeof(original)));nm_discard_operations(copy);
 // 只向“已解析注册link的消费者”注入数值，不伪造目标机器码/ABI。
 bounds_link=512-sizeof(struct nm_key_type_tail);assert(!bounds_check_key_name(NULL,0));
 bounds_link++;assert(bounds_check_key_name(NULL,0)==-E2BIG);
 bounds_link=1024;assert(bounds_check_key_name(NULL,0)==-E2BIG);
 bounds_link=-EOPNOTSUPP;assert(bounds_check_key_name(NULL,0)==-EOPNOTSUPP);
 struct_offset=saved;nm_owned_operation_fallback=fallback;
 puts("owned bounds: 512 accepted; 513/1024/4096 rejected; uncovered known-in-bound tail retained; unknown remains unknown PASS");
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('oracle-output', 'cli-source', 'reference-image', 'image', 'output'):
        p.add_argument('--' + n, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    operations = (ROOT / 'nomount/nm_operations.c').read_text()
    aliases = function(operations, 'nm_prepare_operation_sizes').replace('nm_prepare_operation_sizes(', 'bounds_prepare_sizes(', 1).replace('calculate_btf_operation_sizes(', 'bounds_btf_sizes(').replace('calculate_function_operation_sizes(', 'bounds_function_sizes(')
    aliases += '\n' + function(offsets, 'nm_prepare_control_layout').replace('nm_prepare_control_layout(', 'bounds_prepare_control(', 1).replace('calculate_btf_control_layout(', 'bounds_btf_control(').replace('calculate_function_control_offsets(', 'bounds_control_fields(').replace('calculate_function_key_callbacks(', 'bounds_callbacks(').replace('calculate_function_key_type_size(', 'bounds_tail(')
    aliases += '\n' + function(offsets, 'nm_check_key_name').replace('nm_check_key_name(', 'bounds_check_key_name(', 1).replace('nm_find_key_registration(', 'bounds_registration(')
    rows = []
    for abi in ('int', 'bool'):
        original = (a.oracle_output / abi / 'contracts.c').read_text()
        before = assertions(original)
        assert len(before) == 1742
        source = original
        owned = function(offsets, 'nm_owned_operation_size')
        # 既有业务夹具默认static；仅尺寸消费者用真实动态实现，其余Oracle表达式不变。
        source = source.replace(function(source, 'nm_owned_operation_size'), '\n#undef CONFIG_KPM_BASELINES\n' + owned + '\n#define CONFIG_KPM_BASELINES 1\n', 1)
        validate = 'static int nm_owned_operation_size(enum nm_ops_kind);\n#undef CONFIG_KPM_BASELINES\n' + function(offsets, 'nm_validate_control_layout') + '\n#define CONFIG_KPM_BASELINES 1\n'
        source = source.replace(function(source, 'nm_validate_control_layout'), validate, 1)
        source = source.replace(function(source, 'nm_new_operations'), function(operations, 'nm_new_operations'), 1)
        assert assertions(source) == before
        source = source.replace('int main(int argc,char**argv)', 'static int previous_bounds_main(int argc,char**argv)', 1)
        source += '\n' + STUBS + '\n#undef CONFIG_KPM_BASELINES\n' + aliases + '\n#define CONFIG_KPM_BASELINES 1\n' + TEST
        source += '\nint main(int argc,char**argv){assert(!previous_bounds_main(argc,argv));check_owned_bounds();return 0;}\n'
        assert assertions(source)[:1742] == before
        out = a.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread', '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', str(out / 'contracts.c'), str(a.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str(a.reference_image.resolve()), str(a.image.resolve())], out / 'run.log')
        rows.append({'abi': abi, 'original_assert_sites': 1742, 'added_assert_sites': len(assertions(source)) - 1742, 'total_assert_sites': len(assertions(source)), 'result': 'PASS'})
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer numeric size/extent boundary checks and preserved business Oracle; preparation status stubs, no synthetic vendor kernel or native registration', 'migrations': [], 'unknown_minus_one': 'existing 512 fallback retained; no upper bound proven', 'rows': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
