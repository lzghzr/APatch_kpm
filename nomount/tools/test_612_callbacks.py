#!/usr/bin/env python3
"""保留1907处冻结业务Oracle，执行独立file布局、回调前部和分列时间。"""
import argparse
import json
from pathlib import Path
import re
import subprocess

from test_directory_abis import function

ROOT = Path(__file__).resolve().parents[2]


def assertions(text):
    return re.findall(r'\bassert\s*\([^;]+\);', text)


def run(command, log):
    result = subprocess.run(command, capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    result.check_returncode()


TEST = r'''
static struct file* p612_backing;
static unsigned p612_reads,p612_writes;
static long p612_read(struct kiocb* request,struct iov_iter* iter){
 struct nm_kiocb_head* r=(void*)request;assert(r->ki_filp==p612_backing&&iter==(void*)99);
 p612_reads++;r->ki_pos+=3;return 3;
}
static long p612_write(struct kiocb* request,struct iov_iter* iter){
 struct nm_kiocb_head* r=(void*)request;assert(r->ki_filp==p612_backing&&iter==(void*)99);
 p612_writes++;return -ENOSPC;
}
static void p612_check(void){
 security_fixture_reset();security_target();
 struct_offset=p612_offsets;
 assert(!validate_offsets()&&!nm_validate_file_offsets((const void*)&struct_offset));
 assert(!nm_validate_inode_offsets((const void*)&struct_offset)&&!nm_validate_directory_offsets((const void*)&struct_offset));
 assert(nm_file_path_offset((const void*)&struct_offset)==64&&nm_file_io_start((const void*)&struct_offset)==16);
 _Alignas(128) unsigned char outer[1024]={0},real[1024]={0},ops[512]={0},inode[1024]={0},source[1024]={0};
 struct inode* real_inode=(void*)source;
 *(void**)(real+struct_offset.file_inode_ops)=real_inode;
 *(void**)(real+struct_offset.file_operations)=ops;
 *(struct nm_path*)(real+struct_offset.file_path)=(struct nm_path){(void*)7,(void*)8};
 *(u32*)(real+struct_offset.file_flags)=0x87654321U;
 assert(nm_file_inode(real)==real_inode&&nm_file_ops(real)==ops&&nm_file_path(real)->mnt==(void*)7);
 assert(nm_file_flags(real)==0x87654321U&&!nm_file_io(NULL));
 nm_set_file_private(outer,real);p612_backing=(void*)real;
 nm_set_fop(ops,40,p612_read);nm_set_fop(ops,48,p612_write);
 struct nm_kiocb_head request={.ki_filp=(void*)outer,.ki_pos=11};
 assert(nm_read_iter((void*)&request,(void*)99)==3&&request.ki_filp==(void*)outer&&request.ki_pos==14&&p612_reads==1);
 assert(nm_write_iter((void*)&request,(void*)99)==-ENOSPC&&request.ki_filp==(void*)outer&&p612_writes==1);
 request.ki_complete=(void*)1;assert(nm_read_iter((void*)&request,(void*)99)==-EOPNOTSUPP&&p612_reads==1);
 assert(nm_write_iter((void*)&request,(void*)99)==-EOPNOTSUPP&&p612_writes==1);request.ki_complete=NULL;
 *(void**)(real+struct_offset.file_operations)=NULL;
 assert(nm_read_iter((void*)&request,(void*)99)==-EINVAL);
 assert(nm_write_iter((void*)&request,(void*)99)==-EINVAL);
 void* table=nm_new_file_operations();assert(!IS_ERR(table));
 assert(nm_operation_callback(table,16)==nm_llseek&&nm_operation_callback(table,40)==nm_read_iter);
 assert(!nm_operation_callback(table,8)&&!nm_operation_callback(table,32));nm_discard_operations(table);
 struct nm_inode_split_size_times* from=(void*)(source+80);struct nm_inode_split_size_times* to=(void*)(inode+80);
 from->i_size=123;
 for(unsigned n=0;n<3;n++){from->seconds[n]=-7+(int)n;from->nanoseconds[n]=900+n;}
 *(u32*)(inode+124)=0xdeadbeefU;*(u32*)(source+124)=0x12345678U;
 *(u64*)(inode+128)=0x123456789abcdef0ULL;
 nm_copy_inode_size_times(inode,source);
 assert(to->i_size==123&&nm_inode_size_times_equal(inode,source));
 assert(*(u32*)(inode+124)==0xdeadbeefU&&*(u64*)(inode+128)==0x123456789abcdef0ULL);
 for(unsigned n=0;n<3;n++){
  to->seconds[n]++;assert(!nm_inode_size_times_equal(inode,source));to->seconds[n]--;
  to->nanoseconds[n]++;assert(!nm_inode_size_times_equal(inode,source));to->nanoseconds[n]--;
 }
 nm_initialize_directory_inode(inode,source,765,(void*)11,(void*)12);
 assert(nm_inode_size(inode)==4096&&to->seconds[2]==from->seconds[2]&&to->nanoseconds[2]==from->nanoseconds[2]);
 assert(*(u32*)(inode+124)==0xdeadbeefU);
 struct struct_offset bad=struct_offset;bad.file_layout=-1;assert(nm_validate_file_offsets(&bad)==-EOPNOTSUPP);
 bad=struct_offset;bad.file_operations=bad.file_inode_ops;assert(nm_validate_file_offsets(&bad)==-EINVAL);
 bad=struct_offset;bad.file_path=bad.file_position;assert(nm_validate_file_offsets(&bad)==-EINVAL);
 bad=struct_offset;bad.fop_io_bias=-1;assert(nm_validate_file_offsets(&bad)==-EINVAL);
 bad=struct_offset;bad.inode_times_layout=-1;assert(nm_validate_inode_offsets(&bad)==-EOPNOTSUPP);
 bad=struct_offset;bad.dentry_lock=bad.dentry_ops;assert(nm_validate_directory_offsets(&bad)==-EINVAL);
 acl_reset();assert(!p612_static_nm_activate_xattr_reads_locked()&&nm_xattr_reads_ready&&xr_count==3&&nm_xattr_get_args==5);
 acl_reset();acl_mode=0;assert(p612_static_nm_activate_xattr_reads_locked()==-ENODATA&&!xr_count);
 acl_reset();acl_error=-EINVAL;assert(p612_static_nm_activate_xattr_reads_locked()==-EINVAL&&!xr_count);
 xw_reset(2,true);assert(!p612_static_nm_activate_xattr_writes_locked()&&nm_xattr_writes_ready&&xw_count==2&&nm_xattr_write_status==-EOPNOTSUPP);
 xw_reset(2,true);xw_btf_missing=true;assert(p612_static_nm_activate_xattr_writes_locked()==-ENODATA&&!xw_count);
 xw_reset(2,true);xw_query_error=-EINVAL;assert(p612_static_nm_activate_xattr_writes_locked()==-EINVAL&&!xw_count);
 xf_original=calloc(1,xf_size);xf_image=mmap(NULL,xf_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(xf_original&&xf_image!=MAP_FAILED);
 xf_reset();assert(!p612_static_nm_activate_xattr_extra_locked()&&!xf_count);
 xf_reset();struct_offset.getattr_context_kind=nm_xattr_set_context=2;xf_mode=1;xf_unavailable=false;xf_has_acl=true;
 assert(!p612_static_nm_activate_xattr_extra_locked()&&nm_xattr_extra_ready&&xf_count==3);
 xf_reset();struct_offset.getattr_context_kind=nm_xattr_set_context=2;assert(p612_static_nm_activate_xattr_extra_locked()==-ENODATA&&!xf_count);
 xf_reset();struct_offset.getattr_context_kind=nm_xattr_set_context=2;xf_mode=1;xf_unavailable=false;xf_btf_error=-EINVAL;
 assert(p612_static_nm_activate_xattr_extra_locked()==-EINVAL&&!xf_count);
 assert(!munmap(xf_image,xf_size));free(xf_original);
 nm_discard_directory_view();puts("6.12 callbacks: independent fields, shifted I/O, split time without generation overwrite, rejected overlaps PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('oracle-output', 'offsets', 'reference-image', 'image', 'legacy-image', 'cli-source', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    current_offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    fields = re.findall(r'int16_t\s+(\w+);', current_offsets.split('};', 1)[0])
    values = json.loads(args.offsets.read_text())['offsets']
    assert set(values) == set(fields)
    changed = {
        'nm_offsets.c': ['nm_file_ops', 'nm_file_flags', 'nm_file_path', 'validate_offsets', 'nm_validate_inode_offsets',
                         'nm_validate_file_offsets', 'nm_validate_directory_offsets', 'nm_initialize_directory_inode',
                         'nm_copy_backing_inode_attributes'],
        'nm_file.c': ['nm_read_iter', 'nm_write_iter', 'nm_validate_file_control_offsets', 'nm_new_file_operations'],
        'nm_setattr.c': ['nm_setattr_context'],
        'nm_directory.c': ['nm_directory_llseek', 'nm_install_directory'],
        'nm_virtual_directory.c': ['nm_prepare_virtual_directory_engine'],
        'nm_backing_inode.c': ['nm_prepare_backing_inode_engine', 'nm_revalidate_backing_child'],
        'nm_xattr.c': ['nm_activate_xattr_reads_locked'],
        'nm_xattr_write.c': ['nm_activate_xattr_writes_locked'],
        'nm_xattr_extra.c': ['nm_activate_xattr_extra_locked'],
    }
    rows = []
    for abi in ('int', 'bool'):
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        old = assertions(original)
        assert len(old) == 1907
        header = re.search(r'#ifndef __NM_STRUCTS_H\b.*?#endif', original, re.S)
        assert header and original.count('#ifndef __NM_STRUCTS_H') == 1
        current_header = (ROOT / 'nomount/nm_structs.h').read_text()
        source = original.replace(header.group(), current_header[current_header.index('#ifndef'):].rstrip(), 1)
        declaration = re.search(r'struct struct_offset\s*\{[^}]+\};', source).group()
        source = source.replace(declaration, current_offsets.split('};', 1)[0].split('\n', 1)[1] + '};', 1)
        for file, names in changed.items():
            body = (ROOT / 'nomount' / file).read_text()
            for name in names:
                previous = function(source, name)
                assert source.count(previous) == 1
                replacement = function(body, name)
                lookup = {'nm_xattr.c': 'acl_lookup', 'nm_xattr_write.c': 'xs_runtime_lookup', 'nm_xattr_extra.c': 'xf_lookup'}.get(file)
                if lookup:
                    replacement = replacement.replace('kallsyms_lookup_name_by_suffix', lookup)
                if file == 'nm_xattr_write.c':
                    replacement = replacement.replace('hook_wrap(', 'xw_wrap(')
                if file == 'nm_xattr_extra.c':
                    replacement = replacement.replace('hook_wrap(', 'xf_wrap(').replace('hook_wrap3(', 'xf_wrap3(')
                source = source.replace(previous, replacement, 1)
        for after, names in {'nm_file_ops': ['nm_file_path_offset', 'nm_file_io_start', 'nm_file_io_end', 'nm_file_io'],
                             'nm_inode_size': ['nm_copy_inode_size_times', 'nm_inode_size_times_equal']}.items():
            marker = function(source, after)
            source = source.replace(marker, marker + '\n' + '\n'.join(function(current_offsets, n) for n in names), 1)
        cold = function((ROOT / 'nomount/nm_backing_inode.c').read_text(), 'nm_prepare_backing_inode_engine')
        cold = cold.replace('nm_prepare_backing_inode_engine(', 'cold_nm_prepare_backing_inode_engine(', 1).replace('nm_prepare_backing_inode_functions(', 'cold_nm_prepare_backing_inode_functions(')
        at = cold.index('{') + 1
        cold = cold[:at] + '\n cold_note("nm_prepare_backing_inode_engine");' + cold[at:]
        source = source.replace(function(source, 'cold_nm_prepare_backing_inode_engine'), cold, 1)
        assert assertions(source) == old
        source = source.replace('int main(int argc,char**argv)', 'static int previous_612_main(int argc,char**argv)', 1)
        source += '\nstatic const struct struct_offset p612_offsets={' + ','.join(f'.{n}={values[n]}' for n in fields) + '};\n'
        for file, name, lookup in [('nm_xattr.c', 'nm_activate_xattr_reads_locked', 'acl_lookup'),
                                   ('nm_xattr_write.c', 'nm_activate_xattr_writes_locked', 'xw_lookup'),
                                   ('nm_xattr_extra.c', 'nm_activate_xattr_extra_locked', 'xf_lookup')]:
            body = function((ROOT / 'nomount' / file).read_text(), name)
            body = body.replace(name + '(', 'p612_static_' + name + '(', 1).replace('kallsyms_lookup_name_by_suffix', lookup)
            if file == 'nm_xattr_write.c':
                body = body.replace('hook_wrap(', 'xw_wrap(')
            if file == 'nm_xattr_extra.c':
                body = body.replace('hook_wrap(', 'xf_wrap(').replace('hook_wrap3(', 'xf_wrap3(')
            source += '\n#define CONFIG_KPM_BASELINES 1\n' + body + '\n'
        source += TEST + '\nint main(int argc,char**argv){assert(!previous_612_main(argc,argv));p612_check();return 0;}\n'
        assert assertions(source)[:1907] == old
        out = args.output / abi
        out.mkdir()
        (out / 'contracts.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-Wno-invalid-noreturn', '-pthread',
             '-fno-builtin', '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', '-g', str(out / 'contracts.c'),
             str(args.cli_source), '-o', str(out / 'contracts')], out / 'compile.log')
        run([str((out / 'contracts').resolve()), str(args.reference_image.resolve()), str(args.image.resolve()),
             str(args.legacy_image.resolve())], out / 'run.log')
        rows.append({'abi': abi, 'preserved_assert_sites': len(old), 'added_assert_sites': len(assertions(source)) - len(old)})
    (args.output / 'receipt.json').write_text(json.dumps({'oracle_migrations': [], 'host': rows}, indent=2) + '\n')
    print(rows)


if __name__ == '__main__':
    main()
