#!/usr/bin/env python3
"""在8份既有BTF断言后追加setattr布局、回调与原生helper反例。"""
import argparse
import json
from pathlib import Path
import re
from test_directory_abis import function
from test_file_control import run

ROOT = Path(__file__).resolve().parents[2]
TEST = r'''
{
 struct kpm_btf b={&object,host_find,host_type,host_name,host_size};bool unavailable=false;
 struct btf_type*ops=(void*)kpm_btf_type(&b,"inode_operations",4);
 struct btf_type*proto=(void*)nm_btf_callback_prototype(&b,ops,"setattr");
 int context=(proto->info&65535)==2?0:nm_btf_context_kind(&b,proto);assert(context>=0&&context<=2);
 struct_offset.getattr_context_kind=context;struct_offset.permission_abi=context+1;
 struct nm_setattr_layout layout;int result=calculate_btf_setattr(&layout,&unavailable);
 if(result)fprintf(stderr,"setattr positive returned %d\n",result);
 assert(!result&&!unavailable&&layout.slot==104&&layout.context==context&&layout.lock_kind==1);
 assert(layout.lock_offset==EXPECTED_LOCK);
 struct btf_type*inode=(void*)kpm_btf_type(&b,"inode",4);struct btf_member*m=(void*)(inode+1);unsigned hit=0;
 for(unsigned i=0;i<(inode->info&65535);i++)if(!strcmp(host_name(&object,m[i].name_off),"i_rwsem")){
  u32 saved=m[i].offset;m[i].offset+=8;assert(calculate_btf_setattr(&layout,&unavailable)<0);m[i].offset=saved;
  saved=m[i].type;m[i].type=proto->size;assert(calculate_btf_setattr(&layout,&unavailable)<0);m[i].type=saved;hit++;
 }assert(hit==1);
 struct btf_type*attr=(void*)kpm_btf_type(&b,"iattr",4);m=(void*)(attr+1);hit=0;
 for(unsigned i=0;i<(attr->info&65535);i++)if(!strcmp(host_name(&object,m[i].name_off),"ia_valid")){
  u32 saved=m[i].offset;m[i].offset+=32;assert(calculate_btf_setattr(&layout,&unavailable)<0);m[i].offset=saved;hit++;
 }assert(hit==1);
 u32 saved=proto->info;proto->info=(saved&~65535U)|1;assert(calculate_btf_setattr(&layout,&unavailable)<0);proto->info=saved;
 struct btf_param*params=(void*)(proto+1);saved=params[context?2:1].type;params[context?2:1].type=params[context?1:0].type;
 assert(calculate_btf_setattr(&layout,&unavailable)<0);params[context?2:1].type=saved;
 struct btf_type*fn=(void*)kpm_btf_type(&b,"notify_change",12);struct btf_type*p=(void*)host_type(&object,fn->size);
 params=(void*)(p+1);unsigned last=(p->info&65535)-1;saved=params[last].type;params[last].type=params[last-1].type;
 assert(calculate_btf_setattr(&layout,&unavailable)<0);params[last].type=saved;
 fn=(void*)kpm_btf_type(&b,"__mnt_is_readonly",12);saved=fn->name_off;fn->name_off=0;
 assert(calculate_btf_setattr(&layout,&unavailable)<0);fn->name_off=saved;
 fn=(void*)kpm_btf_type(&b,"down_write_killable",12);p=(void*)host_type(&object,fn->size);saved=p->info;p->info=(saved&~65535U)|2;
 assert(calculate_btf_setattr(&layout,&unavailable)<0);p->info=saved;
 api_mode=1;assert(calculate_btf_setattr(&layout,&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_setattr(&layout,&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(!calculate_btf_setattr(&layout,&unavailable));printf("setattr slot=%d lock=%d context=%d; 8 mutations + 2 API boundaries PASS\n",layout.slot,layout.lock_offset,layout.context);
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fixtures', type=Path, nargs='+', required=True)
    p.add_argument('--blobs', type=Path, nargs='+', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert len(a.fixtures) == len(a.blobs) == 8
    a.output.mkdir(parents=True, exist_ok=False)
    header = (ROOT / 'nomount/nm_structs.h').read_text()
    layout = 'struct nm_setattr_layout {' + header.split('struct nm_setattr_layout {', 1)[1].split('};', 1)[0] + '};'
    query = function((ROOT / 'nomount/nm_btf.c').read_text(), 'calculate_btf_setattr')
    rows = []
    for i, (fixture, blob) in enumerate(zip(a.fixtures, a.blobs)):
        source = (fixture / 'btf.c').read_text()
        before = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert source.count('free(blob);') == 1
        source = source.replace('int main(int argc,char**argv)', layout+'\n'+query+'\nint main(int argc,char**argv)', 1)
        source = source.replace('free(blob);', TEST.replace('EXPECTED_LOCK', str(152 if i in (5, 6) else 160))+'\nfree(blob);', 1)
        after = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert after[:len(before)] == before
        out = a.output / f'btf-{i}'
        out.mkdir()
        (out / 'btf.c').write_text(source)
        run(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-fsanitize=address,undefined',
             str(out / 'btf.c'), '-o', str(out / 'btf')], out / 'compile.log')
        run([str((out / 'btf').resolve()), str(blob.resolve())], out / 'run.log')
        rows.append({'index': i, 'prior_assert_sites': len(before), 'added_assert_sites': len(after)-len(before), 'result': (out / 'run.log').read_text().strip()})
    (a.output / 'receipt.json').write_text(json.dumps(rows, indent=2)+'\n')
    print(rows)


if __name__ == '__main__':
    main()
