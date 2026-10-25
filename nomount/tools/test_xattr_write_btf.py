#!/usr/bin/env python3
"""保持8份既有BTF断言，追加setxattr/独立ACL/只读helper的真实原型核对与反例。"""
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
 struct btf_type*fn=(void*)kpm_btf_type(&b,"vfs_setxattr",12);assert(fn);
 struct btf_type*p=(void*)host_type(&object,fn->size);int context=!nm_btf_named_parameter(&b,p,0,"dentry")?0:nm_btf_context_kind(&b,p);
 struct btf_type*acl=(void*)kpm_btf_type(&b,"do_set_acl",12);int shape=acl?1:0;
 assert(calculate_btf_xattr_write(context,&unavailable)==shape&&!unavailable);
 assert(calculate_btf_xattr_write(-1,&unavailable)==-EOPNOTSUPP);
 assert(calculate_btf_xattr_write(3,&unavailable)==-EOPNOTSUPP);
 assert(calculate_btf_xattr_write(context?0:1,&unavailable)==-EOPNOTSUPP);
 struct btf_param*a=(void*)(p+1);unsigned n=p->info&65535,at=!!context;
 u32 saved=p->info;p->info=(saved&~65535U)|7;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);p->info=saved;
 saved=p->size;p->size=a[at].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);p->size=saved;
 saved=a[at].type;a[at].type=a[at+2].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);a[at].type=saved;
 saved=a[n-1].type;a[n-1].type=a[at].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);a[n-1].type=saved;
 saved=a[n-2].type;a[n-2].type=a[at].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);a[n-2].type=saved;
 if(context){saved=a[0].type;a[0].type=a[at].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);a[0].type=saved;}
 saved=fn->name_off;fn->name_off=0;assert(calculate_btf_xattr_write(context,&unavailable)==-ENOENT);fn->name_off=saved;
 struct btf_type*ro=(void*)kpm_btf_type(&b,"__mnt_is_readonly",12);assert(ro);
 struct btf_type*rp=(void*)host_type(&object,ro->size);struct btf_param*ra=(void*)(rp+1);
 saved=ra[0].type;ra[0].type=a[at].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);ra[0].type=saved;
 saved=rp->size;rp->size=p->size;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);rp->size=saved;
 if(acl){struct btf_type*ap=(void*)host_type(&object,acl->size);struct btf_param*aa=(void*)(ap+1);
  saved=ap->info;ap->info=(saved&~65535U)|4;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);ap->info=saved;
  saved=aa[1].type;aa[1].type=aa[0].type;assert(calculate_btf_xattr_write(context,&unavailable)==-EOPNOTSUPP);aa[1].type=saved;
 }
 api_mode=1;assert(calculate_btf_xattr_write(context,&unavailable)==-ENODATA&&unavailable);
 api_mode=2;assert(calculate_btf_xattr_write(context,&unavailable)==-ENODATA&&!unavailable);api_mode=0;
 assert(calculate_btf_xattr_write(context,&unavailable)==shape&&!unavailable);
 printf("setxattr context=%d argc=%u, independent ACL=%d: 13 base negatives/boundaries + mapped/ACL extras PASS\n",context,n,shape);
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
    query = function((ROOT / 'nomount/nm_btf.c').read_text(), 'calculate_btf_xattr_write')
    rows = []
    for i, (fixture, blob) in enumerate(zip(a.fixtures, a.blobs)):
        source = (fixture / 'btf.c').read_text()
        before = re.findall(r'\bassert\s*\([^;]+\);', source)
        assert source.count('free(blob);') == 1
        source = source.replace('int main(int argc,char**argv)', query+'\nint main(int argc,char**argv)', 1)
        source = source.replace('free(blob);', TEST+'\nfree(blob);', 1)
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
