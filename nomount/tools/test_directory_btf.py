#!/usr/bin/env python3
"""在真实目标BTF夹具上追加目录actor编码、参数及共同布局拒绝边界。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout-output', type=Path, required=True)
    parser.add_argument('--btf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads((args.layout_output / 'receipt.json').read_text())
    assert receipt['returncode'] == 0 and receipt['btf_sha256'] == sha(args.btf.read_bytes())
    for path, digest in receipt['sources'].items():
        assert sha((root / path).read_bytes()) == digest
    source = (args.layout_output / 'btf.c').read_text()
    anchor = 'puts("OFFSETS");'
    assert source.count(anchor) == 1
    source = source.replace(anchor, r'''
 struct kpm_btf btf;assert(!nm_get_btf(&btf,&unavailable));
 const struct btf_type* ctx=kpm_btf_type(&btf,"dir_context",4);assert(ctx);
 struct kpm_btf_field field;assert(!kpm_btf_member(&btf,ctx,"actor",&field,0));
 struct btf_type* proto=(void*)btf.type_by_id(btf.data,field.type->size);assert(proto);
 u32 resolved_size=0;const struct btf_type* ret=btf.type_by_id(btf.data,proto->size);
 ret=btf.resolve_size(btf.data,ret,&resolved_size);assert(ret);
 u32* encoding=(void*)(ret+1);u32 saved_encoding=*encoding;
 struct struct_offset saved=struct_offset;
 *encoding=resolved_size==1?8U:32U;
 assert(calculate_btf_directory_offsets()==-EOPNOTSUPP && !memcmp(&saved,(const void*)&struct_offset,sizeof(saved)));
 *encoding=resolved_size==1?(1U<<24|8U):(4U<<24|32U);
 assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);
 *encoding=saved_encoding|0x100U;assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);
 *encoding=saved_encoding;
 u32 saved_info=proto->info;proto->info=(saved_info&~65535U)|5;
 assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);proto->info=saved_info;
 struct btf_param* params=(void*)(proto+1);u32 saved_param=params[2].type;params[2].type=params[0].type;
 assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);params[2].type=saved_param;
 u32 saved_result=proto->size;proto->size=0;assert(calculate_btf_directory_offsets()==-EOPNOTSUPP);proto->size=saved_result;
 struct btf_member* members=(void*)(ctx+1);bool found_pos=false;
 for(u32 i=0;i<(ctx->info&65535);i++)if(!strcmp(btf.name_by_offset(btf.data,members[i].name_off),"pos")){
 u32 offset=members[i].offset;members[i].offset=offset+64;assert(calculate_btf_directory_offsets()==-EINVAL);
 members[i].offset=offset;found_pos=true;break;}
 assert(found_pos&&!calculate_btf_directory_offsets()&&struct_offset.dir_actor_abi==saved.dir_actor_abi);
 puts("actor encoding, arguments, return type, pos layout and restored target: PASS");
 ''' + anchor)
    args.output.mkdir(parents=True, exist_ok=False)
    c = args.output / 'btf.c'
    c.write_text(source)
    command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', '-g', str(c), '-o', str(args.output / 'btf')]
    built = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    run = subprocess.run([str(args.output / 'btf'), str(args.btf)], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    (args.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer BTF host API stubs, not runtime proof',
        'btf_sha256': sha(args.btf.read_bytes()), 'sources': receipt['sources'],
        'generated_source_sha256': sha(source.encode()), 'tool_sha256': sha(Path(__file__).read_bytes()),
        'result': run.stdout}, indent=2) + '\n')
    print('Target BTF actor boundaries: PASS')


if __name__ == '__main__':
    main()
