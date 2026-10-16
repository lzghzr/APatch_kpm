#!/usr/bin/env python3
"""保留目录与加载Oracle，追加上游小目录及UID预筛选边界。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from test_directory_abis import function

BASE = 'f70894744b10d7aab212d18a9262e905eacef7d9'
ORACLES = {'int': 'dd4faca496c8887b2aa3951bf43903e0013f831ccc0b30e819b6efe7681f65b9',
           'bool': 'e1ce8a76100f6267aed50fc6dff290f091f02633520c2c0cc704d2075814412c'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    old = lambda name: subprocess.check_output(['git', 'show', BASE + ':nomount/' + name], cwd=root).decode()
    new = lambda name: (root / 'nomount' / name).read_text()
    results = []
    for abi, digest in ORACLES.items():
        original = (args.oracle_output / abi / 'contracts.c').read_text()
        assert sha(original.encode()) == digest
        assert original.count(old('nm_rules.h')) == 1
        source = original.replace(old('nm_rules.h'), new('nm_rules.h'))
        names = ['nm_bloom_words_for', 'nm_qhash', 'nm_rebuild_bloom', 'nomount_bsearch_child', 'nm_find_child',
                 'nm_uid_add', 'nm_uid_del', 'nomount_is_uid_blocked']
        for name in names:
            before, after = function(old('nm_rules.c'), name), function(new('nm_rules.c'), name)
            assert source.count(before) == 1, name
            if name == 'nomount_bsearch_child': after = function(new('nm_rules.c'), 'nm_child_matches') + '\n' + after
            if name == 'nm_uid_add': after = '\n'.join(function(new('nm_rules.c'), n) for n in ['nm_uid_bloom_set', 'nm_uid_bloom_test']) + '\n' + after
            source = source.replace(before, after)
        version = re.search(r'^#define NM_KPM_VERSION "([^"]+)"', new('nm_protocol.h'), re.M).group(1)
        source = source.replace('#define NM_KPM_VERSION "0.4.0"', '#define NM_KPM_VERSION "' + version + '"')
        assertions = re.findall(r'\bassert\s*\([^;]+\);', original)
        assert re.findall(r'\bassert\s*\([^;]+\);', source) == assertions
        source = source.replace('int main(void){', 'static int previous_hotpath_main(void){')
        source += r'''
static int full_hash_calls;
static u32 measured_hash(const void* salt,const char* name,unsigned int len){full_hash_calls++;return fixture_hash(salt,name,len);}
static void check_hotpaths(void){
 target();directory_target();set_uid(1000);thread.flags=0;fail_alloc=0;
 nm_full_name_hash_pair=NULL;kf_nm_full_name_hash=measured_hash;
 struct nomount_child_array* children=NULL;
 struct nomount_leaf *a=nm_alloc_leaf("/system/abcde",13),*b=nm_alloc_leaf("/system/axcye",13),*c=nm_alloc_leaf("/system/q",9);
 assert(!IS_ERR(a)&&!IS_ERR(b)&&!IS_ERR(c));
 assert(nm_bloom_words_for(0)==0&&nm_bloom_words_for(1)==0&&nm_bloom_words_for(2)==0&&nm_bloom_words_for(3)==4);
 assert(!nm_insert_child(&children,a)&&children->count==1&&!children->bloom_words);
 assert(!nm_insert_child(&children,b)&&children->count==2&&!children->bloom_words);
 assert(nm_qhash("abcde",5)==nm_qhash("axcye",5)&&nm_qhash("abcde",5)==nm_qhash("azcwe",5));
 full_hash_calls=0;
 assert(nm_find_child(children,"abcde",5)==a&&nm_find_child(children,"axcye",5)==b&&!nm_find_child(children,"azcwe",5));
 assert(!full_hash_calls&&!nm_find_child(children,"",0)&&!nm_find_child(children,NULL,1));
 struct nomount_child_array* held=children;fail_alloc=1;
 assert(nm_insert_child(&children,c)==-ENOMEM&&children==held);fail_alloc=0;
 assert(!nm_insert_child(&children,c)&&children->count==3&&children->bloom_words==4&&held->count==2&&!held->bloom_words);
 full_hash_calls=0;assert(nm_find_child(children,"abcde",5)==a&&full_hash_calls==1);
 assert(nm_find_child(children,"axcye",5)==b&&nm_find_child(children,"q",1)==c&&!nm_find_child(children,"azcwe",5));
 held=children;assert(!nm_remove_child(&children,c)&&children->count==2&&!children->bloom_words&&held->count==3);
 full_hash_calls=0;assert(nm_find_child(children,"abcde",5)==a&&nm_find_child(children,"axcye",5)==b&&!full_hash_calls);
 assert(!nm_remove_child(&children,b)&&children->count==1&&!children->bloom_words);
 assert(!nm_remove_child(&children,a)&&!children);flush_rcu();nm_free_leaf(a);nm_free_leaf(b);nm_free_leaf(c);
 nm_uid_clear();flush_rcu();nm_block_isolated_uids=false;
 assert(!nm_uid_add(1000)&&!nm_uid_add(1256));
 assert(nm_uid_bloom_test(nomount_uids,1512)&&!nomount_is_uid_blocked(1512));
 struct nm_uid_array* previous=nomount_uids;fail_alloc=1;
 assert(nm_uid_del(1000)==-ENOMEM&&nomount_uids==previous&&nomount_is_uid_blocked(1000)&&nomount_is_uid_blocked(1256));fail_alloc=0;
 assert(!nm_uid_del(1000)&&nomount_is_uid_blocked(1256)&&!nomount_is_uid_blocked(1000));
 assert(nm_uid_bloom_test(nomount_uids,1000)&&previous->count==2&&previous->uids[0]==1000);flush_rcu();
 assert(!nm_uid_del(1256)&&!nomount_uids);
 u32 ids[]={0,63,64,255,256,1000,90000,190000,0xffffffffU};
 for(unsigned int i=0;i<sizeof(ids)/sizeof(ids[0]);i++)assert(!nm_uid_add(ids[i]));
 for(unsigned int i=0;i<sizeof(ids)/sizeof(ids[0]);i++)assert(nomount_is_uid_blocked(ids[i]));
 assert(!nomount_is_uid_blocked(1256));
 nm_uid_clear();flush_rcu();assert(!nomount_uids&&!nomount_is_uid_blocked(1000));
 nm_block_isolated_uids=true;assert(nomount_is_uid_blocked(90000)&&nomount_is_uid_blocked(199999)&&!nomount_is_uid_blocked(200000));nm_block_isolated_uids=false;
 assert(!manager_depth&&!rcu_depth&&!q_count);
 puts("small-child collision and 2/3 transition, zero full hash for tiny lookup; UID collision/delete/limits/failures: PASS");
}
int main(void){assert(!previous_hotpath_main());check_hotpaths();return 0;}
'''
        out = args.output / abi
        out.mkdir()
        c = out / 'contracts.c'
        c.write_text(source)
        command = ['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(root / 'nomount'), '-fsanitize=address,undefined', '-g', str(c), '-o', str(out / 'contracts')]
        built = subprocess.run(command, capture_output=True, text=True)
        (out / 'compile.log').write_text(built.stdout + built.stderr)
        built.check_returncode()
        run = subprocess.run([str(out / 'contracts')], capture_output=True, text=True)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        run.check_returncode()
        results.append({'abi': abi, 'oracle_sha256': digest, 'assertions_preserved': len(assertions),
                        'generated_source_sha256': sha(source.encode()), 'result': run.stdout})
    receipt = {'scope': 'Developer host native API fixtures, not kernel concurrency or real latency',
               'sources': {str(p.relative_to(root)): sha(p.read_bytes()) for p in (root / 'nomount').glob('nm*.[ch]')},
               'tool_sha256': sha(Path(__file__).read_bytes()), 'variants': results}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Hotpath int/bool Oracle: PASS;', results[0]['assertions_preserved'], 'preserved assertions each')


if __name__ == '__main__':
    main()
