#!/usr/bin/env python3
"""以目标短窗口验证 GCC 的 cache/key 入口形态及拒绝边界。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'config', 'fixture', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    raw = a.image.read_bytes()
    config = json.loads(a.config.read_text())
    assert hashlib.sha256(raw).hexdigest() == config['kernel_sha256']
    symbols = {n: o for o, t, n in json.loads(a.symbols.read_text())}
    windows = {'register_key_type': 19, 'super_cache_count': 13}
    c = a.fixture.read_text().split('int main(', 1)[0]
    current = (root / 'nomount/nm_offsets.c').read_text()
    for fn in ('nm_check_key_name', 'nm_find_super_cache'):
        from test_directory_abis import function
        assert function(current, fn) in c
    c += 'int main(void){long page=sysconf(_SC_PAGESIZE);void* pages=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(pages!=MAP_FAILED&&!mprotect((char*)pages+page,page,PROT_NONE));\n'
    evidence = {}
    for name, count in windows.items():
        at = symbols[name]
        words = struct.unpack_from('<' + 'I' * count, raw, at)
        evidence[name] = {'offset': at, 'words': words}
        values = ','.join(map(str, words))
        c += '{const uint32_t words[]={' + values + '};uint32_t* edge=(void*)((char*)pages+page-sizeof(words));memcpy(edge,words,sizeof(words));\n'
        if name == 'register_key_type':
            d = words[18] & 0x3ffffff
            if d & (1 << 25):
                d -= 1 << 26
            assert at + 18 * 4 + d * 4 == symbols['strcmp']
            c += 'uintptr_t compare=(uintptr_t)&edge[18]+inst_get_bl_label(edge[18]);assert(!nm_check_key_name(edge,compare));\n'
            check = 'nm_check_key_name(edge,compare)'
            c += 'assert(nm_check_key_name(edge,compare+4)<0);\n'
            c += 'edge[12]|=1U<<22;assert(nm_check_key_name(edge,compare)<0);memcpy(edge,words,sizeof(words));\n'
        else:
            c += 'assert(nm_find_super_cache(edge)==216);\n'
            check = 'nm_find_super_cache(edge)'
        c += f'for(unsigned i=0;i<{count};i++){{memcpy(edge,words,sizeof(words));edge[i]=0xd503201f;assert({check}<0);}}}}\n'
    c += 'assert(!munmap(pages,page*2));puts("PASS: two actual GCC windows, call identity, 32 refusal mutations and guarded ends");return 0;}\n'
    a.output.mkdir(parents=True, exist_ok=False)
    path = a.output / 'shapes.c'
    path.write_text(c)
    r = subprocess.run(['/usr/bin/clang', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-fsanitize=address,undefined', '-g', str(path), '-o', str(a.output / 'shapes')], capture_output=True, text=True)
    (a.output / 'compile.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    r = subprocess.run([str(a.output / 'shapes')], capture_output=True, text=True)
    (a.output / 'run.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    (a.output / 'receipt.json').write_text(json.dumps({'scope': 'Developer two parser windows; not native initialization', 'kernel_sha256': config['kernel_sha256'], 'evidence': evidence, 'result': r.stdout.strip()}, indent=2) + '\n')
    print(r.stdout.strip())


if __name__ == '__main__':
    main()
