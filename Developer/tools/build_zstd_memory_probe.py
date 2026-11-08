#!/usr/bin/env python3
"""Build three ZSTD-only Android probes from frozen codec objects; never operates a device."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def run(cmd):
    p = subprocess.run(list(map(str, cmd)), text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stdout + p.stderr)
    return p.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name):
    # Select the declaration containing this name, then its balanced body.
    start = source.rfind('\nstatic ', 0, source.index(name)) + 1
    begin = source.index('{', source.index(name, start))
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--llvm-bin', type=Path, required=True)
    p.add_argument('--baseline-codec', type=Path, required=True)
    p.add_argument('--candidate-codec', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True, help='frozen 251240c module directory')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    out = a.output.resolve()
    old, new, module = a.baseline_codec.resolve(), a.candidate_codec.resolve(), a.module.resolve()
    gen = new / 'generated'
    old_commit = run(['git', '-C', old, 'rev-parse', 'HEAD']).strip()
    new_commit = run(['git', '-C', new, 'rev-parse', 'HEAD']).strip()
    if old_commit != '3f8cfd7c18d8006557e28c77ffd7debca46bd4db' or new_commit != '251240cf7e530ae7224141b552a39f808c59fcb8':
        raise ValueError('codec directories must belong to the specified frozen worktrees')
    # Instrument sources are read from commits, not another role's staged work.
    head = run(['git', '-C', ROOT, 'rev-parse', 'HEAD']).strip()
    source_commit = run(['git', '-C', module, 'rev-parse', 'HEAD']).strip()
    if source_commit != '251240cf7e530ae7224141b552a39f808c59fcb8':
        raise ValueError('module must be the frozen inline02 source')
    for name in ('zram_codec_bench_runner.c', 'zram_codec_bench_bridge.h'):
        (out / name).write_text(run(['git', '-C', ROOT, 'show', f'{head}:Tester/tools/{name}']))
    source = run(['git', '-C', module, 'show', f'{source_commit}:zram_zstd/zram_zstd.c'])
    struct_start = source.index('struct zstd_ctx {')
    struct_end = source.index('};', struct_start) + 2
    bridge = '''#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include "linux/zstd.h"
#include "zs_zstd_config.h"
#include "zram_codec_bench_bridge.h"
#ifndef ENOMEM
#define ENOMEM 12
#endif
static void* bench_vzalloc(unsigned long n) { return calloc(1, n); }
static void bench_vfree(const void* p) { free((void*)p); }
#define kfunc(n) bench_##n
'''
    bridge += source[struct_start:struct_end] + '\n'
    for name in ('zstd_release', 'zstd_params', 'zstd_prepare', 'zstd_encode'):
        bridge += function(source, name) + '\n'
    bridge += '''static struct zstd_ctx context;
const char* zs4_device_bridge_name(unsigned int algorithm) { assert(algorithm == 0); return "zstd"; }
void zs4_device_bridge_init(unsigned int algorithm, size_t* csize, size_t* dsize) {
  assert(algorithm == 0); assert(!zstd_prepare(&context));
  *csize = ZSTD_estimateCCtxSize_usingCParams(zstd_params().cParams);
  *dsize = ZSTD_estimateDCtxSize();
}
void zs4_device_bridge_release(void) { zstd_release(&context); }
unsigned int zs4_device_bridge_compress(const uint8_t* in, uint8_t* packed) {
  size_t n = zstd_encode(context.cctx, packed, 8192, in, 4096);
  assert(!zs_zstd_is_error(n) && n); return n;
}
unsigned int zs4_device_bridge_decompress(const uint8_t* packed, unsigned int length, uint8_t* out) {
  size_t n = ZSTD_decompressDCtx(context.dctx, out, 4096, packed, length);
  assert(!zs_zstd_is_error(n) && n == 4096); return n;
}
'''
    (out / 'bridge.c').write_text(bridge)
    (out / 'bindings.c').write_text('''#include <string.h>
void* (*kf_memcpy)(void*, const void*, size_t) = memcpy;
void* (*kf_memmove)(void*, const void*, size_t) = memmove;
void* (*kf_memset)(void*, int, size_t) = memset;
''')
    (out / 'wrappers.c').write_text('''#include "zs_memory.h"
void* zs_probe_memcpy(void* d, const void* s, size_t n) { return kf_memcpy(d,s,n); }
void* zs_probe_memmove(void* d, const void* s, size_t n) { return kf_memmove(d,s,n); }
void* zs_probe_memset(void* d, int c, size_t n) { return kf_memset(d,c,n); }
''')
    cc = a.llvm_bin / 'aarch64-linux-android31-clang'
    scalar = ['-O2', '-fno-strict-aliasing', '-fno-PIC', '-fno-stack-protector', '-fno-common',
              '-fno-asynchronous-unwind-tables', '-mgeneral-regs-only', '-ffixed-x18',
              '-mno-outline-atomics', '-fno-builtin', '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=']
    include = ['-I' + str(d) for d in (out, module, module / 'compat', gen, gen / 'common')]
    for name in ('bridge', 'bindings', 'wrappers'):
        # bindings uses libc declarations, not the freestanding compatibility headers.
        flags = ['-O2', '-fno-builtin'] if name == 'bindings' else scalar + include
        run([cc, *flags, '-c', out / (name + '.c'), '-o', out / (name + '.o')])
    run([cc, '-O2', '-fno-strict-aliasing', '-I' + str(out), '-c', out / 'zram_codec_bench_runner.c', '-o', out / 'runner.o'])
    def objects(directory):
        return sorted(x for x in directory.rglob('*.o') if x.relative_to(directory).parts[0] in ('common', 'compress', 'decompress'))
    baseline, candidate = objects(old), objects(new)
    if not baseline or [x.relative_to(old) for x in baseline] != [x.relative_to(new) for x in candidate]:
        raise ValueError('frozen codec object inventories differ')
    wrapped = []
    for x in baseline:
        target = out / 'wrapped-objects' / x.relative_to(old)
        target.parent.mkdir(parents=True, exist_ok=True)
        run([a.llvm_bin / 'llvm-objcopy', '--redefine-sym', 'memcpy=zs_probe_memcpy',
             '--redefine-sym', 'memmove=zs_probe_memmove', '--redefine-sym', 'memset=zs_probe_memset', x, target])
        wrapped.append(target)
    results = []
    for mode, objs in [('old_builtin_libc', baseline), ('old_builtin_kpm_route', wrapped), ('new_pointer_route', candidate)]:
        binary = out / mode
        run([cc, '-static', out / 'runner.o', out / 'bridge.o', out / 'bindings.o', out / 'wrappers.o', *objs, '-lm', '-o', binary])
        results.append({'name': mode, 'bytes': binary.stat().st_size, 'sha256': digest(binary)})
    def inventory(label, directory, objs):
        return {'label': label, 'objects': [{'name': str(x.relative_to(directory)), 'sha256': digest(x)} for x in objs]}
    manifest = {'scope': 'Developer diagnostic instrument, Android build only; no device execution or KPM load',
                'instrument_commit': head, 'module_adapter_commit': source_commit,
                'baseline_core_commit': old_commit,
                'candidate_core_commit': source_commit,
                'compiler': run([cc, '--version']).splitlines()[0], 'codec_flags': scalar,
                'sources': {x.name: digest(x) for x in sorted(out.glob('*.[ch]'))},
                'inputs': [inventory('old', old, baseline), inventory('new', new, candidate)],
                'binaries': results,
                'control': 'Same module wrapper, inline error predicate, runner, libc pointer bindings, memory allocation, parameters and 64-page input. Only core memory routing differs.',
                'run': 'algorithm 0 only; existing public source_text.bin must be exactly 262144 bytes',
                'limitations': 'libc targets instead of kernel memory functions; old_builtin_libc calibrates the previous userspace instrument, not the KPM route'}
    (out / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
