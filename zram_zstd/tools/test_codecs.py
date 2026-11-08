#!/usr/bin/env python3
"""Developer host selfcheck of production registrations, display and all three codecs."""
import argparse
import ctypes.util
import json
from pathlib import Path
import re
import subprocess
from prepare_codec import prepare
from host_native import native_source, hook_frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lz4-library', help='independently installed liblz4')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    prelude = (module / 'tools/selfcheck_fixture.c').read_text().split('/* ENTRIES */')[0]
    prelude = prelude[:prelude.index('static void* display_lookup')]
    prelude = prelude.replace('static void test_display(void);', '')
    production = native_source(module, (module / 'zram_zstd.c').read_text())
    for name in ('zs_structs.h', 'zs_offsets.c', 'zs_btf.c', 'zs_display.c', 'zs_lz4_config.h', 'zs_lz4kd.c'):
        production = production.replace(f'#include "{name}"', (module / name).read_text())
    production = re.sub(r'^#include (?!"zs_zstd_config.h").*\n', '', production, flags=re.M)
    production = production.replace('__attribute__((section(".data.re_offsets"), used))', '')
    common = (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    source = (module / 'tools/codec_fixture.c').read_text()
    display = (module / 'tools/selfcheck_fixture.c').read_text().split('// 显示生产代码', 1)[1]
    source = source.replace('/* DISPLAY_FIXTURE */', '// 显示生产代码' + display)
    source = source.replace('/* LZ4KD_TESTS */', (module / 'tools/lz4kd_fixture.h').read_text() + '\n' +
                            (module / 'tools/lz4kd_fast_fixture.h').read_text() + '\n' +
                            (module / 'tools/memory_fixture.h').read_text())
    native = (module / 'tools/references/linux-6.6-zstd-compress-module.c').read_text()
    native = native[native.index('#define ZSTD_FORWARD_IF_ERR'):native.index('int zstd_min_clevel')]
    native = native.replace('zstd_cctx_init(', 'reference_zstd_cctx_init(')
    native = re.sub(r'\bzstd_cctx\b', 'ZSTD_CCtx', native)
    native = re.sub(r'\bzstd_parameters\b', 'ZSTD_parameters', native)
    alignment = (module / 'tools/native_alignment_fixture.h').read_text()
    alignment = alignment.replace('/* NATIVE_ZSTD_PARAMETERS */', native + '\n#undef ZSTD_FORWARD_IF_ERR\n')
    source = source.replace('/* NATIVE_ALIGNMENT_TESTS */', alignment)
    source = source.replace('/* PAGE_SIZE_TESTS */', (module / 'tools/page_size_fixture.h').read_text())
    source = source.replace('/* UTILITIES */', common).replace('/* BTF */', (module / 'tools/btf_fixture.h').read_text())
    # Keep the original lookup implementation and assertions; wrap only the generated host fixture.
    source = source.replace('static void* lookup(const char* name) {', 'static void* codec_lookup(const char* name) {', 1)
    symbol_fixture = (module / 'tools/symbol_lookup_fixture.h').read_text()
    source = source.replace('int main(int argc, char** argv) {', symbol_fixture + '\nint main(int argc, char** argv) {')
    source = source.replace('  lz4kd_tests();', '  lz4kd_tests();\n  lz4kd_fast_tests();\n  zs_memory_tests();\n  zs_zstd_error_tests();\n  symbol_lookup_tests();')
    source = hook_frame(prelude + source).replace('/* PRODUCTION */', production)
    path = args.output / 'fixture.c'
    path.write_text(source)
    generated = args.output / 'codec'
    prepare(module, generated)
    binary = args.output / 'fixture'
    common_cmd = [
        'clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-Wno-pragma-once-outside-header',
        '-DXXH_NO_STDLIB', '-DXXH_STATIC_LINKING_ONLY=', '-fno-strict-aliasing',
        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        '-I' + str(module), '-I' + str(module / 'compat'), '-I' + str(generated), '-I' + str(generated / 'common'),
        '-I' + str(module / 'upstream/lz4'), '-I' + str(module / 'upstream/lz4kd'),
        '-include', str(module / 'zs_lz4_config.h'), '-include', str(module / 'zs_lz4kd_config.h'),
        '-include', str(module / 'upstream/lz4kd/lz4kd.h')
    ]
    lz4_object = args.output / 'lz4.o'
    result = subprocess.run([*common_cmd, '-O3', '-c', str(module / 'upstream/lz4/lz4.c'), '-o', str(lz4_object)],
                            capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    cmd = [*common_cmd, str(path), *map(str, sorted(generated.rglob('*.c'))), str(lz4_object),
           str(module / 'zs_lz4kd_encode.c'), str(module / 'tools/host_memory.c'), str(module / 'zs_lz4kd_decode.c'),
           str(module / 'upstream/lz4kd/lz4kd_decode.c'), '-o', str(binary)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    with (args.output / 'compile.log').open('a') as log:
        log.write(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    library = args.lz4_library or ctypes.util.find_library('lz4')
    if not library:
        raise RuntimeError('independent liblz4 unavailable')
    zstd_library = ctypes.util.find_library('zstd')
    if not zstd_library:
        raise RuntimeError('independent libzstd unavailable')
    result = subprocess.run([str(binary), library, zstd_library], text=True, capture_output=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    if result.stderr:
        raise RuntimeError(result.stderr)
    receipt = {'scope': 'Developer ASan/UBSan production codec/registration/display host contracts; not native Crypto/zram proof',
               'assert_sites': len(re.findall(r'\bassert\s*\(', source)),
               'library': str(library), 'zstd_library': str(zstd_library), 'result': 'PASS', 'stdout': result.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(result.stdout)


if __name__ == '__main__':
    main()
