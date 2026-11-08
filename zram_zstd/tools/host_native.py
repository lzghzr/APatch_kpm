"""Host adapters for ARM64 hook frames and typed assembly entries; no production assertions are replaced."""
NATIVE_ENTRIES = ('compress', 'decompress', 'create_zstd', 'create_lz4', 'create_lz4kd', 'destroy',
                  'setup_zstd', 'setup_lz4', 'setup_lz4kd', 'release')


def native_source(module, source):
    # Only the privileged register read is modeled; production TG1 decoding stays intact.
    source = source.replace('#include <cache.h>', 'static uint64_t read_tcr(uint32_t el);')
    aliases = '\n'.join(f'#define zs_native_{name} zs_native_{name}_impl' for name in NATIVE_ENTRIES)
    source = source.replace('#include "zs_native.h"', aliases + '\n' + (module / 'zs_native.h').read_text())
    source = source.replace('#include "zs_native.c"', (module / 'zs_native.c').read_text())
    return source.replace('#include "zs_native_btf.c"', (module / 'zs_native_btf.c').read_text())


def hook_frame(source, native_fixture=False):
    source = source.replace('uint64_t arg0, arg1, ret;', 'uint64_t arg0, arg1, ret; int skip_origin;')
    stub = 'static void hook_unwrap(void* func, void* before, void* after);\n'
    if not native_fixture:
        stub = 'static void hook_unwrap(void* func, void* before, void* after) { __builtin_trap(); }\n'
    return stub + source
