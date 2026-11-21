#!/usr/bin/env python3
"""Run the production init/exit branches with a stubbed engine in both build modes."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    entry = (module / 'nomount.c').read_text()
    layout = (module / 'nm_offsets.c').read_text()

    def between(source, start, end):
        a = source.index(start)
        return source[a:source.index(end, a)]

    # ELF section placement is checked on the ARM64 output, not the host TU.
    table = between(layout, 'struct struct_offset {', '// 仅在确认BTF不可用')
    table = table.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static char diagnostic[256];
static int prepared, prepare_result;
#define nm_log_error(...) snprintf(diagnostic, sizeof(diagnostic), __VA_ARGS__)
#define nm_log_info(...) ((void)0)
#define NM_KPM_VERSION "fixture"
#define NM_OFFSET_MODE "fixture"
void* (*slot_memset)(void*, int, size_t);
void* (*slot_memcpy)(void*, const void*, size_t);
void* (*slot_memmove)(void*, const void*, size_t);
int (*slot_memcmp)(const void*, const void*, size_t);
void* (*slot_memchr)(const void*, int, size_t);
#define kfunc(name) slot_##name
static int nm_prepare_control_engine(void) {
  ++prepared;
  return prepare_result;
}
''' + table + between(
        entry, 'static bool nm_initialized;', 'static long nomount_ctl0(') + between(
        entry, 'static long nomount_exit(', 'KPM_INIT(') + r'''
static void enable_mem_slots(void) {
  slot_memset = memset; slot_memcpy = memcpy; slot_memmove = memmove;
  slot_memcmp = memcmp; slot_memchr = memchr;
}

int main(void) {
  assert(struct_offset.file_layout == -1);
  assert(nomount_init("unexpected", "load-file", NULL) == -EINVAL);
  assert(prepared == 0 && !nm_initialized && diagnostic[0] == '\0');

#ifdef CONFIG_KPM_BASELINES
  // Refusal must precede even the slot checks; test both advertised load paths.
  for (int i = 0; i < 2; ++i) {
    if (i)
      enable_mem_slots();
    assert(nomount_init(NULL, i ? "pre-kernel-init" : "load-file", NULL) == -EINVAL);
    assert(prepared == 0 && !nm_initialized);
    assert(strstr(diagnostic, "static baseline is unconfigured"));
    diagnostic[0] = '\0';
    assert(nomount_exit(NULL) == 0 && diagnostic[0] == '\0');
  }

  // Both configured layout tags continue into the existing engine checks.
  for (int mode = 0; mode <= 1; ++mode) {
    struct_offset.file_layout = mode;
    prepare_result = -EOPNOTSUPP;
    assert(nomount_init(NULL, "load-file", NULL) == -EOPNOTSUPP);
    assert(prepared == mode + 1 && !nm_initialized);
    assert(strstr(diagnostic, "initialization failed"));
    diagnostic[0] = '\0';
    assert(nomount_exit(NULL) == 0 && diagnostic[0] == '\0');
  }
#else
  assert(nomount_init(NULL, "load-file", NULL) == -ENOENT);
  assert(prepared == 0 && !nm_initialized);
  enable_mem_slots();
  prepare_result = -EOPNOTSUPP;
  assert(nomount_init(NULL, "load-file", NULL) == -EOPNOTSUPP);
  assert(prepared == 1 && !nm_initialized);
#endif

  prepare_result = 0;
  int before = prepared;
  assert(nomount_init(NULL, "load-file", NULL) == 0);
  assert(prepared == before + 1 && nm_initialized);
  return 0;
}
'''
    fixture = args.output / 'init.c'
    fixture.write_text(source)
    for variant, flags in [('static', ['-DCONFIG_KPM_BASELINES']), ('dynamic', [])]:
        binary = args.output / variant
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                        '-Wno-unused-function', '-fsanitize=address,undefined', *flags,
                        str(fixture), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        print(f'PASS: {variant} production init contract (stubbed engine)')


if __name__ == '__main__':
    main()
