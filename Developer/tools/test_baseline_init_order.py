#!/usr/bin/env python3
"""Check publication order and execute the production Genl and freezer guards on host."""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRELUDE = '''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define logkm(...) ((void)0)
'''


def func(s, name):
    m = re.search(r'^static [^\n]*?\b' + name + r'\([^;\n]*\) \{', s, re.M)
    assert m, name
    return s[m.start():s.index('\n}', m.end()) + 2]


def run(out, name, content):
    source, executable = out / (name + '.c'), out / name
    source.write_text(PRELUDE + content)
    subprocess.run(['clang', '-std=gnu11', '-Wall', '-Werror', '-fsanitize=address,undefined',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
    print(f'{name}: PASS')


def genl(out, mod):
    root = ROOT / mod
    body = func((root / 're_kernel.c').read_text(), 'inline_hook_init')
    assert (body.index('re_static_genl_layout_valid()') < body.index('prepare_rekernel_genl_server()')
            < body.index('prepare_binder_cleanup_hook()')
            < min(body.index('tracepoint_probe_register('), body.index('hook_wrap(')))
    offsets = (root / 're_offsets.c').read_text()
    table = offsets.split('struct struct_offset {', 1)[1].split('};', 1)[0]
    structs = (root / 're_structs.h').read_text().split('struct genl_family_config {', 1)[1].split('// linux/gfp.h', 1)[0]
    run(out, mod, '#define GENL_NAMSIZ 16\n#define __aligned(n) __attribute__((aligned(n)))\n'
        + 'struct genl_family_config {' + structs + 'static struct struct_offset {' + table + '} struct_offset;\n'
        + func(offsets, 're_static_genl_layout_valid') + r'''
int main(void) {
  const struct struct_offset valid = {
      .genl_family_id = 0, .genl_family_config = 4, .genl_family_mcgrp_offset = 32,
      .genl_family_mcgrps = 40, .genl_family_n_mcgrps = 48, .net_genl_sock = 0x118,
      .genl_family_n_mcgrps_size = 4,
  };
  const int widths[] = {1, 2, 4};
  for (unsigned i = 0; i < ARRAY_SIZE(widths); ++i) {
    struct_offset = valid;
    struct_offset.genl_family_n_mcgrps_size = widths[i];
    assert(re_static_genl_layout_valid());
  }
#define REJECT(f, v) do { struct_offset = valid; struct_offset.f = v; assert(!re_static_genl_layout_valid()); } while (0)
  REJECT(genl_family_mcgrps, -1);
  REJECT(genl_family_mcgrps, 41);
  REJECT(genl_family_id, 4);
  REJECT(genl_family_n_mcgrps, 1023);
  REJECT(genl_family_n_mcgrps_size, 3);
  REJECT(genl_family_n_mcgrps_size, -1);
  REJECT(genl_family_config, -1);
  REJECT(genl_family_mcgrp_offset, 1024);
  REJECT(net_genl_sock, -1);
  return 0;
}
''')


def freezer(out):
    s = (ROOT / 'cgroupv2_freeze/cgroupv2_freeze.c').read_text()
    callbacks = ('get_signal_before proc_pid_wchan_before cgroup_addrm_files_after cgroup_procs_write_after '
                 'css_set_move_task_after __kernfs_create_file_after').split()
    for cb in callbacks:
        assert func(s, cb).split('{', 1)[1].lstrip().startswith('if (!cfv2_active())\n    return;'), cb
    init = func(s, 'inline_hook_init')
    assert (init.index('calculate_offsets()') < init.index('hook_wrap(') < init.index('__atomic_store_n(')
            < init.index('cfv2_arm_uid_mount('))
    targets = ('proc_pid_wchan signal_wake_up_state css_task_iter_start css_task_iter_next css_task_iter_end '
               'css_next_descendant_pre cgroup_kn_lock_live cgroup_kn_unlock cgroup_procs_write '
               'css_set_move_task __kernfs_create_file kernfs_setattr get_signal').split()
    slots = 'schedule wake_up_process of_css seq_printf kstrtoint strim'.split()
    declarations = '\n'.join(f'static void (*{name})(void) = native;' for name in targets + ['kf_'+n for n in slots])
    declarations += '\n' + '\n'.join(f'static void {cb}(void) {{}}' for cb in callbacks if cb != 'cgroup_addrm_files_after')
    run(out, 'freezer', r'''
#define __user
#define IZERO 1
typedef int hook_err_t;
struct cgroup_subsys_state;
struct cgroup;
struct cftype { int member; };
typedef struct { long ret; uintptr_t arg0, arg1, arg3; } hook_fargs4_t;
static struct cftype cgroup_freeze_files[2];
static bool cfv2_hooks_ready;
static void native(void) {}
static int attempts, installed, arm, files, fail_at, layout_error, cftype_error;
static int cgroup_base_files_ver5;
static void* kallsyms_lookup_name(const char* name) { return NULL; }
static int cgroup_init_cftypes(void* unused, struct cftype* cfts) { return cftype_error; }
static int calculate_offsets(void) { return layout_error; }
static void cfv2_prepare_freeze_files(void) {}
static void cfv2_arm_uid_mount(const char* event) { assert(cfv2_hooks_ready); ++arm; }
#define lookup_name(name) ((void)&name)
#define kfunc(name) kf_##name
#define kfunc_lookup_name(name) ((void)0)
static void (*kf_memset)(void) = native;
static void (*css_task_iter_start_v4)(void), (*cgroup_kn_lock_live_v4)(void);
static int publish(struct cgroup_subsys_state* css, struct cgroup* c, struct cftype* t, bool add) {
  assert(t == cgroup_freeze_files && add);
  ++files;
  return 0;
}
static int (*cgroup_addrm_files)(struct cgroup_subsys_state*, struct cgroup*, struct cftype*, bool) = publish;
#define wrap_get_origin_func(a) publish
''' + declarations + '\n' + func(s, 'cfv2_active') + '\n' + func(s, 'cgroup_addrm_files_after') + r'''
static void file_event(void) {
  hook_fargs4_t args = {.arg3 = 1};
  cgroup_addrm_files_after(&args, NULL);
}
static int hook_wrap(void* target, int count, void* before, void* after, void* data) {
  assert(!cfv2_active());
  if (installed >= 3)
    file_event();
  assert(files == 0);
  if (++attempts == fail_at)
    return -1;
  ++installed;
  return 0;
}
''' + init + r'''
static int compat_copy_to_user(char* dest, const char* source, size_t size) {
  memcpy(dest, source, size);
  return (int)size;
}
''' + func(s, 'inline_hook_control0') + r'''
static void reset(void) {
  attempts = installed = arm = files = fail_at = layout_error = cftype_error = 0;
  cfv2_hooks_ready = false;
}
int main(void) {
  layout_error = -EINVAL;
  assert(inline_hook_init(NULL, NULL, NULL) == -EINVAL && !attempts);
  reset();
  cftype_error = -ENOMEM;
  assert(inline_hook_init(NULL, NULL, NULL) == -ENOMEM && !attempts);
  for (int hooks = 5; hooks <= 6; ++hooks) {
    cgroup_base_files_ver5 = hooks == 5 ? IZERO : 0;
    for (int i = 1; i <= hooks; ++i) {
      reset();
      fail_at = i;
      assert(inline_hook_init(NULL, NULL, NULL) == (i == 1 ? -23 : 0));
      assert(attempts == i && installed == i - 1 && !cfv2_active() && !arm);
      file_event();
      assert(!files);
      assert(inline_hook_control0(NULL, NULL, 0) == -ENODEV);
    }
    reset();
    assert(!inline_hook_init(NULL, NULL, NULL));
    assert(installed == hooks && cfv2_active() && arm == 1);
    char reply[16];
    assert(inline_hook_control0(NULL, reply, sizeof(reply)) == 0 && !strcmp(reply, "_(._.)_"));
    file_event();
    assert(files == 1);
  }
  return 0;
}
''')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    out = p.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for mod in ('re_kernel', 're_kernel_x'):
        genl(out, mod)
    freezer(out)
    zs = func((ROOT / 'zram_zstd/zram_zstd.c').read_text(), 'zram_zstd_init')
    static = zs.split('#ifdef CONFIG_KPM_BASELINES', 1)[1].split('#endif', 1)[0]
    assert 'calculate_offsets()' in static and 'return rc;' in static
    assert zs.index(static) < zs.index('kfunc(crypto_has_alg)(')
    print('zram static validation before Crypto probe: PASS')
