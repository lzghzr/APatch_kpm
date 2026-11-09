#!/usr/bin/env python3
"""用选定目标 BTF 执行生产厂商钩子 ABI 查询、注册选择和回滚。"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

from test_native_apis import function


HOST = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define dev_t kernel_dev_t
#define mode_t kernel_mode_t
#define off_t kernel_off_t
#include "re_kernel_host.h"
#undef dev_t
#undef mode_t
#undef off_t
#define kfunc_def(n) (*kf_##n)
#define kfunc(n) kf_##n
#define kfunc_lookup_name(n) ((void)0)
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define logkm(...) ((void)0)
/* BTF */
struct tracepoint { int id; };
static struct tracepoint point;
static struct tracepoint* binder_vendor_record;
static bool binder_vendor_record_registered, binder_proc_hooked, trace = true;
static void* binder_proc_transaction = (void*)0x1000;
static void (*binder_proc_dec_tmpref)(struct binder_proc*);
static int kf_copy_from_user_nofault = 1;
static int have_vendor = 1, have_dec = 1, register_error, wrap_error;
static int registered, unregistered, wrapped, unwrapped;
static void native_dec(struct binder_proc* proc) {}
static void binder_proc_transaction_before(void* args, void* data) {}
static void binder_vendor_transaction_record(void* data, struct binder_transaction_data* tr,
                                             struct binder_transaction* t, struct binder_transaction* reply) {}
static void* kallsyms_lookup_name(const char* name) {
  assert(!strcmp(name, "__tracepoint_android_vh_binder_transaction_record"));
  return have_vendor ? &point : NULL;
}
static void* kallsyms_lookup_name_by_suffix(const char* name) {
  assert(!strcmp(name, "binder_proc_dec_tmpref"));
  return have_dec ? native_dec : NULL;
}
static int tracepoint_probe_register(struct tracepoint* tp, void* callback, void* data) {
  assert(tp == &point && callback == binder_vendor_transaction_record && !data && !wrapped);
  registered++;
  return register_error;
}
static int tracepoint_probe_unregister(struct tracepoint* tp, void* callback, void* data) {
  assert(tp == &point && callback == binder_vendor_transaction_record && !data && !wrapped);
  unregistered++;
  return 0;
}
static int (*kf_tracepoint_probe_register)(struct tracepoint*, void*, void*) = tracepoint_probe_register;
static int (*kf_tracepoint_probe_unregister)(struct tracepoint*, void*, void*) = tracepoint_probe_unregister;
typedef int hook_err_t;
static int hook_wrap(void* fn, int count, void* before, void* after, void* data) {
  assert(fn == (void*)0x1000 && count == 3 && before == binder_proc_transaction_before && !after && !data);
  if (!wrap_error) wrapped++;
  return wrap_error;
}
static void hook_unwrap(void* fn, void* before, void* after) {
  assert(fn == (void*)0x1000 && before == binder_proc_transaction_before && !after && wrapped);
  wrapped--; unwrapped++;
}
/* PRODUCTION */
static void reset(void) {
  assert(!binder_vendor_record_registered && !binder_proc_hooked && !wrapped);
  registered = unregistered = unwrapped = register_error = wrap_error = 0;
  have_vendor = have_dec = trace = kf_copy_from_user_nofault = 1;
  binder_proc_transaction = (void*)0x1000;
  kf_tracepoint_probe_register = tracepoint_probe_register;
  kf_tracepoint_probe_unregister = tracepoint_probe_unregister;
  struct_offset.binder_proc_tmp_ref = EXPECTED_TMP_REF;
}
static void fallback(void) {
  assert(!binder_cleanup_hook_init() && !binder_vendor_record_registered && binder_proc_hooked && wrapped == 1);
  binder_cleanup_hook_exit();
  assert(!wrapped && unwrapped == 1 && !unregistered);
}
int main(int argc, char** argv) {
  assert(argc == 2); FILE* f = fopen(argv[1], "rb"); assert(f);
  fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
  blob = malloc(n); assert(blob && fread(blob, 1, n, f) == (size_t)n); fclose(f);
  kf_bpf_get_btf_vmlinux = host_get; kf_btf_type_by_id = host_type;
  kf_btf_find_by_name_kind = host_find; kf_btf_name_by_offset = host_name; kf_btf_resolve_size = host_size;
  reset();
  assert(!binder_vendor_record_abi() && struct_offset.binder_proc_tmp_ref == EXPECTED_TMP_REF);
  assert(!binder_cleanup_hook_init() && binder_vendor_record_registered && !binder_proc_hooked && registered == 1);
  binder_cleanup_hook_exit(); binder_cleanup_hook_exit(); assert(unregistered == 1 && !unwrapped);
  reset(); binder_proc_transaction = NULL;
  assert(!binder_cleanup_hook_init() && binder_vendor_record_registered); binder_cleanup_hook_exit();
  reset(); have_vendor = 0; fallback();
  reset(); have_dec = 0; fallback();
  reset(); trace = false; fallback();
  reset(); kf_copy_from_user_nofault = 0; fallback();
  reset(); kf_tracepoint_probe_register = NULL; fallback();
  reset(); kf_tracepoint_probe_unregister = NULL; fallback();
  reset(); register_error = -EBUSY; fallback(); assert(registered == 1);
  reset(); register_error = -EBUSY; binder_proc_transaction = NULL;
  assert(binder_cleanup_hook_init() == -EBUSY && !binder_vendor_record_registered && !binder_proc_hooked);
  reset(); have_vendor = 0; binder_proc_transaction = NULL;
  assert(binder_cleanup_hook_init() < 0 && !registered && !wrapped);
  reset(); have_vendor = 0; wrap_error = 7;
  assert(binder_cleanup_hook_init() == -23 && !binder_proc_hooked);
#ifndef CONFIG_KPM_BASELINES
  reset(); kf_bpf_get_btf_vmlinux = NULL; fallback(); kf_bpf_get_btf_vmlinux = host_get;
  reset();
  struct btf_type* func = (void*)kpm_btf_type(&(struct kpm_btf){.data=&object,.find_by_name_kind=host_find,
      .type_by_id=host_type}, "__traceiter_android_vh_binder_transaction_record", 12);
  assert(func); struct btf_type* proto = (void*)host_type(&object, func->size);
  struct btf_param* params = (void*)(proto + 1);
  u32 old = params[3].name_off; params[3].name_off = 0;
  assert(binder_vendor_record_abi() == -EINVAL); fallback(); params[3].name_off = old;
  reset(); old = proto->info; proto->info = (old & ~65535U) | 3;
  assert(binder_vendor_record_abi() == -EINVAL); proto->info = old;
  reset(); struct btf_type* proc = (void*)host_type(&object, host_find(&object, "binder_proc", 4));
  struct btf_member* members = (void*)(proc + 1); unsigned i;
  for (i=0; i<(proc->info&65535); i++) if (!strcmp(host_name(&object,members[i].name_off),"tmp_ref")) break;
  assert(i<(proc->info&65535)); old=members[i].offset; members[i].offset++;
  assert(binder_vendor_record_abi() == -EINVAL); members[i].offset=old;
  struct kpm_btf b = {.data=&object,.find_by_name_kind=host_find,.type_by_id=host_type,
                     .name_by_offset=host_name,.resolve_size=host_size};
  struct kpm_btf_field field;
  assert(!kpm_btf_member(&b, proc, "tmp_ref", &field, 0));
  u32* encoding = (void*)(field.type + 1); old = *encoding; *encoding &= ~(1U << 24);
  assert(binder_vendor_record_abi() == -EINVAL); *encoding = old;
  struct btf_type* dec_func = (void*)kpm_btf_type(&b,"binder_proc_dec_tmpref",12);
  struct btf_type* dec_proto = (void*)host_type(&object,dec_func->size);
  struct btf_param* dec_params = (void*)(dec_proto+1);
  old=dec_params[0].type; dec_params[0].type=params[1].type;
  assert(binder_vendor_record_abi() == -EINVAL); dec_params[0].type=old;
  old=dec_proto->size; dec_proto->size=1;
  assert(binder_vendor_record_abi() == -EINVAL); dec_proto->size=old;
  assert(!binder_vendor_record_abi());
#else
  reset(); struct_offset.binder_proc_tmp_ref = -1;
  assert(binder_vendor_record_abi() == -EINVAL); fallback();
  reset(); struct_offset.binder_proc_tmp_ref = EXPECTED_TMP_REF + 1;
  assert(binder_vendor_record_abi() == -EINVAL);
#endif
  free(blob);
  puts("vendor hook: ABI/reference layout, preferred registration, fallback, missing dependencies and rollback: PASS");
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--btf", type=Path, required=True)
    ap.add_argument("--tmp-ref", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("btf_host", root / "re_kernel/tools/test_btf.py")
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    data = args.btf.read_bytes()
    records, strings = host.index_btf(data)
    (args.output / "input.btf").write_bytes(data)
    (args.output / "re_kernel_host.h").write_text("#include <ktypes.h>\n" + (root / "re_kernel/re_structs.h").read_text())
    common = (root / "kpm_utils.h").read_text().split("// BTF\n", 1)[1].split("// instruction\n", 1)[0]
    offsets = (root / "re_kernel/re_offsets.c").read_text()
    btf = re.search(r"struct struct_offset\s*\{.*?\};", offsets, re.S)[0] + "\nstatic struct struct_offset struct_offset;\n"
    btf += common + "\nstatic const u32 records[] = {" + ",".join(map(str, records)) + "};\n"
    btf += f"static const u32 string_start={strings}, string_length={len(data)-strings};\n" + host.HOST
    source = (root / "re_kernel/re_kernel.c").read_text()
    production = (root / "re_kernel/re_vendor_btf.c").read_text()
    production += function(source, "binder_cleanup_hook_init") + "\n" + function(source, "binder_cleanup_hook_exit")
    results = []
    for static in (False, True):
        mode = "static" if static else "dynamic"
        code = f"#define EXPECTED_TMP_REF {args.tmp_ref}\n" + ("#define CONFIG_KPM_BASELINES 1\n" if static else "")
        code += HOST.replace("/* BTF */", btf).replace("/* PRODUCTION */", production)
        path, binary = args.output / (mode + ".c"), args.output / mode
        path.write_text(code)
        cmd = ["clang", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-parameter",
               "-Wno-unused-variable", "-Wno-macro-redefined", "-idirafter", str(root / "KernelPatch/kernel/include"),
               "-I", str(args.output), "-fsanitize=address,undefined", "-g", str(path), "-o", str(binary)]
        build = subprocess.run(cmd, capture_output=True, text=True)
        (args.output / (mode + "-build.log")).write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stderr
        run = subprocess.run([str(binary.resolve()), str((args.output / "input.btf").resolve())], capture_output=True, text=True)
        results.append({"mode": mode, "exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
        assert run.returncode == 0, run.stdout + run.stderr
        print(mode + ": " + run.stdout.strip())
    (args.output / "receipt.json").write_text(json.dumps({"scope": "Developer BTF/host emulation, no device conclusion",
        "tmp_ref": args.tmp_ref, "results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
