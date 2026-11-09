#!/usr/bin/env python3
"""执行生产分配器检查、skb 释放分派和 Genl 依赖条件，不操作设备。"""

import argparse
import json
from pathlib import Path
import re
import subprocess


def function(text, name):
    match = re.search(r"^static (?:inline )?[^\n]*?\b" + name + r"\(", text, re.M)
    start = match.start()
    end = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


HOST = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef unsigned int gfp_t;
#define __force
/* PRODUCTION_GFP */
struct sk_buff { unsigned int refs, destroyed; };
static unsigned int available, noprof_lookups, allocations[3], releases[2];
static char allocation;
enum { LEGACY = 1, INTERNAL = 2, NOPROF = 4, FREE = 8, SKB_FREE = 16, SKB_CONSUME = 32, BINDER_PROC = 64, BINDER_TRANS = 128 };
static void* record_alloc(size_t size, gfp_t flags, int index) {
  assert(size == 37 && flags == (index == 2 ? 0x20u : 0x480020u));
  allocations[index]++;
  return &allocation;
}
static void* legacy_alloc(size_t size, gfp_t flags) { return record_alloc(size, flags, 0); }
static void* internal_alloc(size_t size, gfp_t flags) { return record_alloc(size, flags, 1); }
static void* noprof_alloc(size_t size, gfp_t flags) { return record_alloc(size, flags, 2); }
static void native_free(const void* p) { assert(p == &allocation); }
static void record_release(struct sk_buff* skb, int index) {
  releases[index]++;
  if (skb) {
    assert(skb->refs && !skb->destroyed);
    if (!--skb->refs)
      skb->destroyed++;
  }
}
static void native_skb_free(struct sk_buff* skb) { record_release(skb, 0); }
static void native_skb_consume(struct sk_buff* skb) { record_release(skb, 1); }
static void* lookup(const char* name) {
  if (!strcmp(name, "kmalloc")) return available & LEGACY ? legacy_alloc : NULL;
  if (!strcmp(name, "__kmalloc")) return available & INTERNAL ? internal_alloc : NULL;
  if (!strcmp(name, "__kmalloc_noprof")) {
    noprof_lookups++;
    return available & NOPROF ? noprof_alloc : NULL;
  }
  if (!strcmp(name, "kfree")) return available & FREE ? native_free : NULL;
  if (!strcmp(name, "kfree_skb")) return available & SKB_FREE ? native_skb_free : NULL;
  if (!strcmp(name, "consume_skb")) return available & SKB_CONSUME ? native_skb_consume : NULL;
  if (!strcmp(name, "binder_proc_transaction")) return available & BINDER_PROC ? (void*)0x1000 : NULL;
  if (!strcmp(name, "binder_transaction")) return available & BINDER_TRANS ? (void*)0x2000 : NULL;
  assert(!"unexpected lookup");
  return NULL;
}
#define kfunc(n) kf_##n
#define kvar(n) kv_##n
#define kfunc_lookup_name(n) (kf_##n = (typeof(kf_##n))lookup(#n))
#define kallsyms_lookup_name_by_suffix(n) lookup(n)
#define kallsyms_lookup_name(n) lookup(n)
#define pr_info(...) ((void)0)
#define kfunc_call(n, ...) if (kf_##n) return kf_##n(__VA_ARGS__)
#define kfunc_direct_call(n, ...) return kf_##n(__VA_ARGS__)
#define logkm(...) ((void)0)
static void* (*kf_kmalloc)(size_t, gfp_t);
static void* (*kf___kmalloc)(size_t, gfp_t);
static void* binder_proc_transaction;
static void* binder_transaction;
static void (*kf_kfree)(const void*);
static void (*kf_kfree_skb)(struct sk_buff*);
static void (*kf_consume_skb)(struct sk_buff*);
static int kf_genl_register_family = 1, kf___genl_register_family = 1, kf_genl_unregister_family = 1;
static int kf___alloc_skb = 1, kf_genlmsg_put = 1, kf_nla_put = 1, kf_skb_trim = 1;
static int kf_netlink_broadcast = 1, kv_init_net = 1;
/* PRODUCTION */
static void reset(unsigned int mask) {
  available = mask;
  noprof_lookups = 0;
  memset(allocations, 0, sizeof(allocations));
  memset(releases, 0, sizeof(releases));
  kf_kmalloc = kf___kmalloc = NULL;
  kf_kfree = NULL;
  kf_kfree_skb = kf_consume_skb = NULL;
  rekernel_gfp_atomic = GFP_ATOMIC;
}
static void check_allocator(unsigned int mask) {
  reset(mask);
  int valid = (mask & FREE) && (mask & (LEGACY | INTERNAL | NOPROF));
  assert(allocator_init() == (valid ? 0 : -EOPNOTSUPP));
  assert(noprof_lookups == !(mask & (LEGACY | INTERNAL)));
  if (valid) {
    assert(rekernel_gfp_atomic == (mask & (LEGACY | INTERNAL) ? 0x480020u : 0x20u));
    assert(kmalloc(37, rekernel_gfp_atomic) == &allocation);
    unsigned int expected = mask & LEGACY ? 0 : mask & INTERNAL ? 1 : 2;
    for (unsigned int i = 0; i < 3; i++) assert(allocations[i] == (i == expected));
    kf_kfree(&allocation);
  }
}
static void check_release(unsigned int mask) {
  reset(mask);
  skb_init();
  int valid = mask & (SKB_FREE | SKB_CONSUME);
  assert(genl_dependencies() == (valid ? 0 : -EOPNOTSUPP));
  if (!valid)
    return;
  struct sk_buff skb = {.refs = 2};
  nlmsg_free(&skb);
  assert(skb.refs == 1 && !skb.destroyed);
  nlmsg_free(&skb);
  assert(!skb.refs && skb.destroyed == 1);
  unsigned int expected = mask & SKB_FREE ? 0 : 1;
  assert(releases[expected] == 2 && !releases[!expected]);
  nlmsg_free(NULL);
  assert(releases[expected] == 3 && !releases[!expected]);
}
int main(void) {
  for (unsigned int mask = 0; mask < 16; mask++) check_allocator(mask);
  for (unsigned int mask = 0; mask < 64; mask += 16) check_release(mask);
  reset(SKB_FREE | SKB_CONSUME);
  kf_kfree_skb = native_skb_free;
  kf_consume_skb = native_skb_consume;
  struct sk_buff skb = {.refs = 1};
  nlmsg_free(&skb);
  assert(skb.destroyed == 1 && releases[0] == 1 && !releases[1]);
  int* required[] = {&kf_genl_unregister_family, &kf___alloc_skb, &kf_genlmsg_put,
                    &kf_nla_put, &kf_skb_trim, &kf_netlink_broadcast, &kv_init_net};
  for (unsigned int i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
    *required[i] = 0;
    assert(genl_dependencies() == -EOPNOTSUPP);
    *required[i] = 1;
  }
  kf_genl_register_family = 0;
  assert(!genl_dependencies());
  kf___genl_register_family = 0;
  assert(genl_dependencies() == -EOPNOTSUPP);
  kf_genl_register_family = kf___genl_register_family = 1;
  available = BINDER_PROC | BINDER_TRANS;
  assert(binder_dependencies() == 0 && binder_proc_transaction && binder_transaction);
  available = BINDER_TRANS;
  assert(binder_dependencies() == 0 && !binder_proc_transaction && binder_transaction);
  available = BINDER_PROC;
  assert(binder_dependencies() == -21);
  available = 0;
  assert(binder_dependencies() == -21);
  /* TARGET */
  puts("native APIs: allocator precedence/absence, skb single release, Genl and Binder fail-closed: PASS");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-symbols", type=Path, help="已选目标的 [offset,type,name] 符号清单")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    source = (root / "re_kernel.c").read_text()
    utils = (root / "re_utils.h").read_text()
    structs = (root / "re_structs.h").read_text()
    flags = structs.split("// linux/gfp.h\n", 1)[1].split("// uapi/asm/signal.h\n", 1)[0]
    flags += re.search(r"^static gfp_t rekernel_gfp_atomic = .*?;", source, re.M)[0]
    allocator = source.split("  kfunc_lookup_name(kfree);", 1)[1].split("  kvar_lookup_name(binder_stats);", 1)[0]
    allocator = "  kfunc_lookup_name(kfree);" + allocator
    skb = source.split("  kfunc_lookup_name(kfree_skb);", 1)[1].split("  kfunc_lookup_name(netlink_broadcast);", 1)[0]
    skb = "  kfunc_lookup_name(kfree_skb);" + skb
    genl = function(source, "start_rekernel_genl_server")
    genl = genl.split("  lookup_name(genl_rcv_msg);", 1)[1].split("  struct genl_family* family", 1)[0]
    binder = source.split("  kfunc_lookup_name(memdup_user);\n\n", 1)[1].split("  lookup_name(do_send_sig_info);", 1)[0]
    sdk = (root.parent / "KernelPatch/kernel/linux/include/linux/slab.h").read_text()
    production = "static int allocator_init(void) {\n" + allocator + "  return 0;\n}\n"
    production += "static void skb_init(void) {\n" + skb + "}\n"
    production += "static int genl_dependencies(void) {\n" + genl + "  return 0;\n}\n"
    production += "static int binder_dependencies(void) {\n" + binder + "  return 0;\n}\n"
    production += function(sdk, "kmalloc") + "\n" + function(utils, "nlmsg_free")
    target = ""
    mask = None
    if args.target_symbols:
        names = {n for _, _, n in json.loads(args.target_symbols.read_text())}
        mask = sum(1 << i for i, n in enumerate(("kmalloc", "__kmalloc", "__kmalloc_noprof", "kfree",
                                               "kfree_skb", "consume_skb")) if n in names)
        # 本轮目标必须同时具有分配、释放与合法 skb 引用释放入口。
        assert mask & 8 and mask & 7 and mask & 48
        # 目标必须包含在真机 kallsyms 上可解析的 binder 事务入口。
        assert "binder_transaction" in names
        binder_mask = (64 if "binder_proc_transaction" in names else 0) | 128
        target = f"check_allocator({mask}); check_release({mask});\n"
        target += f"reset({mask}); assert(!allocator_init()); skb_init(); assert(!genl_dependencies());\n"
        target += f"available = {binder_mask}; assert(!binder_dependencies());\n"
        target += 'puts("selected target symbol dependencies: PASS");'
    code = HOST.replace("/* PRODUCTION_GFP */", flags).replace("/* PRODUCTION */", production)
    code = code.replace("/* TARGET */", target)
    path, binary = args.output / "native-apis.c", args.output / "native-apis"
    path.write_text(code)
    command = ["clang", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
               "-g", "-fno-omit-frame-pointer", str(path), "-o", str(binary)]
    build = subprocess.run(command, capture_output=True, text=True)
    (args.output / "build.log").write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stdout + build.stderr
    run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    receipt = {"scope": "Developer host simulation; no device conclusion", "target_symbol_mask": mask,
               "exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    assert run.returncode == 0, run.stdout + run.stderr
    print(run.stdout.strip())


if __name__ == "__main__":
    main()
