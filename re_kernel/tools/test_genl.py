#!/usr/bin/env python3
"""提取生产函数与公共指令宏，执行动态版 Genl/上下文主机自检。"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from test_genl_offsets import instruction_source, offset_source


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="新的空输出目录")
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    source = (module / "re_kernel.c").read_text()
    genl_symbols = source.split("// Generic Netlink\n", 1)[1].split(
        "static bool binder_transaction_buffer_release_ver6", 1)[0]
    genl = genl_symbols + source[source.index("static struct genl_family* rekernel_genl_family;"):].split(
        "// Binder 调用上下文\n", 1)[0]
    context = source.split("// Binder 调用上下文\n", 1)[1].split("// binder_node_lock\n", 1)[0]
    functions = instruction_source(root) + offset_source(module) + genl + context
    fixture = (module / "tools/test_genl.c").read_text().replace("/* PRODUCTION_FUNCTIONS */", functions)
    (args.output / "genl-test.c").write_text(fixture)
    (args.output / "re_kernel_host.h").write_bytes((module / "re_kernel.h").read_bytes())
    (args.output / "re_structs.h").write_bytes((module / "re_structs.h").read_bytes())
    (args.output / "instruction_host.h").write_text(instruction_source(root))
    anchors = (module / "tools/test_genl_anchors.c").read_text().replace(
        "/* PRODUCTION_FUNCTIONS */", instruction_source(root) + offset_source(module))
    (args.output / "anchors-test.c").write_text(anchors)
    offsets = (module / "re_offsets.c").read_text()
    getters = []
    for name in ("binder_transaction_to_proc", "binder_transaction_buffer", "binder_transaction_code",
                 "binder_transaction_flags", "binder_node_ptr", "binder_node_cookie"):
        start = offsets.index("static inline", offsets.index("// " + name + "\n"))
        end = offsets.index("\n}", start) + 2
        getters.append(offsets[start:end])
    structure = offset_source(module).split("static long calculate_offsets", 1)[0]
    cleanup = source[source.index("static bool binder_can_update_transaction("):source.index("static inline void outstanding_txns_dec(")]
    fixture = (module / "tools/test_cleanup.c").read_text().replace(
        "/* PRODUCTION_FUNCTIONS */", structure + "\n" + "\n".join(getters) + "\n" + cleanup)
    (args.output / "cleanup-test.c").write_text(fixture)
    flow_getters = list(getters)
    for name in ("binder_proc_alloc", "binder_proc_is_dead", "binder_proc_is_frozen", "binder_proc_outstanding_txns",
                 "binder_node_has_async_transaction", "binder_node_async_todo"):
        start = offsets.index("static inline", offsets.index(name + "\n"))
        end = offsets.index("\n}", start) + 2
        flow_getters.append(offsets[start:end])
    frozen = source[source.index("static inline bool binder_is_frozen("):source.index("// cgroupv2_freeze")]
    flow = source[source.index("static bool binder_can_update_transaction("):source.index("static void do_send_sig_info_before(")]
    fixture = (module / "tools/test_cleanup_flow.c").read_text().replace(
        "/* PRODUCTION_FUNCTIONS */", structure + "\n" + "\n".join(flow_getters) + "\n" + frozen + flow)
    (args.output / "cleanup-flow-test.c").write_text(fixture)
    binder_from = offsets.split("  // 获取 binder_transaction->from；", 1)[1].split("  // 获取 binder_stats_deleted_addr", 1)[0]
    fixture = (module / "tools/test_binder_from.c").read_text().replace(
        "/* INSTRUCTIONS */", instruction_source(root)).replace(
        "/* PRODUCTION_FROM */", "// 获取 binder_transaction->from；" + binder_from)
    (args.output / "binder-from-test.c").write_text(fixture)
    binder_dead = offsets.split("  // 旧 Binder 没有 is_frozen，", 1)[1].split("  // 获取 task_struct->jobctl", 1)[0]
    # 生产片段的 CONFIG_DEBUG 日志在此宿主编译中关闭。
    fixture = (module / "tools/test_binder_dead.c").read_text().replace(
        "/* INSTRUCTIONS */", instruction_source(root)).replace(
        "/* PRODUCTION_DEAD */", "// 旧 Binder 没有 is_frozen，" + binder_dead)
    (args.output / "binder-dead-test.c").write_text(fixture)
    binder_alloc = offsets.split("  // 获取 binder_alloc->pid,", 1)[1].split("  // 获取 binder_transaction->from；", 1)[0]
    fixture = (module / "tools/test_binder_alloc.c").read_text().replace(
        "/* INSTRUCTIONS */", instruction_source(root)).replace(
        "/* PRODUCTION_ALLOC */", "// 获取 binder_alloc->pid," + binder_alloc)
    (args.output / "binder-alloc-test.c").write_text(fixture)
    results = []
    for name, flags, test in (("base", [], "genl-test.c"),
                              ("network", ["-DCONFIG_NETWORK"], "genl-test.c"),
                              ("instructions", [], str(module / "tools/test_instructions.c")),
                              ("cleanup", [], "cleanup-test.c"),
                              ("cleanup_flow", [], "cleanup-flow-test.c"),
                              ("anchors", [], "anchors-test.c"),
                              ("binder_from", [], "binder-from-test.c"),
                              ("binder_dead", [], "binder-dead-test.c"),
                              ("binder_alloc", [], "binder-alloc-test.c")):
        binary = args.output / name
        source_path = args.output / test if test.endswith("-test.c") else Path(test)
        command = [args.cc, "-Wall", "-Werror", "-Wno-unused-function", "-Wno-macro-redefined",
                   "-idirafter", str(root / "KernelPatch/kernel/include"), "-I", str(args.output),
                   "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", *flags,
                   str(source_path), "-o", str(binary)]
        build = subprocess.run(command, capture_output=True, text=True)
        (args.output / (name + "-build.log")).write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stdout + build.stderr
        run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
        (args.output / (name + ".log")).write_text(run.stdout + run.stderr)
        assert run.returncode == 0, run.stdout + run.stderr
        results.append({"name": name, "sha256": sha256(binary), "output": run.stdout})
        print(name + ": " + run.stdout.strip())
    inputs = [module / name for name in ("re_kernel.c", "re_runtime.c", "re_offsets.c", "re_kernel.h", "re_structs.h", "re_utils.h",
                                         "tools/test_genl.c", "tools/test_genl.py",
                                         "tools/test_genl_offsets.py", "tools/test_instructions.c", "tools/test_cleanup.c",
                                         "tools/test_cleanup_flow.c",
                                         "tools/test_genl_anchors.c", "tools/test_binder_from.c", "tools/test_binder_dead.c", "tools/test_binder_alloc.c")]
    inputs.append(root / "kpm_utils.h")
    receipt = {"scope": "Developer host selfcheck; no device conclusion",
               "sources": {str(path.relative_to(root)): sha256(path) for path in inputs}, "results": results}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
