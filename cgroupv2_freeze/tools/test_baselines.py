#!/usr/bin/env python3
"""对照 Nokia 镜像上的动态解码、静态配置与实际 KPM 补丁。"""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

MODULE = Path(__file__).resolve().parents[1]
ROOT = MODULE.parent
PROFILE = MODULE / "local/configs/nokia-b2n-4.4.192.json"
REGRESSIONS = MODULE / "local/configs/static-profiles.json"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "kernel_img/offset_harness"))
import bootimg
import kallsyms_extract

ANCHORS = (
    "css_task_iter_start", "cgroup_kn_lock_live", "task_clear_jobctl_trapping", "tty_audit_fork",
    "zap_other_threads", "freezing_slow_path", "schedule_timeout_interruptible",
    "cgroup_subtree_control_show", "cgroup_freezing", "cgroup_fork",
)

FIXTURE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef __APPLE__
typedef int64_t loff_t;
#endif
typedef uint32_t u32;
typedef int64_t s64;
#define printk(...) ((void)0)
#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

struct list_head { void* next; void* prev; };
struct cgroup_subsys_state;
struct cgroup;
struct kernfs_open_file;
struct seq_file;
struct task_struct;
struct signal_struct;
struct css_set { uint64_t words[16]; };
/* CFTYPE */
#include "cfv2_utils.h"
static uint64_t css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO,
                cgroup_base_files_ver5 = UZERO;

#ifndef CONFIG_KPM_BASELINES
/* DECODE */
/* WORDS */
static bool initial_available = true;
static void* kallsyms_lookup_name(const char* name) {
  /* LOOKUP */
  return NULL;
}
#define lookup_name(name) name = (typeof(name))kallsyms_lookup_name(#name); if (!(name)) return -21
#define kvar(name) kv_##name
#define kvar_def(name) (*kv_##name)
#define kvar_lookup_name(name) kv_##name = kallsyms_lookup_name(#name)
static void* css_task_iter_start = words_css_task_iter_start;
static void* cgroup_kn_lock_live = words_cgroup_kn_lock_live;
#endif
/* IMPLEMENTATION */

static int cgroup_freeze_show(struct seq_file* seq, void* data) { return 0; }
static ssize_t cgroup_freeze_write(struct kernfs_open_file* of, char* buf, size_t len, loff_t offset) { return 0; }
/* PREPARE */
static const struct struct_offset nokia = { /* PROFILE */ };

static void check_registration(const struct struct_offset* profile) {
  assert(css_task_iter_start_ver5 == (profile->css_task_iter_start_arity == 3 ? IZERO : UZERO));
  assert(cgroup_kn_lock_live_ver5 == (profile->cgroup_kn_lock_live_arity == 2 ? IZERO : UZERO));
  assert(cgroup_base_files_ver5 == (profile->kernfs_owner_fixup ? UZERO : IZERO));
  struct cftype saved[2];
  memcpy(saved, cgroup_freeze_files, sizeof(saved));
  cfv2_prepare_freeze_files();
  unsigned char expected[sizeof(cgroup_freeze_files)] = "cgroup.freeze";
  unsigned int flags = CFTYPE_NOT_ON_ROOT;
  typeof(&cgroup_freeze_show) show = cgroup_freeze_show;
  typeof(&cgroup_freeze_write) write = cgroup_freeze_write;
  memcpy(expected + profile->cftype_flags_offset, &flags, sizeof(flags));
  memcpy(expected + profile->cftype_show_offset, &show, sizeof(show));
  memcpy(expected + profile->cftype_write_offset, &write, sizeof(write));
  assert(2 * profile->cftype_stride <= sizeof(expected));
  assert(!memcmp(cgroup_freeze_files, expected, 2 * profile->cftype_stride));
  memcpy(cgroup_freeze_files, saved, sizeof(saved));
}

int main(void) {
#ifdef CONFIG_KPM_BASELINES
  assert(calculate_offsets() == -EINVAL);
  assert(cgroup_freeze_files[0].flags == 0);  // 未配置时不写表项。
  struct_offset = nokia;
  assert(calculate_offsets() == 0);
  check_registration(&nokia);

  struct_offset.css_task_iter_start_arity = 3;
  assert(calculate_offsets() == 0);
  assert(css_task_iter_start_ver5 == IZERO && cgroup_kn_lock_live_ver5 == UZERO);
  struct_offset = nokia;
  struct_offset.cgroup_kn_lock_live_arity = 2;
  assert(calculate_offsets() == 0);
  assert(css_task_iter_start_ver5 == UZERO && cgroup_kn_lock_live_ver5 == IZERO);
  struct_offset.kernfs_owner_fixup = 0;
  assert(calculate_offsets() == 0 && cgroup_base_files_ver5 == IZERO);

  /* REGRESSIONS */
  /* REJECTIONS */
  puts("static: Nokia, Mi 8 and Mi 9 fixtures; offset 0 accepted; unconfigured and bad layouts rejected");
#else
  assert(calculate_offsets() == 0);
  /* COMPARE */
  check_registration(&nokia);
  initial_available = false;
  assert(calculate_offsets() == -ENOENT);
  puts("dynamic: Nokia Image decodes to the same freezer offsets, ABI and cftype slots");
#endif
}
'''


def check_image(path, profile):
    image = bootimg.unpack_file(path)
    if image.release != profile["release"] or image.kernel_sha256 != profile["kernel_sha256"]:
        raise ValueError("镜像不是配置所绑定的 Nokia 裸内核")
    syms, mode = kallsyms_extract.extract(image.data)
    if syms is None:
        raise ValueError(f"无法解析目标符号表：{mode}")
    symbols = {name: address for address, _, name in syms}
    assert not {"cgroup_freeze_write", "cgroup_file_open", "cgroup_base_files"}.intersection(symbols)

    def word(name, delta):
        return struct.unpack_from("<I", image.data, symbols[name] + delta)[0]

    # B2N 的原生注册路径：flags 测试、show/write 指针调用、表项步长、dfl_cgrp 写入。
    offsets = profile["offsets"]
    for name, delta, op, unit, field in (
        ("cgroup_addrm_files", 0x68, 0xb9400260, 4, "cftype_flags_offset"),
        ("cgroup_seqfile_show", 0x24, 0xf9400262, 8, "cftype_show_offset"),
        ("cgroup_file_write", 0x34, 0xf9400264, 8, "cftype_write_offset"),
        ("cgroup_init_cftypes", 0x84, 0x91000273, 1, "cftype_stride"),
        ("link_css_set", 0x30, 0xf9000022, 8, "css_set_dfl_cgrp"),
    ):
        insn = word(name, delta)
        assert insn & ~(0xfff << 10) == op, (name, hex(insn))
        assert ((insn >> 10) & 0xfff) * unit == offsets[field], field
    assert word("cgroup_seqfile_show", 0x34) == 0xd63f0040  # blr x2
    assert word("cgroup_file_write", 0x40) == 0xd63f0080  # blr x4
    assert word("cgroup_init_cftypes", 0x20) == 0x39400260  # name[0]

    arrays = []
    for name in ANCHORS:
        values = ", ".join(hex(word(name, i * 4)) for i in range(0x20))
        arrays.append(f"static uint32_t words_{name}[] = {{{values}}};")
    pos = symbols["init_css_set"]
    slots = struct.unpack_from("<16Q", image.data, pos)
    # cgrp_links.next/prev 均指向内嵌链表头；由此核对映像地址域及自指针是否存在。
    assert slots[7] == slots[8] and slots[7] > 0xffff000000000000
    init_address = slots[7] - 0x38
    assert init_address not in slots
    arrays.append("static struct css_set initial = {{" + ", ".join(f"{x:#x}ULL" for x in slots) + "}};")
    lookup = [f'if (!strcmp(name, "{n}")) return words_{n};' for n in ANCHORS]
    lookup.append('if (initial_available && !strcmp(name, "init_css_set")) return &initial;')
    return "\n".join(arrays), "\n".join(lookup)


def check_kpm(baseline, offsets, out):
    patch = [sys.executable, str(ROOT / "patch_offsets.py")]
    data = baseline.read_bytes()
    layout = json.loads(Path(str(baseline) + ".json").read_text())
    start, size = layout["table_offset"], layout["table_size"]
    fields = layout["fields"]
    assert layout["schema"] == 3 and set(fields) == set(offsets)
    assert set(layout["offsets"].values()) == {-1}
    fmt = f"<{len(fields)}h"
    assert struct.unpack(fmt, data[start:start + size]) == (-1,) * len(fields)
    patched = out / "nokia.kpm"
    subprocess.run(patch + ["patch", baseline, "--offsets", PROFILE, "--output", patched], check=True)
    blob = out / "offsets.bin"
    subprocess.run(patch + ["dump", patched, "--output", blob], check=True)
    by_blob = out / "nokia-blob.kpm"
    subprocess.run(patch + ["patch", baseline, "--blob", blob, "--output", by_blob], check=True)
    changed = patched.read_bytes()
    assert by_blob.read_bytes() == changed
    assert changed[:start] == data[:start] and changed[start + size:] == data[start + size:]
    assert len(blob.read_bytes()) == size
    values = dict(zip(fields, struct.unpack(fmt, blob.read_bytes())))
    assert values == offsets
    regressions = {name: fixture["offsets"] for name, fixture in json.loads(REGRESSIONS.read_text()).items()}
    # 从已验证配置派生零偏移用例。
    regressions["zero_state"] = dict(regressions["mi9"], task_struct_state=0)
    for name, config in regressions.items():
        profile = out / f"{name}.json"
        profile.write_text(json.dumps(config))
        target = out / f"{name}.kpm"
        subprocess.run(patch + ["patch", baseline, "--offsets", profile, "--output", target], check=True)
        changed = target.read_bytes()
        assert changed[:start] == data[:start] and changed[start + size:] == data[start + size:]
        assert dict(zip(fields, struct.unpack(fmt, changed[start:start + size]))) == config
    return values, regressions


def check_host(words, lookup, offsets, regressions, out):
    code = (MODULE / "cgroupv2_freeze.c").read_text()
    header = (MODULE / "cgroupv2_freeze.h").read_text()
    shared = (ROOT / "kpm_utils.h").read_text()
    implementation = (MODULE / "cfv2_offsets.c").read_text()
    if sys.platform == "darwin":
        # 仅换宿主汇编节名；ARM64 KPM 的可补丁 ELF 节由 check_kpm 单独验证。
        implementation = implementation.replace('section(".data.re_offsets")',
                                                   'section("__DATA,__cfv2_offsets")')
    regression_checks = []
    for name, values in regressions.items():
        initializer = ", ".join(f".{field} = {value}" for field, value in values.items())
        regression_checks.append(
            f"const struct struct_offset {name} = {{{initializer}}};\n"
            f"struct_offset = {name};\n"
            "assert(calculate_offsets() == 0);\n"
            f"check_registration(&{name});"
        )
    regression_checks.append(
        "long first_member = 0;\n"
        "assert(task_state_ptr((struct task_struct*)&first_member) == &first_member);"
    )
    parts = {
        "CFTYPE": header[header.index("enum {\n  CFTYPE_ONLY"):header.rindex("#endif")],
        "DECODE": shared.split("// instruction\n", 1)[1].rsplit("#endif", 1)[0],
        "WORDS": words,
        "LOOKUP": lookup,
        "IMPLEMENTATION": implementation,
        "PREPARE": code[code.index("static struct cftype cgroup_freeze_files"):
                        code.index("static void cgroup_addrm_files_after")],
        "PROFILE": ", ".join(f".{name} = {value}" for name, value in offsets.items()),
        "REGRESSIONS": "\n".join(regression_checks),
        "COMPARE": "\n".join(f"assert(struct_offset.{name} == nokia.{name});"
                             for name in offsets if name.startswith(("task_", "signal_", "seq_", "css_set_"))
                             or name == "cgroup_flags"),
        "REJECTIONS": "\n".join(f"struct_offset = nokia; struct_offset.{name} = {value}; "
                                "assert(calculate_offsets() == -EINVAL);" for name, value in [
                                    *((name, -1) for name in offsets),
                                    ("cftype_flags_offset", 64 + 1), ("cftype_write_offset", 136),
                                    ("cftype_stride", 184), ("cftype_stride", 224),
                                    ("task_struct_signal", 2025),
                                ]),
    }
    fixture = FIXTURE
    for part, text in parts.items():
        fixture = fixture.replace(f"/* {part} */", text)
    generated = out / "test.c"
    generated.write_text(fixture)
    for mode in ("dynamic", "static"):
        binary = out / mode
        flags = ["-DCONFIG_KPM_BASELINES"] if mode == "static" else []
        subprocess.run(["cc", "-std=gnu11", "-O1", "-Wall", "-Werror", "-Wno-unused-function",
                        "-fsanitize=address,undefined", "-I", MODULE, *flags, generated, "-o", binary], check=True)
        subprocess.run([binary], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args()
    if not PROFILE.is_file():
        print(f"跳过 Nokia 档回归：缺少 {PROFILE.relative_to(ROOT)}")
        return
    if not REGRESSIONS.is_file():
        parser.error(f"缺少回归配置：{REGRESSIONS.relative_to(ROOT)}")
    profile = json.loads(PROFILE.read_text())
    words, lookup = check_image(args.image, profile)
    with TemporaryDirectory(prefix="cfv2-static-test-") as path:
        out = Path(path)
        values, regressions = check_kpm(args.baseline, profile["offsets"], out)
        check_host(words, lookup, values, regressions, out)


if __name__ == "__main__":
    main()
