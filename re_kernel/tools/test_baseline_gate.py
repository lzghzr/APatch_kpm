#!/usr/bin/env python3
"""实现方自检：静态模板门禁能区分「参考布局」与「已按目标核对」（re_kernel / re_kernel_x）。

夹具直接取生产源码：`struct struct_offset` 定义、表 `.data.re_offsets` 的参考初始器、
`re_baseline_check()` 函数体，拼进一个主机程序执行，因此判的是交付件里那份表与那段门禁，
不是重写的副本。`--artifacts` 附加核对已构建静态件的同名 JSON：模板原样交付时
`template_abi` 与 `cred_uid` 都必须仍是 -1。
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

MODULES = ("re_kernel", "re_kernel_x")

HOST = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int logged;
#define logkm(...) (logged++)

/* SCHEMA */

// 原样交付的参考布局（模板初值）。
static const struct struct_offset reference = REFERENCE_BODY;
static volatile struct struct_offset struct_offset;

/* GATE */

static void load(const struct struct_offset* values) {
  struct_offset = *values;
  logged = 0;
}

int main(void) {
  // 1. 原样交付的参考布局：必须拒载。
  assert(reference.template_abi == -1 && reference.cred_uid == -1);
  load(&reference);
  assert(re_baseline_check() == -EINVAL);
  assert(logged == 1);

  // 2. 只填一个哨兵（cred_uid 取真实值，其余保持参考实值）：仍然必须拒载。
  {
    struct struct_offset values = reference;
    values.cred_uid = 4;
    load(&values);
    assert(re_baseline_check() == -EINVAL);
    assert(logged == 1);
  }

  // 3. 只写确认字段、偏移仍未取证：必须拒载。
  {
    struct struct_offset values = reference;
    values.template_abi = 1;
    load(&values);
    assert(re_baseline_check() == -EINVAL);
    assert(logged == 1);
  }

  // 4. 0 不是目标标识（表里的 0 与「未配置」必须分开），必须拒载。
  {
    struct struct_offset values = reference;
    values.cred_uid = 4;
    values.template_abi = 0;
    load(&values);
    assert(re_baseline_check() == -EINVAL);
    assert(logged == 1);
  }

  // 5. 已按目标核对：放行。
  {
    struct struct_offset values = reference;
    values.cred_uid = 4;
    values.template_abi = 0x050f;
    load(&values);
    assert(re_baseline_check() == 0);
    assert(logged == 0);
  }

  // 6. 偏移 0 是合法值，不能被当成未配置。
  {
    struct struct_offset values = reference;
    values.cred_uid = 0;
    values.template_abi = 1;
    load(&values);
    assert(re_baseline_check() == 0);
    assert(logged == 0);
  }

  printf("%s: reference layout rejected (sentinel alone / marker alone / marker 0), "
         "configured table and offset 0 accepted: PASS\n", MODULE_NAME);
  return 0;
}
'''


def extract(source, module):
    schema = re.search(r"struct struct_offset \{.*?\n\};\n", source, re.S)
    assert schema, f"{module}: struct struct_offset not found"
    blocks = re.findall(r"volatile struct struct_offset struct_offset[^=]*= (\{.*?\n\});\n", source, re.S)
    reference = [block for block in blocks if "binder_release_abi" in block]
    assert len(reference) == 1, f"{module}: expected one reference initializer, got {len(reference)}"
    gate = re.search(r"static inline long re_baseline_check\(void\) \{.*?\n\}\n", source, re.S)
    assert gate, f"{module}: re_baseline_check not found"
    fields = re.findall(r"int16_t\s+(\w+)\s*;", schema.group(0))
    assert fields[-3:] == ["binder_proc_tmp_ref", "template_abi", "binder_release_abi"], fields[-3:]
    assert len(fields) == 47 and len(set(fields)) == 47, len(fields)
    return schema.group(0).strip(), reference[0], gate.group(0).strip(), fields


def check_placement(root):
    """门禁必须在任何安装动作之前生效（源文本顺序断言，配合上面的执行夹具）。"""
    checked = []
    for module in MODULES:
        text = (root / module / "re_kernel.c").read_text()
        init = text[text.index("static long inline_hook_init"):]
        end = init.find("\nstatic long ", 1)
        body = init if end < 0 else init[:end]
        gate = body.index("re_baseline_check()")
        install = min(index for index in (body.find("start_rekernel_genl_server("),
                                         body.find("hook_wrap("), body.find("hook_func("))
                        if index >= 0)
        assert gate < install, module
        checked.append(module)
    return checked


def check_sidecars(root, fields):
    checked = 0
    for module in MODULES:
        for layout in sorted((root / module).glob("*_baselines.kpm.json")):
            data = json.loads(layout.read_text())
            assert data["table_size"] == len(fields) * 2 == 94, (layout.name, data["table_size"])
            assert data["fields"] == fields, layout.name
            assert data["offsets"]["template_abi"] == -1, layout.name
            assert data["offsets"]["cred_uid"] == -1, layout.name
            checked += 1
    return checked


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cc", default="clang")
    ap.add_argument("--artifacts", type=Path, help="产物目录（缺省为仓库根）：核对 *_baselines.kpm.json")
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[2]
    fields = None
    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        for module in MODULES:
            schema, body, gate, fields = extract((root / module / "re_offsets.c").read_text(), module)
            program = (HOST.replace("/* SCHEMA */", schema)
                       .replace("REFERENCE_BODY", body)
                       .replace("/* GATE */", gate)
                       .replace("MODULE_NAME", f'"{module}"'))
            source = scratch / f"{module}.c"
            source.write_text(program)
            binary = scratch / module
            subprocess.run([args.cc, "-O1", "-g", "-Wall", "-Werror", "-fsanitize=address,undefined",
                            str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
    print(f"gate placement before any install call: {', '.join(check_placement(root))}: PASS")
    if args.artifacts:
        print(f"static sidecars: {check_sidecars(args.artifacts, fields)} checked, "
              "template_abi/cred_uid still -1: PASS")


if __name__ == "__main__":
    main()
