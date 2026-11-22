#!/usr/bin/env python3
"""用实际工具链核对 re_kernel_x 默认和独立输出目录的内嵌布局。"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from patch_offsets import configuration_sections, elf_sections


def run(*args, env):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def check(work, kp_dir, toolchain, version, separate):
    module = work / "re_kernel_x"
    shutil.copytree(ROOT / module.name, module, ignore=shutil.ignore_patterns(
        "*.kpm", "*.kpm.json", "*.o", "out", "local", "re_vmlinux", "__pycache__"))
    for shared in ("kpm_toolchain.mk", "kpm_runtime.c", "kpm_utils.h", "patch_offsets.py"):
        shutil.copyfile(ROOT / shared, work / shared)

    env = os.environ.copy()
    env.pop("OUT_DIR", None)
    env.pop("LAYOUT_DIR", None)
    output = work / "products" if separate else module
    make = ["make", "-C", str(module), f"KP_DIR={kp_dir}", f"TOOLCHAIN={toolchain}"]
    if separate:
        make += [f"OUT_DIR={output}"]

    run(*make, env=env)
    assert not list(output.glob("*_debug.kpm*")), "默认目标不应构建 debug"
    run(*make, "debug", env=env)

    stem = f"re_kernel_x_{version}"
    static = [output / f"{stem}{suffix}.kpm" for suffix in ("_baselines", "_baselines_debug")]
    dynamic = [output / f"{stem}{suffix}.kpm" for suffix in ("", "_debug")]
    assert set(output.glob("*.kpm")) == set(static + dynamic)
    layouts = []
    for kpm in static:
        raw = configuration_sections(kpm.read_bytes())[3]
        assert raw is not None, f"{kpm.name}: 缺少 .kpm.layout"
        exported = work / f"{kpm.name}.json"
        run(sys.executable, str(work / "patch_offsets.py"), "baseline", str(kpm),
            "--source", str(module / "re_offsets.c"), "--output", str(exported), env=env)
        sidecar = kpm.with_suffix(".kpm.json")
        assert sidecar.is_file(), f"{kpm.name}: 缺少配套 JSON"
        assert exported.read_bytes() == sidecar.read_bytes(), kpm.name
        layouts.append(raw)
    assert set(output.glob("*.kpm.json")) == {kpm.with_suffix(".kpm.json") for kpm in static}
    for kpm in dynamic:
        image = kpm.read_bytes()
        entries, names_index = elf_sections(image)
        names = entries[names_index]
        assert b"\0.kpm.layout\0" not in image[names[4]:names[4] + names[5]], kpm.name

    run(*make, "ci", env=env)
    print(f"{toolchain} / {work.name}: 普通、调试静态版均含内嵌布局和配套 JSON")
    return layouts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kp-dir", type=Path, default=ROOT / "KernelPatch")
    parser.add_argument("--toolchain", choices=("gcc", "ndk"), default="gcc")
    args = parser.parse_args()
    assert (args.kp_dir / "kernel/include/kpmodule.h").is_file(), "需要已初始化的 KernelPatch SDK"
    version = re.search(r"^MYKPM_VERSION\s*:=\s*(\S+)",
                        (ROOT / "re_kernel_x/Makefile").read_text(), re.M)[1]
    with tempfile.TemporaryDirectory(prefix="rekx-layout-") as directory:
        root = Path(directory)
        default = check(root / "default", args.kp_dir.resolve(), args.toolchain, version, False)
        separate = check(root / "separate", args.kp_dir.resolve(), args.toolchain, version, True)
        assert default[0] == default[1] == separate[0] == separate[1]


if __name__ == "__main__":
    main()
