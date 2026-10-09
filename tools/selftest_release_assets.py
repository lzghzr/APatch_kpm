#!/usr/bin/env python3
"""执行 Actions 中的真实 Release 筛选脚本，验证统一基线及其他模块的发布范围。"""

from pathlib import Path
import json
import subprocess
import tempfile
import textwrap
import unittest

from selftest_artifact_gate import fixture


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        repo = Path(__file__).resolve().parents[1]
        (self.root / "tools").symlink_to(repo / "tools", target_is_directory=True)
        workflow = (repo / ".github/workflows/build-kpm.yml").read_text()
        step = workflow.split("      - name: Prepare release assets\n", 1)[1]
        self.script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
        for debug in (False, True):
            data, layout = fixture(unified=True, debug=debug)
            (self.target / layout["kpm"]).write_bytes(data)
            (self.target / (layout["kpm"] + ".json")).write_text(json.dumps(layout))
        data, _ = fixture(unified=True)
        # 保持元数据字节长度，避免移动 ELF 中记录的节位置。
        (self.target / "other_mod_x_1.6.kpm").write_bytes(data.replace(b"name=re_kernel_x\0", b"name=other_mod_x\0"))
        (self.target / "modules.txt").write_text("re_kernel_x\nother_mod_x\n")

    def run_script(self):
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", self.script], cwd=self.root,
                              capture_output=True, text=True)

    def test_unified_release_and_other_modules(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.root / "release"
        self.assertEqual({p.name for p in release.iterdir()}, {
            "re_kernel_x_1.6.kpm", "re_kernel_x_1.6.kpm.json", "other_mod_x_1.6.kpm",
            "BUILD_MANIFEST.json", "SHA256SUMS"})
        for name in ("re_kernel_x_1.6.kpm", "re_kernel_x_1.6.kpm.json", "other_mod_x_1.6.kpm"):
            self.assertEqual((release / name).read_bytes(), (self.target / name).read_bytes())
        self.assertTrue((self.target / "re_kernel_x_1.6_debug.kpm").is_file())
        self.assertTrue((self.target / "re_kernel_x_1.6_debug.kpm.json").is_file())

    def reject(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "release/BUILD_MANIFEST.json").exists())

    def test_duplicate_baseline_rejected(self):
        data, layout = fixture()
        (self.target / layout["kpm"]).write_bytes(data)
        (self.target / (layout["kpm"] + ".json")).write_text(json.dumps(layout))
        self.reject()

    def test_missing_layout_rejected(self):
        (self.target / "re_kernel_x_1.6.kpm.json").unlink()
        self.reject()

    def test_missing_baseline_rejected(self):
        (self.target / "re_kernel_x_1.6.kpm").unlink()
        (self.target / "re_kernel_x_1.6.kpm.json").unlink()
        self.reject()


if __name__ == "__main__":
    unittest.main(verbosity=2)
