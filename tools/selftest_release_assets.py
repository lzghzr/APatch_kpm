#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""按正式发布的两步核对资产：准备发布包，再选择上传附件。"""

import json
import shutil
import subprocess
import unittest

from selftest_artifact_gate import fixture
from selftest_offset_modes import MODULES, write_product
from selftest_workflow_support import REPO, WorkflowStepTestCase


class ReleaseAssetsTests(WorkflowStepTestCase):
    """第一步：从 CI 产物准备发布包，并用真实门禁校验。"""

    step_name = "Prepare release assets"

    def setUp(self):
        super().setUp()
        self.target = self.root / "target"
        self.target.mkdir()

        # 门禁读取父仓和 KernelPatch 的提交；两者都使用临时仓库，不依赖开发工作区。
        tools = self.root / "tools"
        tools.mkdir()
        shutil.copy2(REPO / "tools/artifact_gate.py", tools)
        for repo in (self.root, self.root / "KernelPatch"):
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "marker").write_text("x\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "init"], check=True)

    def write_unified_assets(self):
        for debug in (False, True):
            data, layout = fixture(unified=True, debug=debug)
            (self.target / layout["kpm"]).write_bytes(data)
            (self.target / (layout["kpm"] + ".json")).write_text(json.dumps(layout))
        data, _ = fixture(unified=True)
        # 保持元数据字节长度，避免移动 ELF 中记录的节位置。
        (self.target / "other_mod_x_1.6.kpm").write_bytes(data.replace(b"name=re_kernel_x\0", b"name=other_mod_x\0"))
        (self.target / "modules.txt").write_text("re_kernel_x\nother_mod_x\n")

    def write_dual_mode_assets(self, *, include_cgroup=False):
        for module in MODULES:
            for mode in ('static', 'dynamic'):
                for debug in (False, True):
                    write_product(self.target, module, mode, debug)
        modules = list(MODULES)
        if include_cgroup:
            modules.append('cgroupv2_freeze')
            for mode in ('static', 'dynamic'):
                write_product(self.target, 'cgroupv2_freeze', mode)
        (self.target / 'modules.txt').write_text('\n'.join(modules) + '\n')

    def reject(self):
        result = self.run_step()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "release/BUILD_MANIFEST.json").exists())

    def test_unified_release_and_other_modules(self):
        self.write_unified_assets()
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.root / "release"
        self.assertEqual({p.name for p in release.iterdir()}, {
            "re_kernel_x_1.6.kpm", "re_kernel_x_1.6.kpm.json", "other_mod_x_1.6.kpm",
            "BUILD_MANIFEST.json", "SHA256SUMS"})
        for name in ("re_kernel_x_1.6.kpm", "re_kernel_x_1.6.kpm.json", "other_mod_x_1.6.kpm"):
            self.assertEqual((release / name).read_bytes(), (self.target / name).read_bytes())
        self.assertTrue((self.target / "re_kernel_x_1.6_debug.kpm").is_file())
        self.assertTrue((self.target / "re_kernel_x_1.6_debug.kpm.json").is_file())

    def test_duplicate_baseline_rejected(self):
        self.write_unified_assets()
        data, layout = fixture()
        (self.target / layout["kpm"]).write_bytes(data)
        (self.target / (layout["kpm"] + ".json")).write_text(json.dumps(layout))
        self.reject()

    def test_missing_layout_rejected(self):
        self.write_unified_assets()
        (self.target / "re_kernel_x_1.6.kpm.json").unlink()
        self.reject()

    def test_missing_baseline_rejected(self):
        self.write_unified_assets()
        (self.target / "re_kernel_x_1.6.kpm").unlink()
        (self.target / "re_kernel_x_1.6.kpm.json").unlink()
        self.reject()

    def test_release_contains_six_normal_products_and_three_layouts(self):
        self.write_dual_mode_assets()
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.root / 'release'
        self.assertEqual(len(list(release.glob('*.kpm'))), 6)
        self.assertEqual(len(list(release.glob('*.kpm.json'))), 3)
        self.assertFalse(list(release.glob('*_debug.kpm')))
        for path in release.glob('*.kpm*'):
            self.assertEqual(path.read_bytes(), (self.root / 'target' / path.name).read_bytes())

    def test_release_requires_run_cmd_dynamic(self):
        self.write_dual_mode_assets()
        (self.target / 'run_cmd_demo_1.0.kpm').unlink()
        self.reject()

    def test_release_requires_run_cmd_static_layout(self):
        self.write_dual_mode_assets()
        (self.target / 'run_cmd_demo_1.0_baselines.kpm.json').unlink()
        self.reject()

    def test_release_collects_cgroup_pair_and_layout(self):
        self.write_dual_mode_assets(include_cgroup=True)
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        prefix = 'cgroupv2_freeze_1.0'
        self.assertEqual({p.name for p in (self.root / 'release').glob(prefix + '*')},
                         {prefix + ext for ext in ('.kpm', '_baselines.kpm', '_baselines.kpm.json')})

    def test_release_rejects_cgroup_dynamic_only(self):
        self.write_dual_mode_assets(include_cgroup=True)
        for path in self.target.glob('cgroupv2_freeze_*_baselines.kpm*'):
            path.unlink()
        self.reject()


class UploadSelectionTests(WorkflowStepTestCase):
    """第二步：从准备好的发布包里选出用户实际下载的附件。"""

    step_name = "Select release uploads"

    def setUp(self):
        super().setUp()
        self.release = self.root / "release"
        self.release.mkdir()
        for name in ("re_kernel_x_1.6.kpm", "other_mod_x_1.6.kpm",
                     "run_cmd_demo_1.3.0.kpm", "run_cmd_demo_1.3.0_baselines.kpm",
                     "NoMount-kpm_2.1.1-20261014.zip"):
            (self.release / name).write_bytes(b"payload")
        for name in ("re_kernel_x_1.6.kpm.json", "run_cmd_demo_1.3.0_baselines.kpm.json",
                     "BUILD_MANIFEST.json", "NoMount-kpm_2.1.1-20261014.zip.json", "NoMount-kpm.json"):
            (self.release / name).write_text("{}")
        (self.release / "SHA256SUMS").write_text("")

    def test_uploads_only_user_assets(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual({p.name for p in (self.root / "upload").iterdir()}, {
            "re_kernel_x_1.6.kpm", "re_kernel_x_1.6.kpm.json", "other_mod_x_1.6.kpm",
            "run_cmd_demo_1.3.0.kpm", "run_cmd_demo_1.3.0_baselines.kpm",
            "run_cmd_demo_1.3.0_baselines.kpm.json",
            "NoMount-kpm_2.1.1-20261014.zip", "NoMount-kpm.json"})

    def test_missing_companion_zip_rejected(self):
        (self.release / "NoMount-kpm_2.1.1-20261014.zip").unlink()
        self.assertNotEqual(self.run_step().returncode, 0)

    def test_missing_update_manifest_rejected(self):
        (self.release / "NoMount-kpm.json").unlink()
        self.assertNotEqual(self.run_step().returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
