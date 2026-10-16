#!/usr/bin/env python3
"""验证 ZIP 发布副本的身份绑定、传输损坏及版本混用边界。"""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from release_zip import MANIFEST, PACKAGE, digest, merge, prepare


class ZipReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        archive = self.root / "archive"
        archive.mkdir()
        self.package = archive / PACKAGE
        with zipfile.ZipFile(self.package, "w") as package:
            package.writestr("module.prop", "id=nomount\nname=NoMount-kpm\nversion=v2.1.1-20261014\n")
        self.manifest = {
            "module": "nomount", "kind": "companion-zip", "version": "2.1.1-20261014",
            "source_commit": "a" * 40, "upstream_commit": "b" * 40,
            "instance_id": "fixture#1", "source_dirty": False, "input_unchanged": True,
            "artifacts": [{"name": PACKAGE, "path": str(self.package),
                           "sha256": digest(self.package), "size": self.package.stat().st_size}],
        }
        self.write_manifest()
        self.result = self.root / "result.json"
        self.result.write_text(json.dumps({
            "artifact": self.manifest["artifacts"][0], "instance_id": "fixture#1", "source_commit": "a" * 40}))
        self.staged = self.root / "zip"
        self.release = self.root / "release"
        self.release.mkdir()
        self.kpm = self.release / "NoMount_2.1.1-20261014.kpm"
        self.kpm.write_bytes(b"frozen KPM fixture")
        self.build = {"source_commit": "a" * 40, "artifacts": [
            {"file": self.kpm.name, "sha256": digest(self.kpm),
             "info": {"name": "NoMount", "version": "2.1.1-20261014"}}]}
        self.write_build()

    def write_manifest(self):
        (self.package.parent / "MANIFEST.json").write_text(json.dumps(self.manifest))

    def write_build(self):
        (self.release / "BUILD_MANIFEST.json").write_text(json.dumps(self.build))

    def stage(self):
        prepare(self.result, self.staged)

    def test_merge_preserves_kpm_and_archive_and_hashes_every_file(self):
        old_kpm = self.kpm.read_bytes()
        old_archive = self.package.read_bytes()
        old_manifest = (self.package.parent / "MANIFEST.json").read_bytes()
        self.stage()
        merge(self.staged, self.release)
        self.assertEqual(self.kpm.read_bytes(), old_kpm)
        self.assertEqual(self.package.read_bytes(), old_archive)
        self.assertEqual((self.package.parent / "MANIFEST.json").read_bytes(), old_manifest)
        self.assertEqual((self.release / PACKAGE).read_bytes(), old_archive)
        build = json.loads((self.release / "BUILD_MANIFEST.json").read_text())
        self.assertEqual(build["artifacts"], self.build["artifacts"])
        self.assertEqual(build["companions"][0]["instance_id"], "fixture#1")
        lines = (self.release / "SHA256SUMS").read_text().splitlines()
        sums = dict(line.split("  ", 1)[::-1] for line in lines)
        self.assertEqual(set(sums), {self.kpm.name, PACKAGE, MANIFEST, "BUILD_MANIFEST.json"})
        for name, value in sums.items():
            self.assertEqual(digest(self.release / name), value)

    def test_downloaded_zip_damage_rejected(self):
        self.stage()
        (self.staged / PACKAGE).write_bytes(b"damaged ZIP")
        with self.assertRaisesRegex(ValueError, "产物哈希"):
            merge(self.staged, self.release)

    def test_different_source_commit_rejected(self):
        self.stage()
        self.build["source_commit"] = "c" * 40
        self.write_build()
        with self.assertRaisesRegex(ValueError, "来源提交"):
            merge(self.staged, self.release)
        self.assertFalse((self.release / PACKAGE).exists())

    def test_different_version_rejected(self):
        self.stage()
        self.build["artifacts"][0]["info"]["version"] = "0.5.2"
        self.write_build()
        with self.assertRaisesRegex(ValueError, "版本"):
            merge(self.staged, self.release)

    def test_missing_nomount_kpm_rejected(self):
        self.stage()
        self.build["artifacts"] = []
        self.write_build()
        with self.assertRaisesRegex(ValueError, "缺少 NoMount"):
            merge(self.staged, self.release)

    def test_repeated_merge_cannot_replace_assets(self):
        self.stage()
        merge(self.staged, self.release)
        original = {path.name: path.read_bytes() for path in self.release.iterdir()}
        with self.assertRaisesRegex(ValueError, "拒绝覆盖"):
            merge(self.staged, self.release)
        self.assertEqual({path.name: path.read_bytes() for path in self.release.iterdir()}, original)

    def test_dirty_zip_candidate_rejected(self):
        self.manifest["source_dirty"] = True
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "构建身份"):
            self.stage()
        self.assertFalse(self.staged.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
