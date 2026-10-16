#!/usr/bin/env python3
"""核对正式发布的更新入口、版本化下载地址及变更说明。"""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from release_zip import CHANGELOG, MANIFEST, PACKAGE, UPDATE, digest, merge, prepare, publish_update


class UpdateJsonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        archive = self.root / "archive"
        archive.mkdir()
        package = archive / PACKAGE
        self.props = ("id=nomount\nname=NoMount-kpm\nversion=v2.1.1-20261014\n"
                      "versionCode=20261014\nupdateJson=https://github.com/lzghzr/APatch_kpm/"
                      "releases/latest/download/NoMount-kpm.json\n")
        with zipfile.ZipFile(package, "w") as contents:
            contents.writestr("module.prop", self.props)
            contents.writestr("CHANGELOG.md", "### 2.1.1-20261014\n\n发布 NoMount KPM。\n")
        manifest = {
            "module": "nomount", "kind": "companion-zip", "version": "2.1.1-20261014",
            "source_commit": "a" * 40, "upstream_commit": "b" * 40,
            "instance_id": "fixture#1", "source_dirty": False, "input_unchanged": True,
            "artifacts": [{"name": PACKAGE, "path": str(package), "sha256": digest(package),
                           "size": package.stat().st_size}],
        }
        (archive / "MANIFEST.json").write_text(json.dumps(manifest))
        result = self.root / "result.json"
        result.write_text(json.dumps({"source_commit": "a" * 40, "instance_id": "fixture#1",
                                      "artifact": manifest["artifacts"][0]}))
        self.release = self.root / "release"
        self.release.mkdir()
        (self.release / "BUILD_MANIFEST.json").write_text(json.dumps({
            "source_commit": "a" * 40, "artifacts": [
                {"info": {"name": "NoMount", "version": "2.1.1-20261014"}}]}))
        staged = self.root / "zip"
        prepare(result, staged)
        merge(staged, self.release)

    def test_update_points_to_tagged_versioned_zip_and_bundled_changelog(self):
        publish_update(self.release, "release/2026 10", "lzghzr/APatch_kpm")
        update = json.loads((self.release / UPDATE).read_text())
        self.assertEqual(update, {
            "version": "v2.1.1-20261014", "versionCode": 20261014,
            "zipUrl": "https://github.com/lzghzr/APatch_kpm/releases/download/release%2F2026%2010/" + PACKAGE,
            "changelog": "https://github.com/lzghzr/APatch_kpm/releases/download/release%2F2026%2010/" + CHANGELOG,
        })
        self.assertIs(type(update["versionCode"]), int)
        with zipfile.ZipFile(self.release / PACKAGE) as package:
            self.assertEqual((self.release / CHANGELOG).read_bytes(), package.read("CHANGELOG.md"))
        lines = (self.release / "SHA256SUMS").read_text().splitlines()
        sums = dict(line.split("  ", 1)[::-1] for line in lines)
        self.assertEqual(set(sums), {PACKAGE, MANIFEST, "BUILD_MANIFEST.json", UPDATE, CHANGELOG})
        for name, value in sums.items():
            self.assertEqual(digest(self.release / name), value)

    def test_repository_mismatch_rejected_before_update_files_written(self):
        with self.assertRaisesRegex(ValueError, "发布仓库"):
            publish_update(self.release, "1.0.0", "Other/Repository")
        self.assertFalse((self.release / UPDATE).exists())
        self.assertFalse((self.release / CHANGELOG).exists())

    def test_repeated_update_cannot_replace_metadata(self):
        publish_update(self.release, "1.0.0", "lzghzr/APatch_kpm")
        before = {path.name: path.read_bytes() for path in self.release.iterdir()}
        with self.assertRaisesRegex(ValueError, "拒绝覆盖"):
            publish_update(self.release, "1.0.1", "lzghzr/APatch_kpm")
        self.assertEqual({path.name: path.read_bytes() for path in self.release.iterdir()}, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
