#!/usr/bin/env python3
"""核对版本化包名与配套 ZIP 自带更新记录的版本约束。

ZIP 与 KPM 独立更新：只要求 `module/CHANGELOG.md` 的首条标题等于 `module.prop` 的版本，
与 KPM 的发布版本无关。
"""
import ast
from pathlib import Path
import unittest

from build_zip import zip_changelog
from release_zip import MANIFEST, PACKAGE


class ZipMetadataTests(unittest.TestCase):
    def build_tree(self):
        return ast.parse(Path(__file__).with_name("build_zip.py").read_text())

    def test_versioned_package_and_builder_match(self):
        root = Path(__file__).resolve().parents[1]
        props = dict(line.split("=", 1) for line in (root / "module/module.prop").read_text().splitlines() if "=" in line)
        version = props["version"].removeprefix("v")
        self.assertEqual(PACKAGE, "NoMount-kpm_" + version + ".zip")
        self.assertEqual(MANIFEST, PACKAGE + ".json")
        package = next(node.value for node in ast.walk(self.build_tree())
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "package" for target in node.targets))
        result = eval(compile(ast.Expression(body=package), "build_zip.py", "eval"),
                      {"output": Path("artifacts"), "version": version})
        self.assertEqual(result.name, PACKAGE)

    def test_bundled_changelog_matches_zip_version(self):
        root = Path(__file__).resolve().parents[1]
        props = dict(line.split("=", 1) for line in (root / "module/module.prop").read_text().splitlines() if "=" in line)
        version = props["version"].removeprefix("v")
        data = (root / "module/CHANGELOG.md").read_bytes()
        result = zip_changelog(data, version).decode()
        self.assertTrue(result.startswith("## v" + version + "\n"))
        self.assertNotIn("\n## v", result)

    def test_leading_document_entry_is_rejected(self):
        data = "# 更新记录\n\n## 2026-10-17 文档整理\n\n文档。\n\n## v2.1.1\n\n发布原文。\n".encode()
        with self.assertRaisesRegex(AssertionError, "CHANGELOG release version mismatch"):
            zip_changelog(data, "2.1.1")

    def test_version_section_is_extracted(self):
        data = "# 更新记录\n\n## v2.1.1\n\n发布。\n\n## v2.1.0\n\n旧版。\n".encode()
        self.assertEqual(zip_changelog(data, "2.1.1").decode(), "## v2.1.1\n\n发布。\n")

    def test_wrong_release_is_rejected(self):
        data = "## v2.2\n\n新版。\n\n## v2.1.1\n\n旧版。\n".encode()
        with self.assertRaisesRegex(AssertionError, "CHANGELOG release version mismatch"):
            zip_changelog(data, "2.1.1")

    def test_missing_changelog_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "CHANGELOG release version mismatch"):
            zip_changelog(b"", "2.1.1")
        with self.assertRaisesRegex(AssertionError, "CHANGELOG release version mismatch"):
            zip_changelog(b"# NoMount\n", "2.1.1")


if __name__ == "__main__":
    unittest.main()
