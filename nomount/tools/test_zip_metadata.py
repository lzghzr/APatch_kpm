#!/usr/bin/env python3
"""核对版本化包名与更新记录首条的原始版本约束。"""
import ast
from pathlib import Path
import unittest

from release_zip import MANIFEST, PACKAGE


class ZipMetadataTests(unittest.TestCase):
    def build_tree(self):
        return ast.parse(Path(__file__).with_name("build_zip.py").read_text())

    def extract_changelog(self, readme, version):
        # 直接执行 main 中原有的三条语句，测试不另行解析或过滤历史。
        main = next(node for node in self.build_tree().body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        statements = []
        for node in main.body:
            if isinstance(node, ast.Assign):
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id == "history":
                    statements.append(node)
                elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                      and target.value.id == "contents" and isinstance(target.slice, ast.Constant)
                      and target.slice.value == "CHANGELOG.md"):
                    statements.append(node)
            elif (isinstance(node, ast.Assert) and isinstance(node.msg, ast.Constant)
                  and node.msg.value == "README release version mismatch"):
                statements.append(node)
        self.assertEqual(len(statements), 3)
        namespace = {"readme": readme, "version": version, "contents": {}}
        exec(compile(ast.Module(body=statements, type_ignores=[]), "build_zip.py", "exec"), namespace)
        return namespace["contents"]["CHANGELOG.md"].decode()

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

    def test_current_readme_starts_with_release(self):
        root = Path(__file__).resolve().parents[1]
        props = dict(line.split("=", 1) for line in (root / "module/module.prop").read_text().splitlines() if "=" in line)
        version = props["version"].removeprefix("v")
        result = self.extract_changelog((root / "README.md").read_text(), version)
        self.assertTrue(result.startswith("### " + version + "\n"))
        self.assertNotIn("\n### ", result)

    def test_leading_document_entry_is_rejected(self):
        readme = "## 更新记录\n\n### 2026-10-17 文档整理\n\n文档。\n\n### 2.1.1\n\n发布原文。\n"
        with self.assertRaisesRegex(AssertionError, "README release version mismatch"):
            self.extract_changelog(readme, "2.1.1")

    def test_version_first_history_is_supported(self):
        self.assertEqual(self.extract_changelog("## 更新记录\n\n### 2.1.1\n\n发布。\n", "2.1.1"),
                         "### 2.1.1\n\n发布。\n")

    def test_wrong_first_release_is_rejected(self):
        readme = "## 更新记录\n\n### 2.2\n\n新版。\n\n### 2.1.1\n\n旧版。\n"
        with self.assertRaisesRegex(AssertionError, "README release version mismatch"):
            self.extract_changelog(readme, "2.1.1")

    def test_no_release_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "README release version mismatch"):
            self.extract_changelog("## 更新记录\n\n### 2026-10-17 文档\n\n说明。\n", "2.1.1")

    def test_missing_history_is_rejected(self):
        with self.assertRaises(IndexError):
            self.extract_changelog("# NoMount\n", "2.1.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
