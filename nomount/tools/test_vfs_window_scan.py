#!/usr/bin/env python3
"""源码扫描器正反夹具；通过只说明扫描器行为，不表示生产窗口已获证明。"""

import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

sys.dont_write_bytecode = True
from check_vfs_windows import WINDOWS, exit_code, scan_function, scan_source


class WindowScanTests(unittest.TestCase):
    def scan(self, body, words=27):
        return scan_function(f"static int probe(const unsigned* src) {{\n{body}\n}}", "probe", words)

    def test_strict_less_than_not_equality(self):
        for index in (0, 12, 26):
            with self.subTest(index=index):
                row = self.scan(f"return src[{index}];")
                self.assertEqual(row["status"], "PASS_LITERAL_ONLY")
                self.assertEqual(row["max_literal_index"], index)

    def test_equal_and_excess_are_failures(self):
        for index in (27, 30):
            with self.subTest(index=index):
                row = self.scan(f"return src[{index}];")
                self.assertEqual(row["status"], "FAIL")
                self.assertEqual(exit_code([row]), 1)

    def test_comments_strings_and_braces_do_not_count(self):
        row = self.scan('/* } src[999] */\n// src[888]\nconst char* s="src[777] }"; return src[2];')
        self.assertEqual(row["max_literal_index"], 2)
        self.assertEqual(row["status"], "PASS_LITERAL_ONLY")

    def test_function_calls_are_not_definitions(self):
        source = "int probe(const unsigned* src) { return src[2]; }\n"
        source += "int caller() { if (probe(src) < 0) { return 1; } return 0; }"
        self.assertEqual(scan_function(source, "probe", 27)["status"], "PASS_LITERAL_ONLY")

    def test_comparison_is_a_read(self):
        self.assertEqual(self.scan("return src[1] == 3;")["status"], "PASS_LITERAL_ONLY")

    def test_variable_subscript_never_passes(self):
        for expression in ("src[p + 10]", "src[at++]", "src[30 - 1]", "src[src[1]]"):
            with self.subTest(expression=expression):
                row = self.scan(f"return {expression};")
                self.assertEqual(row["status"], "UNCOVERED")
                self.assertEqual(exit_code([row]), 2)

    def test_pointer_operations_never_pass(self):
        for body in ("src++; return src[0];", "++src; return src[0];",
                     "src += 1; return src[0];", "return *(src + 30);",
                     "const unsigned* alias = src; return alias[30];",
                     "return old_matcher(src);", "return helper(&src[2]);",
                     "return helper(src + 2);", "return helper(&(src[2]));"):
            with self.subTest(body=body):
                self.assertNotEqual(self.scan(body)["status"], "PASS_LITERAL_ONLY")

    def test_address_is_not_a_literal_read(self):
        row = self.scan("return helper(&src[99]) + src[2];")
        self.assertEqual(row["max_literal_index"], 2)
        self.assertEqual(row["status"], "UNCOVERED")

    def test_unknown_does_not_hide_literal_violation(self):
        row = self.scan("return src[p] + src[30];")
        self.assertEqual(row["status"], "FAIL")
        self.assertTrue(row["uncovered"])

    def test_missing_duplicate_and_unclosed_definitions_fail(self):
        for source in ("", "int probe() {", "int probe() {} int probe() {}"):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    scan_function(source, "probe", 27)

    def test_preprocessor_never_passes(self):
        row = self.scan("#if FLAG\nreturn src[0];\n#endif")
        self.assertEqual(row["status"], "UNCOVERED")

    def test_integer_suffix_and_bases(self):
        row = self.scan("return src[0x1aU] + src[012];")
        self.assertEqual(row["max_literal_index"], 26)
        self.assertEqual(row["status"], "PASS_LITERAL_ONLY")

    def test_write_is_not_accepted_as_read_only(self):
        self.assertEqual(self.scan("src[1] = 3; return src[0];")["status"], "UNCOVERED")

    def test_line_numbers(self):
        row = self.scan("return src[0] +\n src[p];")
        self.assertEqual(row["uncovered"][0]["line"], 3)

    def test_three_anchors_include_legacy_helpers(self):
        self.assertEqual(len(WINDOWS), 5)
        self.assertEqual({anchor for anchor, _, _ in WINDOWS},
                         {"super_cache_count", "set_posix_acl", "d_set_d_op"})
        self.assertEqual(exit_code(scan_source("")), 1)

    def test_cli_exit_statuses(self):
        tool = Path(__file__).with_name("check_vfs_windows.py")
        for expression, expected in (("src[0]", 0), ("src[30]", 1), ("src[p]", 2)):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as temp:
                source = Path(temp) / "fixture.c"
                source.write_text("\n".join(f"static int {name}(const unsigned* src) {{ return {expression}; }}"
                                            for _, name, _ in WINDOWS))
                run = subprocess.run([sys.executable, str(tool), "--source", str(source)],
                                     text=True, capture_output=True)
                self.assertEqual(run.returncode, expected, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
