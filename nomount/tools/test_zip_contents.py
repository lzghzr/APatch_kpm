#!/usr/bin/env python3
"""核对 ZIP 白名单、构建输入选择及缺项/多项/重复拒绝。"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from build_zip import (COMPILER_LICENSE_FILES, MODULE_PACKAGE_FILES,
                       check_package_entries, module_inputs, package_entries)


class ZipContentsTests(unittest.TestCase):
    LOCAL_FILES = {
        'module.prop', 'customize.sh', 'post-fs-data.sh', 'boot-completed.sh',
        'uninstall.sh', 'metamount.sh', 'common.sh', 'README.md', 'NOTICE.md',
    }

    def test_frozen_module_inputs_ignore_unlisted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(set(MODULE_PACKAGE_FILES), self.LOCAL_FILES)
            paths = [*('nomount/module/' + name for name in sorted(self.LOCAL_FILES)),
                     'nomount/module/CHANGELOG.md', 'nomount/tools/build_zip.py',
                     'nomount/tools/build_nm.sh', 'nomount/tools/cli-module.patch',
                     'nomount/module/AGENTS.md', 'nomount/module/dump_rules.sh',
                     'nomount/module/surprise.sh', 'nomount/module/extra/note.md']
            for rel in paths:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(rel + '\n')
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c',
                            'user.email=fixture@example.invalid', '-c',
                            'commit.gpgsign=false', 'commit', '--no-gpg-sign',
                            '-qm', 'fixture'], cwd=root, check=True)
            inputs, contents = module_inputs(root, 'HEAD')
            self.assertEqual(set(inputs), set(paths[:len(self.LOCAL_FILES) + 4]))
            self.assertEqual(set(contents), self.LOCAL_FILES |
                             {'sources/build-nm.sh', 'sources/cli-module.patch'})
            self.assertEqual(contents['README.md'], b'nomount/module/README.md\n')
            self.assertEqual(contents['NOTICE.md'], b'nomount/module/NOTICE.md\n')
            self.assertIn('nomount/module/CHANGELOG.md', inputs)
            self.assertNotIn('CHANGELOG.md', contents)

    def expected(self, compiler='zig'):
        return package_entries(['module/metainstall.sh', 'module/webroot/index.js',
                                'module/webroot/locales/zh.json', 'userspace/src/nm.c',
                                'userspace/src/nm.h', 'LICENSE'], compiler)

    def test_expanded_whitelist_for_both_compilers(self):
        core = self.LOCAL_FILES | {
            'metainstall.sh', 'LICENSE', 'bin/nm', 'sources/build-nm.sh',
            'sources/cli-module.patch', 'sources/nm.c', 'sources/nm.h',
            'webroot/index.js', 'webroot/locales/zh.json',
        }
        licenses_by_compiler = {
            'zig': ('licenses/musl-COPYRIGHT', 'licenses/zig-LICENSE'),
            'ndk': ('licenses/NDK-NOTICE', 'licenses/NDK-NOTICE.toolchain'),
        }
        self.assertEqual(COMPILER_LICENSE_FILES, licenses_by_compiler)
        for compiler, licenses in licenses_by_compiler.items():
            with self.subTest(compiler=compiler):
                expected = self.expected(compiler)
                self.assertEqual(expected, core | set(licenses))
                check_package_entries(list(expected), expected)

    def test_extra_entries_rejected_even_inside_approved_directory(self):
        expected = self.expected()
        for extra in ['CHANGELOG.md', 'AGENTS.md', 'dump_rules.sh',
                      'other.sh', 'sources/unselected.c', 'licenses/unselected.txt',
                      'webroot/unselected.js']:
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(AssertionError, 'whitelist mismatch'):
                    check_package_entries([*expected, extra], expected)

    def test_every_required_entry_is_required(self):
        expected = self.expected()
        for missing in sorted(expected):
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(AssertionError, 'whitelist mismatch'):
                    check_package_entries(list(expected - {missing}), expected)

    def test_duplicate_entry_rejected(self):
        expected = self.expected()
        with self.assertRaisesRegex(AssertionError, 'duplicate entries'):
            check_package_entries([*expected, 'module.prop'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
