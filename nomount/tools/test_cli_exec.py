#!/usr/bin/env python3
"""执行生产安装脚本，区分 CLI 加载、KPM 连接失败并验证失败时不创建数据或快捷入口。"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = r'''#!/bin/sh
printf '%s\n' "${*:-probe}" >> "$CALLS"
case "$*" in
    '')
        case "$MODE" in
            exit134) echo "executable's TLS segment is underaligned: alignment is 8, needs to be at least 64 for ARM64 Bionic" >&2; exit 134 ;;
            exit126) echo 'cannot execute binary file' >&2; exit 126 ;;
            exit127) echo 'not found' >&2; exit 127 ;;
            badhelp) echo 'unexpected application'; exit 1 ;;
            zero) echo 'NoMount CLI (nm) - Usage Guide:'; exit 0 ;;
        esac
        printf 'NoMount CLI (nm) - Usage Guide:\n\nRule Commands:\n'; exit 1 ;;
    version)
        [ "$MODE" != queryerror ] || exit 7
        if [ "$MODE" = wrongversion ]; then echo '24 (KPM fixture)'; else echo "$VERSION (KPM fixture)"; fi ;;
    'uid block_isolated')
        [ "$MODE" != isolatederror ] || exit 7
        if [ "$MODE" = badisolated ]; then echo unknown; else echo 0; fi ;;
    *) echo "unexpected operation: $*" >&2; exit 99 ;;
esac
'''
HARNESS = r'''
ui_print() { printf '%s\n' "$*"; }
abort() { ui_print "$*"; exit 1; }
set_perm() { printf 'set_perm\n' >> "$WRITES"; }
mkdir() { printf 'mkdir\n' >> "$WRITES"; }
ln() { printf 'ln\n' >> "$WRITES"; }
. "$1"
'''


class CliExecutionTests(unittest.TestCase):
    def run_install(self, mode='ready', version='23'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            binary = root / 'bin/nm'
            binary.write_text(CLI)
            binary.chmod(0o755)
            shutil.copyfile(ROOT / 'module/common.sh', root / 'common.sh')
            calls, writes = root / 'calls', root / 'writes'
            env = dict(os.environ, APATCH='true', ARCH='arm64', MODPATH=str(root),
                       CALLS=str(calls), WRITES=str(writes), MODE=mode, VERSION=version)
            result = subprocess.run(['sh', '-c', HARNESS, 'fixture',
                                     str(ROOT / 'module/customize.sh')],
                                    env=env, text=True, capture_output=True)
            return (result, calls.read_text().splitlines(), writes.read_text().splitlines())

    def test_supported_protocols_install_after_execution_probe(self):
        for version in ('22', '23'):
            with self.subTest(version=version):
                result, calls, writes = self.run_install(version=version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, ['probe', 'version', 'uid block_isolated'])
                self.assertEqual(writes, ['set_perm', 'mkdir', 'ln'])
                self.assertIn('NoMount 已连接', result.stdout)

    def test_cli_load_failures_stop_before_kpm_and_install_writes(self):
        for mode in ('exit134', 'exit126', 'exit127', 'badhelp', 'zero'):
            with self.subTest(mode=mode):
                result, calls, writes = self.run_install(mode)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(calls, ['probe'])
                self.assertEqual(writes, ['set_perm'])
                self.assertIn('配套 CLI 无法在本机执行', result.stdout)
                self.assertNotIn('无法连接 NoMount', result.stdout)
                if mode == 'exit134':
                    self.assertIn('TLS segment is underaligned', result.stdout)
                    self.assertIn('退出码 134', result.stdout)

    def test_driver_errors_remain_connection_failures(self):
        for mode, calls in [('queryerror', ['probe', 'version']),
                            ('wrongversion', ['probe', 'version']),
                            ('isolatederror', ['probe', 'version', 'uid block_isolated']),
                            ('badisolated', ['probe', 'version', 'uid block_isolated'])]:
            with self.subTest(mode=mode):
                result, actual, writes = self.run_install(mode)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(actual, calls)
                self.assertEqual(writes, ['set_perm'])
                self.assertIn('无法连接 NoMount', result.stdout)
                self.assertNotIn('配套 CLI 无法在本机执行', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
