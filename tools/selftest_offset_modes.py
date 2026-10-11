#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""独立 ELF 夹具核验三模块双模式、普通布局及真实 Release 筛选。"""

import hashlib
import json
import struct
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from artifact_gate import validate

MODULES = ('re_kernel', 're_kernel_x', 'run_cmd_demo')


def product(module, mode, debug=False):
    version = '1.0_d' if debug else '1.0'
    name = module + '_1.0' + ('_baselines' if mode == 'static' else '') + ('_debug' if debug else '') + '.kpm'
    generic = module == 'run_cmd_demo'
    fields = ['path', 'security', 'sid', 'worker_size'] if generic else ['first', 'second', 'binder_release_abi']
    values = [-1, -1, -1, -1] if generic else [16, -1, 6]
    info = f'name={module}\0version={version}\0offset_mode={mode}\0license=GPL v2\0author=Fixture\0description=Mode fixture\0'.encode()
    sections = [('', 0, b''), ('.shstrtab', 3, b''), ('.kpm.info', 1, info),
                ('.kpm.init', 1, bytes(8)), ('.kpm.exit', 1, bytes(8))]
    if mode == 'static':
        sections.append(('.data.re_offsets', 1, struct.pack('<' + 'h' * len(values), *values)))
    strings = b'\0'
    names = []
    for section, _, _ in sections:
        names.append(len(strings) if section else 0)
        if section:
            strings += section.encode() + b'\0'
    sections[1] = ('.shstrtab', 3, strings)
    content = bytearray(64 + 64 * len(sections))
    content[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                              1, 183, 1, 0, 0, 64, 0, 64, 0, 0, 64, len(sections), 1)
    offsets = {}
    for i, ((section, kind, raw), at) in enumerate(zip(sections, names)):
        offset = len(content)
        offsets[section] = offset
        content += raw
        struct.pack_into('<IIQQQQIIQQ', content, 64 + i * 64, at, kind,
                         3 if section == '.data.re_offsets' else 0, 0, offset, len(raw), 0, 0, 1, 0)
    data = bytes(content)
    layout = None
    if mode == 'static':
        layout = {'schema': 3 if generic else 2, 'kpm': name, 'sha256': hashlib.sha256(data).hexdigest(),
                  'table_offset': offsets['.data.re_offsets'], 'table_size': len(values) * 2,
                  'fields': fields, 'offsets': dict(zip(fields, values))}
        if not generic:
            layout['binder_abi'] = 6
    return name, data, layout


def write_product(root, module, mode, debug=False):
    name, data, layout = product(module, mode, debug)
    path = root / name
    path.write_bytes(data)
    if layout is not None:
        Path(str(path) + '.json').write_text(json.dumps(layout))
    return path, layout


class OffsetModesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_all_modules_modes_and_debug(self):
        for module in MODULES:
            for mode in ('static', 'dynamic'):
                for debug in (False, True):
                    write_product(self.root, module, mode, debug)
        self.assertEqual(len(validate(self.root, MODULES)), 12)

    def test_static_requires_layout(self):
        for module in MODULES:
            with self.subTest(module=module):
                path, _ = write_product(self.root, module, 'static')
                Path(str(path) + '.json').unlink()
                with self.assertRaises(OSError):
                    validate(self.root)
                path.unlink()

    def test_dynamic_rejects_layout(self):
        path, _ = write_product(self.root, 'run_cmd_demo', 'dynamic')
        Path(str(path) + '.json').write_text('{}')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_mode_filename_mismatch(self):
        path, _ = write_product(self.root, 'run_cmd_demo', 'dynamic')
        path.rename(self.root / 'run_cmd_demo_1.0_baselines.kpm')
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_schema3_rejects_bad_identity_and_values(self):
        path, layout = write_product(self.root, 'run_cmd_demo', 'static')
        for key, value in [('schema', True), ('schema', 2), ('binder_abi', 6), ('table_size', True),
                           ('sha256', '0' * 64), ('table_offset', 0), ('fields', ['path'] * 4),
                           ('offsets', {**layout['offsets'], 'sid': 4})]:
            with self.subTest(key=key, value=value):
                Path(str(path) + '.json').write_text(json.dumps({**layout, key: value}))
                with self.assertRaises(ValueError):
                    validate(self.root)

    def test_binder_cannot_downgrade_to_schema3(self):
        for module in MODULES[:2]:
            with self.subTest(module=module):
                path, layout = write_product(self.root, module, 'static')
                layout['schema'] = 3
                del layout['binder_abi']
                Path(str(path) + '.json').write_text(json.dumps(layout))
                with self.assertRaises(ValueError):
                    validate(self.root)
                path.unlink()
                Path(str(path) + '.json').unlink()

    def release(self, mutation=None):
        target = self.root / 'target'
        target.mkdir()
        repo = Path(__file__).resolve().parents[1]
        (self.root / 'tools').symlink_to(repo / 'tools', target_is_directory=True)
        for module in MODULES:
            for mode in ('static', 'dynamic'):
                for debug in (False, True):
                    write_product(target, module, mode, debug)
        (target / 'modules.txt').write_text('\n'.join(MODULES) + '\n')
        if mutation:
            mutation(target)
        step = (repo / '.github/workflows/build-kpm.yml').read_text().split('      - name: Prepare release assets\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=self.root,
                              capture_output=True, text=True)

    def test_release_contains_six_normal_products_and_three_layouts(self):
        result = self.release()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.root / 'release'
        self.assertEqual(len(list(release.glob('*.kpm'))), 6)
        self.assertEqual(len(list(release.glob('*.kpm.json'))), 3)
        self.assertFalse(list(release.glob('*_debug.kpm')))
        for path in release.glob('*.kpm*'):
            self.assertEqual(path.read_bytes(), (self.root / 'target' / path.name).read_bytes())

    def test_release_requires_run_cmd_dynamic(self):
        result = self.release(lambda p: (p / 'run_cmd_demo_1.0.kpm').unlink())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'release/BUILD_MANIFEST.json').exists())

    def test_release_requires_run_cmd_static_layout(self):
        result = self.release(lambda p: (p / 'run_cmd_demo_1.0_baselines.kpm.json').unlink())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'release/BUILD_MANIFEST.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
