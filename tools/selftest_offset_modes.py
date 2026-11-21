#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""用独立 ELF 夹具核验偏移模式、配套布局和 CI 产物筛选。"""

import hashlib
import json
import shutil
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
    generic = module in ('run_cmd_demo', 'cgroupv2_freeze')
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
    def _fake_gate_root(self):
        """把 artifact_gate 复制到临时根下，并给它真实的父仓与子模块。

        以前这里是 `<root>/tools -> <outer>/tools` 软链，于是 artifact_gate 的
        `__file__.resolve()` 穿回外层仓库、靠外层 KernelPatch 才通过——那正是
        AUD-030 指出的"靠 bug 通过"。改为自建最小仓库，夹具自洽。
        """
        gate = self.root / 'tools'
        gate.mkdir(exist_ok=True)
        shutil.copy2(Path(__file__).resolve().parents[1] / 'tools' / 'artifact_gate.py', gate / 'artifact_gate.py')
        for name in ('', 'KernelPatch'):
            repo = self.root / name if name else self.root
            repo.mkdir(exist_ok=True)
            subprocess.run(['git', '-C', str(repo), 'init', '-q'], check=True)
            (repo / 'marker').write_text('x\n')
            for cmd in (['add', '-A'], ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'init']):
                subprocess.run(['git', '-C', str(repo)] + cmd, check=True)
        return gate
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

    def release(self, mutation=None, *, include_cgroup=False):
        target = self.root / 'target'
        target.mkdir()
        repo = Path(__file__).resolve().parents[1]
        self._fake_gate_root()
        for module in MODULES:
            for mode in ('static', 'dynamic'):
                for debug in (False, True):
                    write_product(target, module, mode, debug)
        modules = list(MODULES)
        if include_cgroup:
            modules.append('cgroupv2_freeze')
            for mode in ('static', 'dynamic'):
                write_product(target, 'cgroupv2_freeze', mode)
        (target / 'modules.txt').write_text('\n'.join(modules) + '\n')
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

    def test_release_collects_cgroup_pair_and_layout(self):
        result = self.release(include_cgroup=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        prefix = 'cgroupv2_freeze_1.0'
        self.assertEqual({p.name for p in (self.root / 'release').glob(prefix + '*')},
                         {prefix + ext for ext in ('.kpm', '_baselines.kpm', '_baselines.kpm.json')})

    def build_step(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/build-kpm.yml'
        step = workflow.read_text().split('      - name: Build kpm\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=self.root,
                              capture_output=True, text=True)

    def test_push_collects_all_cgroup_products(self):
        module = self.root / 'cgroupv2_freeze'
        module.mkdir()
        base = 'cgroupv2_freeze_1.0'
        dynamic, static = base + '.kpm', base + '_baselines.kpm'
        # 故意让夹具的默认目标只生成动态版，验证 CI 调用 ci 而不依赖默认目标。
        (module / 'Makefile').write_text(f'base:\n\ttouch {dynamic}\n'
                                         f'all: base\n\ttouch {static} {static}.json\n'
                                         'ci: all\n')
        result = self.build_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.root / 'target'
        self.assertEqual((target / 'modules.txt').read_text(), 'cgroupv2_freeze\n')
        self.assertEqual({p.name for p in target.iterdir()}, {dynamic, static, static + '.json', 'modules.txt'})

    def test_build_uses_each_modules_ci_target(self):
        for name, ci_goal in (('ordinary', 'all'), ('with_debug', 'all debug'), ('archived', 'forbidden')):
            module = self.root / name
            module.mkdir()
            (module / 'Makefile').write_text(f'all:\n\ttouch {name}.kpm\n'
                                             f'debug:\n\ttouch {name}_debug.kpm\n'
                                             f'ci: {ci_goal}\n'
                                             'forbidden:\n\tfalse\n')
        (self.root / 'archived/archive').touch()
        result = self.build_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        target = self.root / 'target'
        self.assertEqual(set((target / 'modules.txt').read_text().splitlines()), {'ordinary', 'with_debug'})
        self.assertEqual({p.name for p in target.glob('*.kpm')},
                         {'ordinary.kpm', 'with_debug.kpm', 'with_debug_debug.kpm'})

    def test_build_rejects_empty_module_output(self):
        module = self.root / 'empty'
        module.mkdir()
        (module / 'Makefile').write_text('ci:\n\t@:\n')
        result = self.build_step()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list((self.root / 'target').glob('*.kpm')))

    def test_dual_mode_ci_rejects_missing_artifacts(self):
        repo = Path(__file__).resolve().parents[1]
        shutil.copy2(repo / 'kpm_toolchain.mk', self.root)
        for name in (*MODULES, 'cgroupv2_freeze', 'nomount', 'zram_zstd'):
            with self.subTest(module=name):
                module = self.root / name
                module.mkdir()
                shutil.copy2(repo / name / 'Makefile', module)
                out, layout = module / 'out', module / 'layouts'
                out.mkdir()
                layout.mkdir()
                prefix = ('NoMount' if name == 'nomount' else name) + '_1.0'
                dynamic = out / (prefix + '.kpm')
                static = out / (prefix + '_baselines.kpm')
                sidecar = layout / (static.name + '.json')
                # 原样执行模块的 ci 配方；把前置构建视为已成功，注入不完整产物集。
                args = ['make', '-C', str(module), '-o', 'all', '-o', 'debug', 'ci',
                        'TOOLCHAIN=gcc', 'TARGET_COMPILE=fixture-', 'CC=false', 'MYKPM_VERSION=1.0',
                        f'OUT_DIR={out}', f'LAYOUT_DIR={layout}']
                for files, reason in (((dynamic,), '仅动态版'),
                                      ((dynamic, static), '缺少布局'),
                                      ((static, sidecar), '缺少动态版'),
                                      ((dynamic, static, sidecar), '产物齐全')):
                    with self.subTest(artifacts=reason):
                        for artifact in files:
                            artifact.touch()
                        result = subprocess.run(args, capture_output=True, text=True)
                        self.assertEqual(result.returncode == 0, len(files) == 3,
                                         result.stdout + result.stderr)
                        for artifact in files:
                            artifact.unlink()

    def test_release_rejects_cgroup_dynamic_only(self):
        def remove_static(target):
            for path in target.glob('cgroupv2_freeze_*_baselines.kpm*'):
                path.unlink()
        result = self.release(remove_static, include_cgroup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'release/BUILD_MANIFEST.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
