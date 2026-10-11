#!/usr/bin/env python3
"""在维护者补丁副本上验证真实双模式产物与发布范围。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import textwrap


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--proposal-root', type=Path, required=True)
    ap.add_argument('--layouts', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location('proposal_gate', args.proposal_root / 'tools/artifact_gate.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    positive = args.output / 'positive'
    target = positive / 'target'
    target.mkdir(parents=True)
    (positive / 'tools').symlink_to((args.proposal_root / 'tools').resolve(), target_is_directory=True)
    for module in ('re_kernel', 're_kernel_x'):
        for kpm in (root / module).glob('*.kpm'):
            shutil.copy2(kpm, target / kpm.name)
            if '_baselines' in kpm.stem:
                shutil.copy2(args.layouts / (module + '-layout-final') / (kpm.name + '.json'), target / (kpm.name + '.json'))
    modules = ['re_kernel', 're_kernel_x']
    (target / 'modules.txt').write_text('\n'.join(modules) + '\n')
    assert len(gate.validate(target, modules)) == 8
    workflow = (args.proposal_root / '.github/workflows/build-kpm.yml').read_text()
    step = workflow.split('      - name: Prepare release assets\n', 1)[1]
    script = textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])

    def release(path):
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=path,
                              capture_output=True, text=True)

    result = release(positive)
    assert result.returncode == 0, result.stdout + result.stderr
    names = {p.name for p in (positive / 'release').iterdir()}
    expected = {p.name for p in target.iterdir() if p.name.endswith(('.kpm', '.kpm.json')) and '_debug' not in p.name}
    assert names == expected | {'BUILD_MANIFEST.json', 'SHA256SUMS'}
    assert len([n for n in names if n.endswith('.kpm')]) == 4
    assert len([n for n in names if n.endswith('.kpm.json')]) == 2
    for name in expected:
        assert (target / name).read_bytes() == (positive / 'release' / name).read_bytes()
    failures = []
    # 每种模式都有拒绝例：缺失 JSON、动态附带 JSON、元信息/文件名错配。
    for label in ('missing-static-layout', 'dynamic-layout', 'mode-filename'):
        negative = args.output / label
        shutil.copytree(target, negative)
        static = next(negative.glob('re_kernel_*_baselines.kpm'))
        dynamic = next(p for p in negative.glob('re_kernel_[0-9]*.kpm')
                       if '_baselines' not in p.stem and not p.stem.endswith('_debug'))
        if label == 'missing-static-layout':
            Path(str(static) + '.json').unlink()
        elif label == 'dynamic-layout':
            Path(str(dynamic) + '.json').write_text('{}')
        else:
            static.rename(negative / static.name.replace('_baselines', '_debug'))
        try:
            gate.validate(negative, modules)
        except (ValueError, OSError, KeyError):
            failures.append(label)
        else:
            raise AssertionError(label + ' was accepted')
    for label, mutation in [('missing-dynamic', 'remove'), ('missing-rek-dynamic', 'remove-rek'), ('duplicate-static', 'duplicate')]:
        negative = args.output / label
        negative.mkdir()
        shutil.copytree(target, negative / 'target')
        (negative / 'tools').symlink_to((args.proposal_root / 'tools').resolve(), target_is_directory=True)
        if mutation in ('remove', 'remove-rek'):
            module = 're_kernel' if mutation == 'remove-rek' else 're_kernel_x'
            next(p for p in (negative / 'target').glob(module + '_[0-9]*.kpm')
                 if '_baselines' not in p.stem and not p.stem.endswith('_debug')).unlink()
        else:
            static = next((negative / 'target').glob('re_kernel_x_*_baselines.kpm'))
            shutil.copy2(static, negative / 'target/re_kernel_x_duplicate_baselines.kpm')
        result = release(negative)
        assert result.returncode != 0 and not (negative / 'release/BUILD_MANIFEST.json').exists()
        failures.append(label)
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer proposal selfcheck; repository-owned gate unchanged',
        'release_files': sorted(names), 'rejected': failures,
        'proposal_sha256': {str(p.relative_to(args.proposal_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in [args.proposal_root / 'tools/artifact_gate.py',
                                      args.proposal_root / '.github/workflows/build-kpm.yml']}}, indent=2) + '\n')
    print('8 artifacts; 4 regular KPMs + 2 static JSONs in Releases; 6 rejection cases: PASS')


if __name__ == '__main__':
    main()
