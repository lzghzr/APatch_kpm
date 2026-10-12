#!/usr/bin/env python3
"""补丁副本的冻结 gitlink 读取和 legacy 命名正反自检。"""
import argparse
import importlib.util
from pathlib import Path
import subprocess


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    args.scratch = args.scratch.resolve()
    args.build = args.build.resolve()
    args.scratch.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    identity = load('patched_identity', root / 'tools/identity.py')
    gate = load('patched_gate', root / 'tools/artifact_gate.py')

    def git(repo, *arguments):
        return subprocess.check_output(['git', '-C', str(repo), '-c', 'commit.gpgsign=false',
                                       '-c', 'user.name=Developer selfcheck', '-c', 'user.email=fixture@invalid',
                                       *arguments], text=True).strip()

    upstream = args.scratch / 'upstream'
    upstream.mkdir()
    git(upstream, 'init', '-q')
    (upstream / 'input.c').write_text('frozen source\n')
    git(upstream, 'add', 'input.c')
    git(upstream, 'commit', '-qm', 'fixture: frozen source')
    old = git(upstream, 'rev-parse', 'HEAD')
    parent = args.scratch / 'parent'
    parent.mkdir()
    git(parent, 'init', '-q')
    (parent / 'module').mkdir()
    (parent / 'module/Makefile').write_text('MYKPM_VERSION := 0.2.0\n')
    git(parent, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', str(upstream.resolve()), 'module/vendor/codec')
    git(parent, 'add', 'module/Makefile', '.gitmodules', 'module/vendor/codec')
    git(parent, 'commit', '-qm', 'fixture: pin dependency')
    frozen = git(parent, 'rev-parse', 'HEAD')
    child = parent / 'module/vendor/codec'
    (child / 'input.c').write_text('new source\n')
    git(child, 'add', 'input.c')
    git(child, 'commit', '-qm', 'fixture: newer dependency')
    identity.REPO = parent.resolve()
    files = identity.source_files('module', parent / 'module')
    assert '.gitmodules' in files and 'module/vendor/codec/input.c' in files
    assert identity.git_blob_at(frozen, 'module/vendor/codec/input.c') == b'frozen source\n'
    assert identity.git_blob_at(frozen, 'module/vendor/codec/input.c', filters=True) == b'frozen source\n'
    assert identity.git_blob_at(frozen, 'module/vendor/codec/missing.c') is None
    assert git(child, 'rev-parse', 'HEAD') != old
    assert identity.VARIANT_SUFFIX['legacy_debug'] == '_d'
    artifacts = gate.validate(args.build)
    assert len(artifacts) == 6
    modern = next(p for p in args.build.glob('*.kpm') if p.name.endswith('0.2.0.kpm'))
    wrong = args.scratch / 'zram_zstd_0.2.0_legacy.kpm'
    wrong.write_bytes(modern.read_bytes())
    try:
        gate.inspect_kpm(wrong)
    except ValueError:
        pass
    else:
        raise AssertionError('modern bytes accepted under legacy name')
    print('PASS: frozen gitlink vs newer HEAD, checkout filters, missing file, .gitmodules input, six variants, naming mismatch')


if __name__ == '__main__':
    main()
