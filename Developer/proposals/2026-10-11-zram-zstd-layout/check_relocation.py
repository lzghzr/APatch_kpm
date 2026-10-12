#!/usr/bin/env python3
"""在临时 Git 仓库验证子模块迁移后的冻结读取；不改现有 Oracle。"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True,
                                   stderr=subprocess.PIPE).strip()


def commit(root, message):
    git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)
    return git(root, 'rev-parse', 'HEAD')


def main():
    spec = importlib.util.spec_from_file_location('identity_relocation', sys.argv[1])
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    with tempfile.TemporaryDirectory(prefix='zstd-relocation-') as scratch:
        root = Path(scratch)
        git(root, 'init', '-q')
        child = root / 'mod/upstream/zstd'
        child.mkdir(parents=True)
        git(child, 'init', '-q')
        (child / 'codec.c').write_bytes(b'frozen codec\n')
        git(child, 'add', 'codec.c')
        frozen_child = commit(child, 'codec baseline')
        (root / '.gitmodules').write_text(
            '[submodule "mod/upstream/zstd"]\n'
            '\tpath = mod/upstream/zstd\n\turl = https://example.invalid/zstd.git\n')
        git(root, 'add', '.gitmodules', 'mod/upstream/zstd')
        frozen_parent = commit(root, 'parent baseline')
        git(root, 'submodule', 'absorbgitdirs', 'mod/upstream/zstd')
        git(root, 'mv', 'mod/upstream/zstd', 'mod/zstd')
        current = root / 'mod/zstd'
        (current / 'codec.c').write_bytes(b'new codec\n')
        git(current, 'add', 'codec.c')
        commit(current, 'codec update')
        git(root, 'add', '.gitmodules', 'mod/zstd')
        current_parent = commit(root, 'parent relocation')
        (current / 'codec.c').write_bytes(b'dirty worktree\n')
        identity.REPO = root
        old = 'mod/upstream/zstd/codec.c'
        new = 'mod/zstd/codec.c'
        cases = {
            'frozen old path': identity.git_blob_at(frozen_parent, old) == b'frozen codec\n',
            'frozen old path with filters': identity.git_blob_at(frozen_parent, old, filters=True) == b'frozen codec\n',
            'new path uses frozen commit': identity.git_blob_at(current_parent, new) == b'new codec\n',
            'missing old blob is rejected': identity.git_blob_at(frozen_parent, 'mod/upstream/zstd/absent.c') is None,
            'wrong parent commit is rejected': identity.git_blob_at('0' * 40, old) is None,
            'stable child object retained': git(current, 'cat-file', '-t', frozen_child) == 'commit',
        }
        for name, passed in cases.items():
            print(('PASS' if passed else 'FAIL') + ': ' + name)
        if not all(cases.values()):
            raise SystemExit(1)


if __name__ == '__main__':
    main()
