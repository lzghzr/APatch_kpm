#!/usr/bin/env python3
"""Six bounded delivery-identity reproductions; keys and Git fixtures stay temporary.

Run from any directory. Only the optional output file persists. Fixture artifacts
are byte placeholders, not KPMs; this checks identity-tool paths, not a whole gate.
The subject's PASS is a branch observation; Git object bytes and actual signature
verification establish the independent counterexample evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
import tempfile


def run(args, data=None, env=None):
    proc = subprocess.run(args, input=data, capture_output=True, env=env)
    proc.check_returncode()
    return proc.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reproduce(repo):
    spec = importlib.util.spec_from_file_location('review_identity', repo / 'tools/identity.py')
    ident = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ident)
    with tempfile.TemporaryDirectory(prefix='delivery-counterexample-') as scratch:
        root = Path(scratch)
        run(['git', 'init', '-q', str(root)])

        def git(*args, data=None, env=None):
            return run(['git', '-C', str(root), *args], data, env).decode().strip()

        for key, value in [('user.name', 'Review Fixture'),
                           ('user.email', 'review@example.invalid'),
                           ('commit.gpgsign', 'false')]:
            git('config', key, value)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / 'key')])
        (root / 'allowed').write_text('review@example.invalid ' + (root / 'key.pub').read_text())
        git('config', 'gpg.format', 'ssh')
        git('config', 'user.signingkey', str(root / 'key'))
        git('config', 'gpg.ssh.allowedSignersFile', str(root / 'allowed'))
        (root / 'mod').mkdir()
        (root / 'tools').mkdir()
        (root / 'mod/Makefile').write_text('MYKPM_VERSION := 1.0\nall:\n\tcc -I.. -c main.c\n')
        (root / 'mod/main.c').write_text('#include "kpm_utils.h"\nint main(void) { return 0; }\n')
        (root / 'kpm_utils.h').write_text('/* common build input */\n')
        for name in ['identity.py', 'build_candidate.py']:
            (root / 'tools' / name).write_bytes((repo / 'tools' / name).read_bytes())
        git('add', 'mod', 'tools', 'kpm_utils.h')
        bare_tree = git('write-tree')
        kp1 = git('commit-tree', bare_tree, '-m', 'KP1')
        kp2 = git('commit-tree', bare_tree, '-m', 'KP2')
        git('update-index', '--add', '--cacheinfo', '160000,' + kp1 + ',KernelPatch')
        tree = git('write-tree')
        source = git('commit-tree', tree, '-m', 'source')
        git('update-ref', 'refs/heads/main', source)

        def signed_commit(tree):
            return git('commit-tree', '-S', tree, '-m', 'signed delivery')

        def changed_tree(remove=(), kp=None):
            index = root / 'case-index'
            index.unlink(missing_ok=True)
            env = dict(os.environ, GIT_INDEX_FILE=str(index))
            git('read-tree', source, env=env)
            for path in remove:
                git('update-index', '--force-remove', path, env=env)
            if kp:
                git('update-index', '--cacheinfo', '160000,' + kp + ',KernelPatch', env=env)
            result = git('write-tree', env=env)
            index.unlink(missing_ok=True)
            return result

        def entry_for(commit, paths):
            files = [{'path': path, 'sha256': digest(run([
                'git', '-C', str(root), 'cat-file', 'blob', commit + ':' + path]))}
                for path in paths]
            source_tree = digest(''.join(
                f"{item['sha256']}  {item['path']}\n"
                for item in sorted(files, key=lambda item: item['path'])).encode())
            flags = digest(b'cc fixed arguments')
            fingerprint = digest('\n'.join([
                'module=mod', 'version=1.0', 'variant=base',
                'source_tree_sha256=' + source_tree, 'toolchain=fixture',
                'kernelpatch_commit=' + kp1, 'flags_sha256=' + flags]).encode())
            return {
                'module': 'mod', 'version': '1.0', 'variant': 'base', 'kind': 'candidate',
                'source_dirty': False, 'source_commit': commit, 'kernelpatch_commit': kp1,
                'build_id': 'fixture-' + source_tree[:12],
                'instance_id': 'fixture-' + source_tree[:12] + '#1', 'toolchain': 'fixture',
                'fingerprint_sha256': fingerprint, 'source_tree_sha256': source_tree,
                'sources': files,
                'recipe': {'captured': True, 'returncode': 0, 'dry_run_sha256': flags,
                           'compiler_sha256': digest(b'fixture compiler')},
                'artifacts': [{'name': 'out.kpm', 'path': 'out.kpm',
                               'sha256': digest(b'fixture bytes')}],
                'build_transaction': {'source_commit': commit,
                    'source_tree_sha256': source_tree, 'kernelpatch_commit': kp1,
                    'recipe_sha256': flags, 'input_unchanged': True, 'returncode': 0}}

        def binding(entry, delivery):
            return {key: entry[key] for key in (
                'instance_id', 'build_id', 'source_commit', 'fingerprint_sha256')} | {
                'delivery_commit': delivery, 'artifacts': {'out.kpm': digest(b'fixture bytes')},
                'signature_verified': True, 'bound_by': 'fixture', 'bound_at': 'fixture'}

        (root / 'out.kpm').write_bytes(b'fixture bytes')
        ident.REPO = root
        paths = ['mod/Makefile', 'mod/main.c', 'kpm_utils.h',
                 'tools/build_candidate.py', 'tools/identity.py']
        entry = entry_for(source, paths)
        cases = []

        def check(label, entry, delivery, bound=None, evidence=None):
            bound = bound or binding(entry, delivery)
            actual_signed = subprocess.run(
                ['git', '-C', str(root), 'verify-commit', delivery], capture_output=True).returncode == 0
            observed = ident.verify_build(entry, profile='delivery', deliveries=[bound])
            cases.append({'case': label, 'signed_independently': actual_signed,
                'source': entry['source_commit'], 'delivery': delivery,
                'source_tree': git('rev-parse', entry['source_commit'] + '^{tree}'),
                'delivery_tree': git('rev-parse', delivery + '^{tree}'),
                'problems': observed['problems'], 'evidence': evidence})

        flat = signed_commit(tree)
        check('equal bytes nonancestor', entry, flat, evidence={'nonancestor': subprocess.run(
            ['git', '-C', str(root), 'merge-base', '--is-ancestor', source, flat]).returncode != 0})
        deleted = signed_commit(changed_tree(remove=['kpm_utils.h']))
        check('recorded shared input deleted', entry, deleted)
        forged = binding(entry, flat)
        forged['source_commit'] = flat
        check('forged source binding', entry, flat, forged)
        changed_kp = signed_commit(changed_tree(kp=kp2))
        check('KernelPatch gitlink changed', entry, changed_kp, evidence={
            'source_gitlink': git('ls-tree', source, 'KernelPatch'),
            'delivery_gitlink': git('ls-tree', changed_kp, 'KernelPatch')})
        missing = signed_commit(changed_tree(remove=['mod/Makefile', 'mod/main.c']))
        missing_entry = entry_for(missing, [path for path in paths if not path.startswith('mod/')])
        missing_flat = signed_commit(git('rev-parse', missing + '^{tree}'))
        check('module missing from both commits with self-consistent forged entry',
              missing_entry, missing_flat, evidence={
                  'source_module_ls_tree': git('ls-tree', missing, 'mod'),
                  'delivery_module_ls_tree': git('ls-tree', missing_flat, 'mod')})
        partial = entry_for(source, [path for path in paths if path != 'kpm_utils.h'])
        check('shared input omitted from sources and deleted in delivery', partial, deleted, evidence={
            'source_blob': git('rev-parse', source + ':kpm_utils.h'),
            'delivery_exists': subprocess.run(['git', '-C', str(root), 'cat-file', '-e',
                deleted + ':kpm_utils.h'], capture_output=True).returncode == 0})
        return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(reproduce(Path(__file__).resolve().parents[3]), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end='')
