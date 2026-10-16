#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""从冻结Git输入编译原版nm并打包NoMount KPM配套元模块。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(cwd, *args):
    return subprocess.check_output(['git', *args], cwd=cwd)


def tree_files(repo, commit, *paths):
    rows = git(repo, 'ls-tree', '-r', '--name-only', '-z', commit, '--', *paths)
    return [p.decode() for p in rows.split(b'\0') if p]


def check_cli(data):
    assert data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HH', data, 16) == (2, 183), 'nm must be ARM64 EXEC'
    entry = struct.unpack_from('<Q', data, 24)[0]
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, count = struct.unpack_from('<HH', data, 54)
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(count)]
    assert all(p[0] not in (2, 3) for p in segments), 'nm must have no dynamic loader'
    assert any(p[0] == 1 and p[1] & 1 and p[3] <= entry < p[3] + p[6] for p in segments)


def adapt_webui(js):
    """适配生成副本的连接状态、彩蛋与规则路径解析。"""
    before = 'if ${NM_BIN} version > /dev/null 2>&1; then lsmod | grep -q nomount && echo lkm || echo built-in; fi'
    assert js.count(before) == 1
    js = js.replace(before, 'if ${NM_BIN} version > /dev/null 2>&1; then echo api; fi')
    before = "el.modeBadge.textContent = data.nmMode === 'lkm' ? translate('mode_lkm') : data.nmMode === 'built-in' ? translate('mode_builtin') : '';"
    assert js.count(before) == 1
    js = js.replace(before, "el.modeBadge.textContent = data.nmMode === 'api' ? translate('mode_connected') : '';")
    face = "'(._.)'"
    assert js.count(face) == 4
    js = js.replace(face, "'_(._.)_'")
    helper = r"""function parseRuleList(text) {
    const rules = JSON.parse(text);
    for (const rule of rules) {
        if (typeof rule?.real === 'string')
            rule.real = rule.real.replace(/\/+/g, '/');
    }
    return rules;
}

"""
    assert js.count('// Home\n') == 1
    js = js.replace('// Home\n', helper + '// Home\n', 1)
    replacements = {
        'const rules = JSON.parse(parts[6]);': 'const rules = parseRuleList(parts[6]);',
        'const activeRules = JSON.parse(jsonPart?.trim() || "[]");': 'const activeRules = parseRuleList(jsonPart?.trim() || "[]");',
        'const activeRules = JSON.parse(stdout.trim() || "[]");': 'const activeRules = parseRuleList(stdout.trim() || "[]");',
    }
    for before, after in replacements.items():
        assert js.count(before) == 1, before
        js = js.replace(before, after, 1)
    return js


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--host-tag', default='darwin-x86_64')
    parser.add_argument('--toolchain', default='ndk26.3.11579264')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    upstream = root / 'nomount/nomount'
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    if git(root, 'status', '--porcelain'):
        parser.error('候选必须从干净冻结提交构建。')
    row = git(root, 'ls-tree', commit, 'nomount/nomount').decode().split()
    assert row[:2] == ['160000', 'commit']
    upstream_commit = row[2]
    assert git(upstream, 'rev-parse', 'HEAD').decode().strip() == upstream_commit
    assert not git(upstream, 'status', '--porcelain')
    inputs = {}
    contents = {}
    for path in tree_files(root, commit, 'nomount/module', 'nomount/tools/build_zip.py', 'nomount/tools/build_nm.sh', 'nomount/README.md'):
        data = git(root, 'show', commit + ':' + path)
        inputs[path] = sha(data)
        if path.startswith('nomount/module/'):
            contents[path.removeprefix('nomount/module/')] = data
        elif path == 'nomount/tools/build_nm.sh':
            contents['sources/build-nm.sh'] = data
    upstream_paths = tree_files(upstream, upstream_commit, 'module/webroot', 'module/metainstall.sh', 'module/rule-paths.sh', 'userspace/src', 'LICENSE')
    sources = {}
    for path in upstream_paths:
        data = git(upstream, 'show', upstream_commit + ':' + path)
        inputs['nomount/nomount/' + path] = sha(data)
        if path.startswith('module/'):
            contents[path.removeprefix('module/')] = data
        elif path.startswith('userspace/src/'):
            sources[Path(path).name] = data
        elif path == 'LICENSE':
            contents['LICENSE'] = data

    # 对输出副本适配状态展示，冻结上游保持原字节。
    js = adapt_webui(contents['webroot/index.js'].decode())
    contents['webroot/index.js'] = ('// SPDX-License-Identifier: GPL-3.0-only\n'
                                  '// NoMount by maxsteeel; connection label, empty-state face and rule path display adapted by Codex, 2026-10-14.\n' + js).encode()
    for name in list(contents):
        if name.startswith('webroot/locales/') and name.endswith('.json'):
            locale = json.loads(contents[name])
            locale['mode_connected'] = '已连接' if name.endswith('/zh.json') else 'Connected'
            contents[name] = (json.dumps(locale, ensure_ascii=False, indent=2) + '\n').encode()

    tool_bin = args.ndk.resolve() / 'toolchains/llvm/prebuilt' / args.host_tag / 'bin'
    tool_hashes = {name: sha((tool_bin / name).read_bytes()) for name in ('clang', 'ld.lld')}
    fingerprint = sha(json.dumps({'inputs': inputs, 'tool_hashes': tool_hashes, 'host_tag': args.host_tag}, sort_keys=True).encode())
    version = re.search(r'(?m)^version=v([^\n]+)', contents['module.prop'].decode()).group(1)
    readme = git(root, 'show', commit + ':nomount/README.md').decode()
    history = readme.split('## 更新记录\n', 1)[1].strip()
    assert history.startswith('### ' + version + '\n'), 'README release version mismatch'
    contents['CHANGELOG.md'] = (history.split('\n### ', 1)[0].strip() + '\n').encode()
    build_id = f'nomount-zip-{version}+g{fingerprint[:12]}.{args.toolchain}'
    output_root = root / 'artifacts/companion/nomount'
    output_root.mkdir(parents=True, exist_ok=True)
    instance = 1
    while True:
        output = output_root / (build_id + '#' + str(instance))
        try:
            output.mkdir()
            break
        except FileExistsError:
            instance += 1
    work = output / 'build'
    work.mkdir()
    for name, data in sources.items():
        (work / name).write_bytes(data)
        contents['sources/' + name] = data
    (work / 'build-nm.sh').write_bytes(contents['sources/build-nm.sh'])
    command = ['sh', 'build-nm.sh', 'nm']
    build_env = dict(os.environ, ANDROID_NDK=str(args.ndk.resolve()), NDK_HOST_TAG=args.host_tag)
    built = subprocess.run(command, cwd=work, env=build_env, text=True, capture_output=True)
    (work / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    contents['bin/nm'] = (work / 'nm').read_bytes()
    check_cli(contents['bin/nm'])
    assert not git(root, 'status', '--porcelain')
    assert git(root, 'rev-parse', 'HEAD').decode().strip() == commit
    assert git(upstream, 'rev-parse', 'HEAD').decode().strip() == upstream_commit
    assert not git(upstream, 'status', '--porcelain')
    assert {name: sha((tool_bin / name).read_bytes()) for name in tool_hashes} == tool_hashes
    package = output / f'NoMount-kpm_{version}.zip'
    with zipfile.ZipFile(package, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if name.endswith('.sh') or name == 'bin/nm' else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == set(contents)
        assert all(archive.read(name) == data for name, data in contents.items())
    manifest = {'module': 'nomount', 'kind': 'companion-zip', 'version': version, 'source_commit': commit,
                'build_id': build_id, 'instance_id': build_id + '#' + str(instance),
                'upstream_commit': upstream_commit, 'source_dirty': False, 'input_unchanged': True,
                'source_fingerprint_sha256': fingerprint, 'inputs': inputs,
                'recipe': {'toolchain': args.toolchain, 'tools_sha256': tool_hashes, 'host_tag': args.host_tag,
                           'command': command, 'script_sha256': sha(contents['sources/build-nm.sh'])},
                'protocol': {'transport': 'keyring', 'payload_size': 4096, 'read_probes': ['version', 'uid block_isolated']},
                'entries': {name: sha(data) for name, data in sorted(contents.items())},
                'artifacts': [{'name': package.name, 'path': str(package.relative_to(root)), 'sha256': sha(package.read_bytes()), 'size': package.stat().st_size}],
                'scope': 'Developer reproducible ZIP; device installation and boot not tested'}
    (output / 'MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'instance_id': manifest['instance_id'], 'source_commit': commit, 'artifact': manifest['artifacts'][0]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
