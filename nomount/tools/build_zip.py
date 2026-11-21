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
import tempfile


MODULE_PACKAGE_FILES = (
    'module.prop', 'customize.sh', 'post-fs-data.sh', 'boot-completed.sh',
    'uninstall.sh', 'metamount.sh', 'common.sh', 'README.md', 'NOTICE.md',
)
COMPILER_LICENSE_FILES = {
    'zig': ('licenses/musl-COPYRIGHT', 'licenses/zig-LICENSE'),
    'ndk': ('licenses/NDK-NOTICE', 'licenses/NDK-NOTICE.toolchain'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(cwd, *args):
    return subprocess.check_output(['git', *args], cwd=cwd)


def tree_files(repo, commit, *paths):
    rows = git(repo, 'ls-tree', '-r', '--name-only', '-z', commit, '--', *paths)
    return [p.decode() for p in rows.split(b'\0') if p]


def module_inputs(repo, commit):
    """只读取声明的模块文件及构建输入；工程文档不随目录隐式进入 ZIP。"""
    paths = [*('nomount/module/' + name for name in MODULE_PACKAGE_FILES),
             'nomount/module/CHANGELOG.md', 'nomount/tools/build_zip.py',
             'nomount/tools/build_nm.sh', 'nomount/tools/cli-module.patch',
             'nomount/tools/webui-module-list.patch']
    inputs, contents = {}, {}
    for path in tree_files(repo, commit, *paths):
        data = git(repo, 'show', commit + ':' + path)
        inputs[path] = sha(data)
        name = path.removeprefix('nomount/module/')
        if name in MODULE_PACKAGE_FILES:
            contents[name] = data
        elif path == 'nomount/tools/cli-module.patch':
            contents['sources/cli-module.patch'] = data
        elif path == 'nomount/tools/build_nm.sh':
            contents['sources/build-nm.sh'] = data
    return inputs, contents


def package_entries(upstream_paths, compiler):
    """按冻结上游文件展开 webroot/sources 白名单，与输出 contents 独立。"""
    expected = set(MODULE_PACKAGE_FILES) | {
        'metainstall.sh', 'LICENSE', 'sources/build-nm.sh',
        'sources/cli-module.patch', 'bin/nm',
    } | set(COMPILER_LICENSE_FILES[compiler])
    for path in upstream_paths:
        if path.startswith('module/webroot/'):
            expected.add(path.removeprefix('module/'))
        elif path.startswith('userspace/src/'):
            expected.add('sources/' + Path(path).name)
    return expected


def check_package_entries(names, expected):
    """多出、缺失或重复任一条目均拒绝。"""
    actual = set(names)
    assert len(names) == len(actual), 'ZIP duplicate entries'
    assert actual == expected, ('ZIP entry whitelist mismatch: '
                                f'extra={sorted(actual - expected)}, '
                                f'missing={sorted(expected - actual)}')


def check_cli(data):
    assert data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HH', data, 16) == (2, 183), 'nm must be ARM64 EXEC'
    entry = struct.unpack_from('<Q', data, 24)[0]
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, count = struct.unpack_from('<HH', data, 54)
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(count)]
    assert all(p[0] not in (2, 3) for p in segments), 'nm must have no dynamic loader'
    assert any(p[0] == 1 and p[1] & 1 and p[3] <= entry < p[3] + p[6] for p in segments)


def adapt_webui(js, patch=None):
    """适配生成副本的连接状态、列表契约与操作失败。"""
    js = apply_source_patch(js, 'index.js', 'webui-module-list.patch', patch)
    before = 'if [ "$driver_status" -eq 0 ]; then lsmod | grep -q nomount && echo lkm || echo built-in; fi'
    assert js.count(before) == 1
    js = js.replace(before, 'MODDIR=${MOD_DIR}/nomount; . "$MODDIR/common.sh"; '
                    'if nm_check_api; then echo api; else echo incompatible; fi')
    before = "el.modeBadge.textContent = data.nmMode === 'lkm' ? translate('mode_lkm') : data.nmMode === 'built-in' ? translate('mode_builtin') : '';"
    assert js.count(before) == 1
    js = js.replace(before, "el.modeBadge.textContent = data.nmMode === 'api' ? translate('mode_connected') : '';")
    before = "active: dVer !== unk,"
    assert js.count(before) == 1
    js = js.replace(before, "active: nmMode === 'api',", 1)
    before = "translate('mode_connected') : '';"
    assert js.count(before) == 1
    js = js.replace(before, "translate('mode_connected') : data.nmMode === 'incompatible' ? translate('mode_incompatible') : '';", 1)
    face = "'(._.)'"
    assert js.count(face) == 4
    js = js.replace(face, "'_(._.)_'")
    # Upstream shellQuote covers paths and module filters; retain errno checking.
    for action in ('load', 'unload'):
        before = 'const { stderr } = await exec(`${NM_BIN} module ' + action + ' ${shellQuote(modPath)}`);'
        assert js.count(before) == 1
        js = js.replace(before, 'const { errno, stderr } = await exec(`${NM_BIN} module ' + action + ' ${shellQuote(modPath)}`);\n    if (errno) throw new Error(stderr || "Module operation failed");', 1)
    return js


def apply_source_patch(body, name, patch_name, patch):
    """Apply a local adaptation to a copy of a frozen upstream source file."""
    if patch is None:
        patch = Path(__file__).with_name(patch_name).read_text()
    with tempfile.TemporaryDirectory(prefix='nomount-source-') as directory:
        path = Path(directory) / name
        path.write_text(body)
        result = subprocess.run(['patch', '--batch', '-p1'], cwd=directory, input=patch,
                                text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return path.read_text()


def adapt_cli_header(body, patch=None):
    return apply_source_patch(body, 'nm.h', 'cli-module.patch', patch)


def adapt_cli(body):
    """生成副本：已知 v22/v23 ABI 探测；默认规则允许独立的 UID 排除范围。"""
    # KPM packaging owns its startup flow and does not use the LKM lock helper.
    lock = """    if (argc == 2 && !strcmp(argv[1], "--try-lock")) {
        if (!flock(STDIN_FILENO, LOCK_EX | LOCK_NB)) return 0;
        return errno == EWOULDBLOCK ? 1 : 2;
    }

"""
    assert body.count(lock) == 1
    body = body.replace(lock, '').replace('#include <sys/file.h>\n', '')
    usage = 'List modules with their injected file count'
    assert body.count(usage) == 1
    body = body.replace(usage, 'List modules, rules and links')
    before = 'if (args.deny_start < args.target_uid || args.deny_end > args.target_uid_end) {'
    assert body.count(before) == 1
    body = body.replace(before, 'if ((args.target_uid || args.target_uid_end) && '
                        '(args.deny_start < args.target_uid || args.deny_end > args.target_uid_end)) {', 1)
    dispatch = """    if (args.action == ACTION_MODULE_LIST) return cmd_module_list(&workspace, &args);
    if (args.action == ACTION_MODULE_LOAD || args.action == ACTION_MODULE_UNLOAD)
        return cmd_module_load_or_unload(&workspace, &args, args.action == ACTION_MODULE_LOAD);

"""
    assert body.count(dispatch) == 1
    body = body.replace(dispatch, '', 1)
    before = '    switch (args.action) {'
    assert body.count(before) == 1
    probe = '''    /* KPM companion: verify wire ABI before any non-version operation. */
    if (args.action != ACTION_NONE && args.action != ACTION_VERSION) {
        payload->cmd = NM_CMD_GET_VERSION;
        payload->arg1 = payload->data_size = 0;
        if (nm_send_payload(payload) != 0 || payload->data_size < 2
            || payload->data_size > sizeof(payload->buffer)
            || payload->buffer[0] != '2'
            || (payload->buffer[1] != '2' && payload->buffer[1] != '3')
            || (payload->data_size > 2 && payload->buffer[2] != ' ')) {
            print_literal("nm: incompatible driver protocol; v22 or v23 required\\n");
            goto do_exit;
        }
        payload->cmd = payload->target_uid = payload->arg1 = payload->data_size = 0;
    }

'''
    return body.replace(before, probe + dispatch + before, 1)


def zip_changelog(data, version):
    """核对仓库 module/CHANGELOG.md 首条版本，并提取当前版本段落。

    ZIP 与 KPM 独立更新：只要求 CHANGELOG 首个二级标题等于 module.prop 的版本，
    与 KPM 的发布版本无关。
    """
    text = data.decode() if isinstance(data, (bytes, bytearray)) else str(data)
    lines = text.splitlines()
    heading = '## v' + version
    first = next((index for index, line in enumerate(lines) if line.startswith('## ')), None)
    if first is None or lines[first].strip() != heading:
        raise AssertionError('CHANGELOG release version mismatch')
    section = [lines[first]]
    for follow in lines[first + 1:]:
        if follow.startswith('## '):
            break
        section.append(follow)
    return ('\n'.join(section).strip() + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    compiler = parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('--zig', type=Path, help='Zig executable (static musl)')
    compiler.add_argument('--ndk', type=Path, help='Existing Android NDK build entry point')
    parser.add_argument('--host-tag', default='darwin-x86_64')
    parser.add_argument('--toolchain')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    upstream = root / 'nomount/upstream/nomount'
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    if git(root, 'status', '--porcelain'):
        parser.error('候选必须从干净冻结提交构建。')
    row = git(root, 'ls-tree', commit, 'nomount/upstream/nomount').decode().split()
    assert row[:2] == ['160000', 'commit']
    upstream_commit = row[2]
    assert git(upstream, 'rev-parse', 'HEAD').decode().strip() == upstream_commit
    assert not git(upstream, 'status', '--porcelain')
    inputs, contents = module_inputs(root, commit)
    upstream_paths = tree_files(upstream, upstream_commit, 'module/webroot', 'module/metainstall.sh', 'userspace/src', 'LICENSE')
    expected_entries = package_entries(upstream_paths, 'zig' if args.zig else 'ndk')
    sources = {}
    for path in upstream_paths:
        data = git(upstream, 'show', upstream_commit + ':' + path)
        inputs['nomount/upstream/nomount/' + path] = sha(data)
        if path.startswith('module/'):
            contents[path.removeprefix('module/')] = data
        elif path.startswith('userspace/src/'):
            sources[Path(path).name] = data
        elif path == 'LICENSE':
            contents['LICENSE'] = data

    sources['nm.c'] = adapt_cli(sources['nm.c'].decode()).encode()
    sources['nm.h'] = adapt_cli_header(sources['nm.h'].decode(), contents['sources/cli-module.patch'].decode()).encode()

    # 对输出副本适配状态展示，冻结上游保持原字节。
    webui_patch = git(root, 'show', commit + ':nomount/tools/webui-module-list.patch').decode()
    js = adapt_webui(contents['webroot/index.js'].decode(), webui_patch)
    contents['webroot/index.js'] = ('// SPDX-License-Identifier: GPL-3.0-only\n'
                                  '// NoMount by maxsteeel; KPM connection, module listing and operation status adapted by Codex, 2026-11-19.\n' + js).encode()
    for name in list(contents):
        if name.startswith('webroot/locales/') and name.endswith('.json'):
            locale = json.loads(contents[name])
            locale['mode_connected'] = '已连接' if name.endswith('/zh.json') else 'Connected'
            locale['mode_incompatible'] = '接口不可用（支持 v22/v23）' if name.endswith('/zh.json') else 'API unavailable (v22/v23 supported)'
            contents[name] = (json.dumps(locale, ensure_ascii=False, indent=2) + '\n').encode()

    if args.zig:
        zig = args.zig.resolve()
        zig_version = subprocess.check_output([str(zig), 'version'], text=True).strip()
        args.toolchain = args.toolchain or 'zig' + zig_version
        def capture_tools():
            digest = hashlib.sha256()
            library = zig.parent / 'lib'
            for path in sorted(p for p in library.rglob('*') if p.is_file()):
                digest.update(str(path.relative_to(library)).encode() + b'\0')
                digest.update(bytes.fromhex(sha(path.read_bytes())))
            return {'zig': sha(zig.read_bytes()), 'zig_lib': digest.hexdigest(),
                    'license': sha((zig.parent / 'LICENSE').read_bytes())}
        contents['licenses/musl-COPYRIGHT'] = (zig.parent / 'lib/libc/musl/COPYRIGHT').read_bytes()
        contents['licenses/zig-LICENSE'] = (zig.parent / 'LICENSE').read_bytes()
    else:
        args.toolchain = args.toolchain or 'ndk26.3.11579264'
        tool_bin = args.ndk.resolve() / 'toolchains/llvm/prebuilt' / args.host_tag / 'bin'
        def capture_tools():
            result = {name: sha((tool_bin / name).read_bytes()) for name in ('clang', 'ld.lld')}
            sysroot = tool_bin.parent / 'sysroot/usr/lib/aarch64-linux-android'
            for path in sorted([*sysroot.glob('*.a'), *(sysroot / '21').glob('*.o'),
                                *(tool_bin.parent / 'lib/clang').glob('*/lib/linux/libclang_rt.builtins-aarch64-android.a')]):
                result[str(path.relative_to(tool_bin.parent))] = sha(path.read_bytes())
            for name in ('NOTICE', 'NOTICE.toolchain'):
                result[name] = sha((args.ndk / name).read_bytes())
            return result
        for name in ('NOTICE', 'NOTICE.toolchain'):
            contents['licenses/NDK-' + name] = (args.ndk / name).read_bytes()
    tool_hashes = capture_tools()
    fingerprint = sha(json.dumps({'inputs': inputs, 'tool_hashes': tool_hashes, 'host_tag': args.host_tag}, sort_keys=True).encode())
    version = re.search(r'(?m)^version=v([^\n]+)', contents['module.prop'].decode()).group(1)
    zip_changelog(git(root, 'show', commit + ':nomount/module/CHANGELOG.md'), version)
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
    build_env = dict(os.environ)
    if args.zig:
        build_env.update(ZIG=str(zig))
    else:
        build_env.update(ANDROID_NDK=str(args.ndk.resolve()), NDK_HOST_TAG=args.host_tag)
    built = subprocess.run(command, cwd=work, env=build_env, text=True, capture_output=True)
    (work / 'compile.log').write_text(built.stdout + built.stderr)
    built.check_returncode()
    contents['bin/nm'] = (work / 'nm').read_bytes()
    check_cli(contents['bin/nm'])
    check_package_entries(list(contents), expected_entries)
    assert not git(root, 'status', '--porcelain')
    assert git(root, 'rev-parse', 'HEAD').decode().strip() == commit
    assert git(upstream, 'rev-parse', 'HEAD').decode().strip() == upstream_commit
    assert not git(upstream, 'status', '--porcelain')
    assert capture_tools() == tool_hashes
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
        check_package_entries(archive.namelist(), expected_entries)
        assert all(archive.read(name) == data for name, data in contents.items())
    manifest = {'module': 'nomount', 'kind': 'companion-zip', 'version': version, 'source_commit': commit,
                'build_id': build_id, 'instance_id': build_id + '#' + str(instance),
                'upstream_commit': upstream_commit, 'source_dirty': False, 'input_unchanged': True,
                'source_fingerprint_sha256': fingerprint, 'inputs': inputs,
                'package_entries': sorted(expected_entries),
                'recipe': {'toolchain': args.toolchain, 'tools_sha256': tool_hashes, 'host_tag': args.host_tag,
                           'command': command, 'script_sha256': sha(contents['sources/build-nm.sh'])},
                'protocol': {'transport': 'keyring', 'payload_size': 4096, 'supported_versions': [22, 23], 'read_probes': ['version', 'uid block_isolated']},
                'entries': {name: sha(data) for name, data in sorted(contents.items())},
                'artifacts': [{'name': package.name, 'path': str(package.relative_to(root)), 'sha256': sha(package.read_bytes()), 'size': package.stat().st_size}],
                'scope': 'Developer reproducible ZIP; device installation and boot not tested'}
    (output / 'MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'instance_id': manifest['instance_id'], 'source_commit': commit, 'artifact': manifest['artifacts'][0]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
