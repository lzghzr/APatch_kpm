#!/usr/bin/env python3
"""在临时目录执行ZIP脚本；CLI/root安装器由宿主夹具代替，不操作设备。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    cases = []

    def fixture(name, mode='ready'):
        work = output / name
        mod = work / 'data/adb/modules/nomount'
        mod.mkdir(parents=True)
        for p in (root / 'nomount/module').iterdir():
            if p.suffix == '.sh':
                # 仅将Android固定路径重定位到宿主临时目录，保留脚本控制流。
                text = p.read_text().replace('/data/adb', str(work / 'data/adb'))
                text = text.replace('/proc/sys/kernel/random/boot_id', str(work / 'boot_id'))
                text = text.replace('"/$partition"', '"' + str(work) + '/$partition"')
                text = text.replace('"/system/$partition"', '"' + str(work) + '/system/$partition"')
                (mod / p.name).write_text(text)
        shutil.copyfile(root / 'nomount/nomount/module/rule-paths.sh', mod / 'rule-paths.sh')
        (work / 'boot_id').write_text('boot-one\n')
        (work / 'system').mkdir()
        data = work / 'data/adb/nomount'
        data.mkdir()
        (mod / 'bin').mkdir()
        cli = mod / 'bin/nm'
        cli.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
from pathlib import Path
a=sys.argv[1:]
with open(os.environ['NM_TEST_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
mode=os.environ['NM_TEST_MODE']
if a==['version']:
 if mode=='missing':sys.exit(1)
 print('0.1.0');sys.exit(0)
if a==['uid','block_isolated']:
 if mode=='isolation_error':sys.exit(1)
 print('unexpected' if mode=='malformed' else '0');sys.exit(0)
if a[:2]==['rule','add'] and mode=='add_error':sys.exit(1)
if a==['rule','clear'] and mode=='clear_error':sys.exit(1)
if a[:2]==['uid','add'] and mode=='uid_error':sys.exit(1)
if a[:2]==['rule','list']:print('[]')
''')
        cli.chmod(0o755)
        fake_bin = work / 'commands'
        fake_bin.mkdir()
        for name in ('insmod', 'rmmod', 'modprobe', 'lsmod'):
            p = fake_bin / name
            p.write_text('#!/bin/sh\nprintf "DRIVER_COMMAND\\n" >> "$NM_TEST_LOG"\nexit 99\n')
            p.chmod(0o755)
        log = work / 'calls.jsonl'
        env = dict(os.environ, PATH=str(fake_bin) + ':' + os.environ['PATH'],
                   NM_TEST_LOG=str(log), NM_TEST_MODE=mode, APATCH='true', KSU='false', ARCH='arm64', MODPATH=str(mod))
        return work, mod, data, log, env

    def calls(log):
        rows = log.read_text().splitlines() if log.exists() else []
        assert 'DRIVER_COMMAND' not in rows
        return [json.loads(row) for row in rows]

    def run(mod, name, env, expected=0):
        if name == 'customize.sh':
            command = ['/bin/sh', '-c', 'ui_print(){ printf "%s\\n" "$*"; }; abort(){ ui_print "$*"; exit 1; }; set_perm(){ chmod "$4" "$1"; }; . "$MODPATH/customize.sh"']
        else:
            command = ['/bin/sh', str(mod / name)]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
        return result

    for mode in ('missing', 'isolation_error', 'malformed'):
        work, mod, data, log, env = fixture('install-' + mode, mode)
        result = run(mod, 'customize.sh', env, 1)
        assert '重启' in result.stdout
        assert not (work / 'data/adb/ap/bin/nm').exists()
        assert all(a[0] == 'version' or a == ['uid', 'block_isolated'] for a in calls(log))
        cases.append('install rejects ' + mode)
    work, mod, data, log, env = fixture('install-ready')
    run(mod, 'customize.sh', env)
    assert (work / 'data/adb/ap/bin/nm').is_symlink()
    assert calls(log) == [['version'], ['uid', 'block_isolated']]
    cases.append('old driver version accepted via read-only protocol probes')
    work, mod, data, log, env = fixture('install-ksu')
    stale = work / 'data/adb/ap/bin/apd'
    stale.parent.mkdir(parents=True)
    stale.write_text('#!/bin/sh\n')
    stale.chmod(0o755)
    env.update(APATCH='false', KSU='true')
    run(mod, 'customize.sh', env)
    assert (work / 'data/adb/ksu/bin/nm').is_symlink()
    assert not (work / 'data/adb/ap/bin/nm').exists()
    cases.append('active root flag wins over stale root files')
    work, mod, data, log, env = fixture('install-arch')
    env['ARCH'] = 'arm'
    run(mod, 'customize.sh', env, 1)
    assert calls(log) == []
    cases.append('unsupported architecture rejected before API calls')

    def files(work, data):
        base = work / 'data/adb/modules'
        module = base / 'example/system/etc'
        module.mkdir(parents=True)
        (module / 'source text.txt').write_text('sample')
        replace = base / 'example/system/app'
        replace.mkdir()
        (replace / '.replace').touch()
        for name, flag in [('disabled', 'disable'), ('removed', 'remove'), ('skipped', 'skip_mount')]:
            p = base / name
            (p / 'system').mkdir(parents=True)
            (p / 'system/ignored').touch()
            (p / flag).touch()
        (data / '.exclusion_list.json').write_text('[{"uid": "10001"}, {"uid":"10002"}]')
        (data / '.block_isolated_uids').touch()

    work, mod, data, log, env = fixture('boot-ready')
    files(work, data)
    run(mod, 'metamount.sh', env)
    commands = calls(log)
    first_rule = next(i for i, a in enumerate(commands) if a[:2] == ['rule', 'add'])
    assert commands.index(['uid', 'add', '10001']) < first_rule
    assert commands.index(['uid', 'add', '10002']) < first_rule
    assert commands.index(['uid', 'block_isolated', 'on']) < first_rule
    assert any('/system/etc/source text.txt' in a for a in commands)
    assert any(a[:3] == ['rule', 'add', '--whiteout'] and '/system/app' in a for a in commands)
    assert all('ignored' not in ' '.join(a) for a in commands)
    assert (data / '.booting').read_text() == 'boot-one\n'
    before = len(commands)
    run(mod, 'post-fs-data.sh', env)
    assert calls(log)[before:] == [['version'], ['uid', 'block_isolated']]
    assert (data / '.booting').exists()
    run(mod, 'boot-completed.sh', env)
    assert not (data / '.booting').exists()
    cases.append('metamount-first startup restores UID before NUL-safe rules; completion clears marker')

    for mode in ('missing', 'uid_error', 'add_error'):
        work, mod, data, log, env = fixture('boot-' + mode, mode)
        files(work, data)
        run(mod, 'metamount.sh', env, 1)
        commands = calls(log)
        if mode != 'missing':
            assert commands[-1] == ['rule', 'clear']
        if mode == 'uid_error':
            assert all(a[:2] != ['rule', 'add'] for a in commands)
        assert not (data / '.booting').exists()
        cases.append('startup rejects/rolls back ' + mode)
    for flag in ('data-disable', 'module-disable', 'module-remove', 'previous-boot'):
        work, mod, data, log, env = fixture(flag)
        if flag == 'previous-boot':
            (data / '.booting').write_text('previous-boot\n')
        elif flag == 'data-disable':
            (data / 'disable').touch()
        else:
            (mod / flag.removeprefix('module-')).touch()
        run(mod, 'metamount.sh', env, 1 if flag == 'previous-boot' else 0)
        assert calls(log)[-1] == ['rule', 'clear']
        assert not (data / '.booting').exists()
        if flag == 'previous-boot':
            assert (data / 'disable').exists()
        cases.append('rule injection skipped for ' + flag)
    work, mod, data, log, env = fixture('uninstall')
    link = work / 'data/adb/ap/bin/nm'
    link.parent.mkdir(parents=True)
    link.symlink_to(mod / 'bin/nm')
    other = work / 'data/adb/ksu/bin/nm'
    other.parent.mkdir(parents=True)
    other.symlink_to('/some/other/tool')
    run(mod, 'uninstall.sh', env)
    assert calls(log)[-1] == ['rule', 'clear']
    assert not link.is_symlink() and other.is_symlink()
    assert not data.exists()
    cases.append('uninstall clears rules, removes owned link and preserves other link')
    for p in (root / 'nomount/module').glob('*.sh'):
        subprocess.run(['/bin/sh', '-n', str(p)], check=True)
    source_paths = list((root / 'nomount/module').glob('*')) + [Path(__file__), root / 'nomount/nomount/module/rule-paths.sh']
    receipt = {'scope': 'Developer shell/API stubs, relocated Android paths; not device boot or installer proof',
               'cases': cases, 'sources': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths if p.is_file()},
               'result': 'PASS'}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(str(len(cases)) + ' ZIP installation/boot/error/uninstall cases: PASS')


if __name__ == '__main__':
    main()
