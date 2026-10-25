#!/usr/bin/env python3
"""v22 安装/启动与标记文件自检；旧脚本断言不改，仅迁移模拟驱动协议输入。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from build_zip import adapt_webui
from test_webui_counts import NODE_TEST


EXTRA = '''    for version in ('21', '23', '22bad', '2.1.1-20261020'):
        work, mod, data, log, env = fixture('protocol-' + version)
        cli = mod / 'bin/nm'
        cli.write_text(cli.read_text().replace("print('22');sys.exit(0)", "print('" + version + "');sys.exit(0)"))
        run(mod, 'customize.sh', env, 1)
        assert calls(log) == [['version']]
        assert not (work / 'data/adb/ap/bin/nm').exists()
        cases.append('v22 installer rejects protocol ' + version)
    work, mod, data, log, env = fixture('v22-markers')
    files(work, data)
    base = work / 'data/adb/modules/example/system'
    (base / 'app/app name.apk').write_text('apk')
    for name, marker in [('empty', '.replace'), ('deleted', '.remove')]:
        (base / name).mkdir()
        (base / name / marker).touch()
    run(mod, 'metamount.sh', env)
    commands = calls(log)
    opaque = next(i for i,a in enumerate(commands) if a[:3] == ['rule','add','--opaque'])
    pairs = next(i for i,a in enumerate(commands) if a[:2] == ['rule','add'] and '--whiteout' not in a and '--opaque' not in a)
    assert opaque < pairs
    assert commands[opaque][3:] == ['/system/app', str(base / 'app')]
    whites = [arg for a in commands if a[:3] == ['rule','add','--whiteout'] for arg in a[3:]]
    assert '/system/empty' in whites and '/system/deleted' in whites and '/system/app' not in whites
    assert any('/system/app/app name.apk' in a for a in commands)
    assert all(not arg.endswith(('.replace','.remove')) for a in commands for arg in a)
    cases.append('nonempty replace -> opaque; empty replace/remove -> whiteout; marker files excluded; NUL-safe order')
    work, mod, data, log, env = fixture('opaque-rollback')
    files(work, data)
    (work / 'data/adb/modules/example/system/app/app.apk').write_text('apk')
    cli = mod / 'bin/nm'
    needle = "if a[:2]==['rule','add'] and mode=='add_error':sys.exit(1)"
    assert cli.read_text().count(needle) == 1
    cli.write_text(cli.read_text().replace(needle, "if a[:3]==['rule','add','--opaque']:sys.exit(1)\\n" + needle))
    run(mod, 'metamount.sh', env, 1)
    commands = calls(log)
    assert any(a[:3] == ['rule','add','--opaque'] for a in commands)
    assert commands[-1] == ['rule','clear'] and not (data / '.booting').exists()
    assert not any(a[:2] == ['rule','add'] and '--opaque' not in a and '--whiteout' not in a for a in commands)
    cases.append('opaque publication failure clears batch and stops before ordinary files')
    work, mod, data, log, env = fixture('trailing-module-dir')
    files(work, data)
    env['MODULE_DIR'] = str(work / 'data/adb/modules') + '/'
    run(mod, 'metamount.sh', env)
    sources = [arg for a in calls(log) if a[:2] == ['rule','add'] for arg in a if arg.startswith(str(work / 'data/adb/modules'))]
    assert sources and all('//' not in arg for arg in sources)
    cases.append('trailing MODULE_DIR slash keeps rule paths normalized')

'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    original_path = root/'nomount/tools/test_zip_module.py'
    original = original_path.read_text()
    needle = "print('0.1.0');sys.exit(0)"
    assert original.count(needle) == 1
    source = original.replace(needle, "print('22');sys.exit(0)", 1)
    assert re.findall(r'\bassert[^\n]+',source) == re.findall(r'\bassert[^\n]+',original)
    marker = "    for p in (root / 'nomount/module').glob('*.sh'):"
    assert source.count(marker) == 1
    source = source.replace(marker, EXTRA+marker, 1)
    args.output.mkdir(parents=True, exist_ok=False)
    generated = args.output/'generated-test.py'
    generated.write_text(source)
    code = "import sys;a=sys.argv[1:];sys.argv=['test_zip_module.py','--output',a[0]];exec(compile(open(a[1]).read(),a[2],'exec'),{'__name__':'__main__','__file__':a[2]})"
    run = subprocess.run([sys.executable,'-B','-c',code,str(args.output/'cases'),str(generated),str(original_path)],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr)
    run.check_returncode()
    receipt = json.loads((args.output/'cases/receipt.json').read_text())
    receipt['scope'] = 'Developer relocated shell fixtures; original assertions retained, fake driver response migrated to protocol 22; not device boot proof'
    receipt['fixture_migration'] = {'old':'0.1.0','new':'22','reason':'v22 ABI now requires explicit protocol identity before installation/injection'}
    upstream = (root/'nomount/upstream/nomount/module/webroot/index.js').read_text()
    original_js, revised_js, runner = [args.output/name for name in ('original.js','revised.js','counts.cjs')]
    original_js.write_text(upstream)
    revised_js.write_text(adapt_webui(upstream))
    runner.write_text(NODE_TEST)
    subprocess.run(['node','--check',str(revised_js)],check=True)
    node = subprocess.run(['node',str(runner),str(original_js),str(revised_js)],capture_output=True,text=True)
    (args.output/'node.log').write_text(node.stdout+node.stderr)
    node.check_returncode()
    receipt['webui_node'] = json.loads(node.stdout)
    (args.output/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
