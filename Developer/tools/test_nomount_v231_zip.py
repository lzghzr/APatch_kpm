#!/usr/bin/env python3
"""Exercise v2.3.1 path and UID parsing, and full/multi-page module JSON."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess

import test_nomount_module_cli as cli


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    # Model a second page reached only by returning the driver's opaque cursor.
    anchor = '  if(getenv("LIST_ERROR")&&p->arg1==1)return -5;'
    assert cli.POST.count(anchor) == 1
    cli.POST = cli.POST.replace(anchor, anchor + '''
  if(getenv("NEXT_RULE_PAGE") && p->arg1 == 0x12345678U){
    FILE *f = fopen(getenv("NEXT_RULE_PAGE"), "rb"); if (!f) abort();
    p->data_size = fread(p->buffer, 1, sizeof(p->buffer), f); fclose(f);
    p->arg1 = ~0U; return 0;
  }''').replace('  p->arg1=1;p->data_size=0;',
                '  p->arg1=getenv("NEXT_RULE_PAGE")?0x12345678U:1;p->data_size=0;')
    cli.build(out)
    modules = out / 'modules'
    modules.mkdir()
    cases = []

    def run(name, argv, expected=0, **settings):
        capture = out / (name + '.bin')
        env = dict(os.environ, MODULES=str(modules), CAPTURE=str(capture), **settings)
        result = subprocess.run([str(out / 'cli'), *argv], env=env, capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == expected, (name, result.stdout, result.stderr)
        cases.append(name)
        return result.stdout, cli.records(capture)

    _, rows = run('normalized-virtual-literal-backing',
                  ['rule', 'add', '/system/a/../b//c/', '/source/link/../dir/'])
    assert [(r['v'], r['r']) for r in rows] == [('/system/b/c', '/source/link/../dir/')]
    _, rows = run('uint-max', ['rule', 'add', '/system/test', '/source',
                               '--uid', '4294967295'])
    assert [r['uid'] for r in rows] == [4294967295]
    for name, argv in [
        ('overflow', ['--uid', '4294967296']),
        ('malformed-range', ['--uid-range', '12-x']),
        ('missing-exclude', ['--uid-excluded']),
        ('incomplete-pair', ['/system/extra']),
    ]:
        _, rows = run(name, ['rule', 'add', '/system/test', '/source', *argv], expected=1)
        assert not rows

    _, rows = run('overlong-component',
                  ['rule', 'add', '/system/test', '/source/' + 'x' * 256], expected=1)
    assert not rows

    def record(vpath):
        return struct.pack('<IIIIIHH', 4, 0, 0, 0, 0, len(vpath), 0) + vpath

    first = b'/system/' + b'a' * (4068 - 24 - len(b'/system/'))
    first_page, last_page = out / 'full', out / 'next'
    first_page.write_bytes(record(first))
    assert first_page.stat().st_size == 4068
    last_page.write_bytes(record(b'/system/second'))
    for version in ('22', '23'):
        stdout, _ = run('full-then-next-' + version, ['module', 'list', '--json'],
                        VERSION=version, RULE_PAGE=str(first_page),
                        NEXT_RULE_PAGE=str(last_page))
        data = json.loads(stdout)
        assert data['mods'] == []
        assert data['rules'] == [{'virtual': first.decode(), 'real': ''},
                                 {'virtual': '/system/second', 'real': ''}]
    stdout, _ = run('empty-list', ['module', 'list', '--json'])
    assert json.loads(stdout) == {'mods': [], 'rules': []}
    print(f'PASS {len(cases)} v2.3.1 CLI cases')


if __name__ == '__main__':
    main()
