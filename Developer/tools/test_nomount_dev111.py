#!/usr/bin/env python3
"""DEV-111: production module listing feeds the generated WebUI ownership calculation."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess

import test_nomount_module_cli as cli


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cli.build(out)
    modules = out/'modules'

    def file(path, text='fixture'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    white = modules/'whiteout_only'
    mixed = modules/"mixed' module"
    file(white/'module.prop', 'name=纯白化\n')
    file(white/'system/hidden/.remove')
    file(white/'system/hidden/pruned/ignored')
    file(mixed/'module.prop', 'name=混合模块\n')
    file(mixed/'system/mixed/normal')
    file(mixed/'system/mixed/char-whiteout')
    file(mixed/'system/mixed/empty/.replace')
    external = out/'external'
    file(external/'value')
    (mixed/'system/mixed/link').symlink_to(external/'value')
    (mixed/'system/mixed/dirlink').symlink_to(external, target_is_directory=True)
    # A whiteout reached through a directory link has empty backing, not a dir mapping.
    file(out/'masked/.remove')
    file(out/'masked/ignored')
    (mixed/'system/mixed/masked').symlink_to(out/'masked', target_is_directory=True)
    (mixed/'system/mixed/broken').symlink_to('missing')
    env = dict(os.environ, MODULES=str(modules))
    page = bytearray()
    counts = {}
    for module in (white, mixed):
        cap = out/(module.name+'.bin')
        r = subprocess.run([str(out/'cli'), 'module', 'load', str(module)],
                           env=dict(env, CAPTURE=str(cap)), capture_output=True, text=True, check=True)
        (out/(module.name+'.log')).write_text(r.stdout+r.stderr)
        rows = cli.records(cap)
        # Native KPM resolves backing links and rejects a broken source. Supply its successful list.
        rows = [row for row in rows if not row['r'] or Path(row['r']).exists()]
        counts[module.name] = len(rows)
        for row in rows:
            v = row['v'].encode()
            real = str(Path(row['r']).resolve()).encode() if row['r'] else b''
            page += struct.pack('<IIIIIHH', row['flags'], 0, 0, 0, 0, len(v), len(real))+v+real
    assert counts == {'whiteout_only': 1, "mixed' module": 6}, counts
    assert len(page) <= 4068
    (out/'rules.bin').write_bytes(page)
    r = subprocess.run([str(out/'cli'), 'module', 'list', '--json'],
                       env=dict(env, RULE_PAGE=str(out/'rules.bin')), capture_output=True, text=True, check=True)
    data = json.loads(r.stdout)
    (out/'module-list.json').write_text(r.stdout)
    pure = next(m for m in data['mods'] if m['modId']=='whiteout_only')
    assert pure['links'] == [{'virtual':'/system/hidden', 'real':'', 'dir':False}]
    mixed_data = next(m for m in data['mods'] if m['modId']==mixed.name)
    assert next(link for link in mixed_data['links'] if link['virtual'].endswith('/masked')) == {
        'virtual':'/system/mixed/masked', 'real':'', 'dir':False}
    assert not any('/pruned/' in r['virtual'] or '/masked/' in r['virtual'] for r in data['rules'])
    js = cli.build_zip.adapt_webui((cli.ROOT/'nomount/upstream/nomount/module/webroot/index.js').read_text())
    body = js[js.index('async function readModules('):js.index('\nfunction buildModuleCard(')]
    harness = '''const fs=require('node:fs'),assert=require('node:assert/strict');
const data=JSON.parse(fs.readFileSync(process.argv[2])),counts=JSON.parse(process.argv[3]);
const NM_BIN='nm',shellQuote=s=>"'"+s.replace(/'/g,"'\\\\''")+"'";
const exec=async()=>({errno:0,stdout:JSON.stringify(data),stderr:''});
'''+body+'''
(async()=>{
 for(const status of ['status_active','status_loaded','status_inactive','status_disabled','status_skipped']){
  for(const m of data.mods){m.disable=status==='status_loaded'||status==='status_disabled';m.skipMount=status==='status_skipped';}
  if(status==='status_inactive')data.rules=[];
  const result=await readModules();assert.equal(result.length,2);
  for(const m of result){assert.equal(m.statusKey,status);assert.equal(m.fileCount,data.rules.length?counts[m.modId]:0);}
 }
 console.log('PASS production CLI JSON -> generated WebUI: pure whiteout and mixed ownership, five states');
})().catch(e=>{console.error(e);process.exit(1)});
'''
    (out/'webui.js').write_text(harness)
    result = subprocess.run(['node', str(out/'webui.js'), str(out/'module-list.json'), json.dumps(counts)],
                            capture_output=True, text=True, check=True)
    (out/'webui.log').write_text(result.stdout+result.stderr)
    # The module dispatcher must pass through the same protocol probe as rule commands.
    for version in ('22', '23', '24'):
        for action in ('load', 'unload', 'list'):
            cap = out/f'protocol-{version}-{action}.bin'
            r = subprocess.run([str(out/'cli'), 'module', action, str(white)],
                               env=dict(env, VERSION=version, CAPTURE=str(cap)), capture_output=True, text=True)
            assert r.returncode == (1 if version=='24' else 0), (version, action, r.stderr)
            if version=='24':
                assert not cap.exists() and 'v22 or v23 required' in r.stdout
    (out/'receipt.json').write_text(json.dumps({'scope':'Developer host CLI/WebUI with native boundaries stubbed',
        'counts':counts,'states':5,'module_protocol_cases':9,'result':result.stdout.strip()},ensure_ascii=False,indent=2)+'\n')
    print(result.stdout.strip()+'; 9 module protocol cases')


if __name__ == '__main__':
    main()
