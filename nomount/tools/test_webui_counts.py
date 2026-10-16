#!/usr/bin/env python3
"""执行真实WebUI计数入口，并验证APatch末尾斜杠的启动目录。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from build_zip import adapt_webui

NODE_TEST = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const [originalPath, revisedPath, replayPath] = process.argv.slice(2);
const original = fs.readFileSync(originalPath, 'utf8');
const revised = fs.readFileSync(revisedPath, 'utf8');
const cases = [];

function classes() {
    const values = new Set();
    return {contains: x => values.has(x), add: x => values.add(x), remove: x => values.delete(x), toggle: () => {}};
}
function sandbox(source, rules, modules) {
    const home = {stats: {textContent: ''}};
    const list = {innerHTML: '', addEventListener: () => {}};
    const ctx = vm.createContext({console, Set, Intl, history: {replaceState: () => {}}, matchMedia: () => ({matches: false, addEventListener: () => {}}), getComputedStyle: () => ({getPropertyValue: () => "#6750a4"}), customElements: {define: () => {}}, HTMLElement: class {}, localStorage: {getItem: x => x === 'nm_home_cache' ? '{}' : null, setItem: () => {}}, window: {addEventListener: () => {}}, document: {documentElement: {setAttribute: () => {}, style: {setProperty: () => {}, removeProperty: () => {}}}, addEventListener: () => {}, getElementById: x => x === 'modules-list' ? list : null}, requestAnimationFrame: fn => fn(), fixtureHome: home,
        fixtureExec: async cmd => {
            let stdout = JSON.stringify(rules);
            if (cmd.includes('uname -r')) stdout = ['kernel', 'model', '15', '35', 'v0.5.1', '0.5.1', stdout, 'api'].join('|||');
            else if (cmd.includes('for mod in *')) stdout += '|||\n' + modules.map(x => `${x}|${x}|false|false`).join('\n');
            return {errno: 0, stdout, stderr: ''};
        }});
    vm.runInContext(source, ctx);
    vm.runInContext('exec = fixtureExec; getHomeElements = () => fixtureHome; translations = {modules_injected_count: "{{count}} modules", module_injected_count: "1 module", modules_injected_files: "{{count}} files"};', ctx);
    const start = source.indexOf('const updateModuleCardDOM = async (card, modId) => {');
    const end = source.indexOf("\n\n    document.getElementById('modules-list')", start);
    assert(start > 0 && end > start);
    vm.runInContext(source.slice(start, end).replace('const updateModuleCardDOM', 'globalThis.updateModuleCardDOM'), ctx);
    return {ctx, home, list};
}
async function check(source, rules, modules, expected, label) {
    const {ctx, home, list} = sandbox(source, rules, modules);
    await ctx.loadHome();
    assert.equal(home.stats.textContent, expected === 1 ? '1 module' : `${expected} modules`);
    await ctx.loadModules();
    assert.equal((list.innerHTML.match(/status-active/g) || []).length, expected);
    for (const moduleId of modules) {
        const fields = {'.switch-input': {checked: true}, '.btn-skip-action': {classList: classes()}, '.files-chip': {style: {display: 'none'}}, '.files-count-text': {textContent: ''}, '.status-chip': {textContent: ''}, '.btn-hot-action': {classList: classes(), querySelector: () => ({textContent: ''})}};
        const card = {querySelector: x => fields[x]};
        await ctx.updateModuleCardDOM(card, moduleId);
        assert.equal(fields['.status-chip'].textContent, expected ? 'status_active' : 'status_inactive');
        assert.equal(fields['.files-chip'].style.display, expected ? '' : 'none');
        if (expected) assert.match(fields['.files-count-text'].textContent, /^[1-9][0-9]* files$/);
    }
    cases.push(label);
}
(async () => {
    const modules = ['alpha', 'beta', 'gamma', 'delta'];
    const rules = modules.map(id => ({virtual: `/system/etc/${id}`, real: `/data/adb/modules//${id}/system/etc/${id}`}));
    rules.push({...rules[0], virtual: '/system/etc/another', real: '/data/adb/modules//alpha/system//etc/another'});
    await check(original, rules, modules, 0, 'original three UI entries reproduce zero for four modules');
    await check(original, rules.map(r => ({...r, real: r.real.replace(/\/+/g, '/')})), modules, 4, 'original UI recognizes clean paths');
    await check(revised, rules, modules, 4, 'revised home, module list and card refresh recognize four modules');
    await check(revised, [...rules, {real: '/data/adb/modules/nomount/bin/nm'}, {real: '/tmp/other/source'}, {real: ''}, {real: null}, {}, null], modules, 4, 'self, other sources and absent paths preserve four-module count');
    await check(revised, [], [], 0, 'empty list stays zero');
    await check(revised, [{real: '/data/adb/modules///alpha/system/etc/a'}], ['alpha'], 1, 'one module and repeated separators');
    const ctx = sandbox(revised, [], []).ctx;
    assert.throws(() => vm.runInContext('parseRuleList("invalid json")', ctx));
    cases.push('malformed JSON remains an error');
    if (replayPath) {
        const replay = JSON.parse(fs.readFileSync(replayPath, 'utf8'));
        const ids = [...new Set(replay.map(r => r.real.split('/').filter(Boolean)[3]))];
        assert.equal(ids.length, 4);
        await check(original, replay, ids, 0, 'previously collected rule paths reproduce zero');
        await check(revised, replay, ids, 4, 'previously collected rule paths replay as four modules');
    }
    process.stdout.write(JSON.stringify({cases, result: 'PASS'}) + '\n');
})().catch(e => {console.error(e); process.exitCode = 1;});
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--replay-json', type=Path)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    a.output.mkdir(parents=True, exist_ok=False)
    upstream = (root / 'nomount/nomount/module/webroot/index.js').read_text()
    original = a.output / 'original.js'
    original.write_text(upstream)
    revised = a.output / 'revised.js'
    revised.write_text(adapt_webui(upstream))
    runner = a.output / 'counts.cjs'
    runner.write_text(NODE_TEST)
    subprocess.run(['node', '--check', str(revised)], check=True)
    cmd = ['node', str(runner), str(original), str(revised)]
    if a.replay_json:
        cmd.append(str(a.replay_json))
    node = subprocess.run(cmd, capture_output=True, text=True)
    (a.output / 'node.log').write_text(node.stdout + node.stderr)
    node.check_returncode()
    receipt = json.loads(node.stdout)
    flow = a.output / 'zip-flow'
    subprocess.run(['python3', str(root / 'nomount/tools/test_zip_module.py'), '--output', str(flow)], check=True, capture_output=True)
    # 在原有Oracle生成的宿主夹具上追加一次末尾斜杠回归，不修改旧测试。
    work = (flow / 'boot-ready').resolve()
    mod = work / 'data/adb/modules/nomount'
    log = work / 'calls.jsonl'
    before = len(log.read_text().splitlines())
    env = dict(os.environ, PATH=str(work / 'commands') + ':' + os.environ['PATH'], NM_TEST_LOG=str(log), NM_TEST_MODE='ready', APATCH='true', KSU='false', ARCH='arm64', MODPATH=str(mod), MODULE_DIR=str(work / 'data/adb/modules') + '/')
    result = subprocess.run(['/bin/sh', str(mod / 'metamount.sh')], env=env, capture_output=True, text=True)
    (a.output / 'shell.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    calls = [json.loads(line) for line in log.read_text().splitlines()[before:]]
    sources = [arg for call in calls if call[:2] == ['rule', 'add'] for arg in call if arg.startswith(str(work / 'data/adb/modules'))]
    assert sources and all('//' not in source for source in sources)
    receipt.update(scope='Developer Node VM executes production WebUI; relocated shell/API fixtures; not live Android WebView proof', trailing_module_dir='PASS', original_zip_cases=15,
                   sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in [root/'nomount/tools/build_zip.py', Path(__file__).resolve(), root/'nomount/module/metamount.sh']})
    if a.replay_json:
        receipt['previously_collected_replay'] = {'sha256': hashlib.sha256(a.replay_json.read_bytes()).hexdigest(), 'rules': len(json.loads(a.replay_json.read_text())), 'modules': 4}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print('Production WebUI home/list/card counts and MODULE_DIR trailing slash: PASS')


if __name__ == '__main__':
    main()
