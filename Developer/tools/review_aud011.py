#!/usr/bin/env python3
"""Reproduce AUD-011 against the frozen Auditor fix without changing the audited tool or KPMs."""
import ast
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
TOOL_COMMIT = 'e9b64b92fbbdc203ea32f5df78c10e5292c0e3a0'
TOOL = 'Auditor/tools/artifact_audit.py'


def source(ref):
    return subprocess.check_output(['git', '-C', str(ROOT), 'show', ref + ':' + TOOL], text=True)


def main():
    fixed, previous = source(TOOL_COMMIT), source(TOOL_COMMIT + '^')
    tool = {'__file__': str(ROOT / TOOL), '__name__': 'aud011_reviewed_tool'}
    exec(compile(fixed, TOOL, 'exec'), tool)

    def check(text, elf):
        fn = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == 'audit_artifact')
        start = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'reloc_types' for t in n.targets))
        end = next(i for i, n in enumerate(fn.body[start:], start) if isinstance(n, ast.If)
                   and isinstance(n.test, ast.Name) and n.test.id == 'bad_relocs')
        namespace = {'elf': elf, 'facts': {}, 'findings': [], 'AARCH64_RELOC_NAMES': tool['AARCH64_RELOC_NAMES']}
        # Execute the actual frozen audit loop, not a rewritten width algorithm.
        exec(compile(ast.Module(body=fn.body[start:end + 1], type_ignores=[]), TOOL, 'exec'), namespace)
        return namespace['facts']['relocations']

    cases = []
    for kind, width in ((257, 8), (258, 4), (259, 2), (260, 8), (261, 4), (262, 2),
                        (275, 4), (282, 4), (283, 4), (286, 4)):
        for label, offset, want in (('touch_end', 120 - width, 0), ('over_by_one', 121 - width, 1),
                                    ('start_at_end', 120, 1)):
            reloc = dict(type=kind, offset=offset, target_size=120, symidx=0, section='.rela.fixture')
            facts = check(fixed, SimpleNamespace(relocations=[reloc], symbols=[None]))
            assert facts['bad'] == want, (kind, label, facts)
            cases.append(dict(type=kind, width=width, case=label, bad=facts['bad']))

    manifest = json.loads((ROOT / 'Developer/reports/handoffs/zram-zstd-1.3.0-20261106-native-front.json').read_text())
    results = []
    for build in manifest['builds']:
        artifact = build['artifacts'][0]
        elf = tool['Elf'](str(ROOT / artifact['path']))
        old, new = check(previous, elf), check(fixed, elf)
        tail = [r for r in elf.relocations if r['target'] == '.text.zs_kcfi' and r['offset'] == 116]
        assert len(tail) == 1 and tail[0]['type'] == 282 and tail[0]['target_size'] == 120
        assert old['bad'] == 1 and new['bad'] == 0, (old, new)
        results.append(dict(source_commit=build['source_commit'], instance_id=build['instance_id'],
                            declared_artifact_sha256=artifact['sha256'], old_bad=old['bad'], new_bad=new['bad'],
                            tail=tail[0], type282_reported_name=tool['AARCH64_RELOC_NAMES'][282]))
    print(json.dumps(dict(role='Developer review of Auditor tool fix; not module re-audit or device execution',
                          tool_commit=TOOL_COMMIT, boundary_checks=cases, candidates=results), indent=2))


if __name__ == '__main__':
    main()
