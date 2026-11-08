#!/usr/bin/env python3
"""Cross-check frozen DEV-068 mappings against numeric/name pairs from llvm-readelf on the same ELF."""
import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FIX = 'b6a90f3eb55549f99dbe1314e9ef8aea7149e921'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--llvm-readelf', type=Path, required=True)
    p.add_argument('--probe-object', type=Path, required=True)
    a = p.parse_args()
    source = subprocess.check_output(['git', '-C', str(ROOT), 'show', FIX + ':Auditor/tools/artifact_audit.py'], text=True)
    table = next(ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'AARCH64_RELOC_NAMES' for t in n.targets))

    def relocations(path):
        text = subprocess.check_output([str(a.llvm_readelf), '-rW', str(path)], text=True)
        pairs = [(int(info, 16) & 0xffffffff, name) for _, info, name in re.findall(
            r'^\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(R_AARCH64_\S+)', text, re.M)]
        assert pairs, path
        for number, name in pairs:
            assert table.get(number) == name, (path.name, number, table.get(number), name)
        return pairs

    probe = relocations(a.probe_object)
    required = {263, 264, 265, 266, 282, 287, 299, 311, 312, 313, 314}
    assert required == {number for number, _ in probe}
    assert 281 not in table
    manifest = json.loads((ROOT / 'Developer/reports/handoffs/zram-zstd-1.3.0-20261106-native-front.json').read_text())
    candidates = []
    for b in manifest['builds']:
        artifact = b['artifacts'][0]
        pairs = relocations(ROOT / artifact['path'])
        counts = Counter(name for _, name in pairs)
        assert counts['R_AARCH64_JUMP26'] == 47
        assert not any(number in (311, 312, 313) for number, _ in pairs)
        candidates.append(dict(source_commit=b['source_commit'], instance_id=b['instance_id'],
                               declared_artifact_sha256=artifact['sha256'], count=len(pairs),
                               types=dict(sorted(counts.items()))))
    print(json.dumps(dict(scope='Developer independent mapping review via LLVM numeric/name pairs; no Auditor parser used',
                          auditor_fix_commit=FIX, probe_pairs=[dict(number=n, name=s) for n, s in probe],
                          unassigned_281_absent=True, candidates=candidates, result='PASS'), indent=2))


if __name__ == '__main__':
    main()
