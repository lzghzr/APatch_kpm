#!/usr/bin/env python3
"""Check complete ARM64 KPM executable sections, KP imports and optional static layout."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def forbidden(mnemonic, operands):
    return (mnemonic in ('.word', '.inst', '<unknown>')
            or bool(re.search(r'\b(?:[bhsdqvz][0-9]+|p[0-9]+|x18|w18|fpcr|fpsr|ffr)\b', operands)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kpm', type=Path, action='append', required=True)
    parser.add_argument('--layout', type=Path)
    parser.add_argument('--llvm-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / 'tools'))
    import artifact_gate
    for mnemonic, operands in [('fmov', 'd0, x0'), ('ld1', '{v0.16b}, [x0]'), ('ptrue', 'p0.b'),
                               ('mov', 'x18, x0'), ('mrs', 'x0, fpcr'), ('.word', '0')]:
        assert forbidden(mnemonic, operands)
    assert not forbidden('add', 'x0, x1, #8')
    exports = set()
    for path in (root / 'KernelPatch/kernel').rglob('*'):
        if path.suffix in ('.c', '.h', '.S'):
            text = path.read_text(errors='replace')
            exports.update(re.findall(r'KP_EXPORT_SYMBOL\(\s*(\w+)\s*\)', text))
            exports.update('kf_' + name for name in re.findall(r'KP_EXPORT_SYMBOL\(kfunc\((\w+)\)\)', text))
    results = []
    for path in args.kpm:
        info, sections = artifact_gate.inspect_kpm(path)
        imports = sorted(line.split()[-1] for line in subprocess.check_output(
            [str(args.llvm_bin / 'llvm-nm'), '--undefined-only', str(path)], text=True).splitlines() if line.strip())
        assert not (set(imports) - exports), set(imports) - exports
        assembly = subprocess.check_output([str(args.llvm_bin / 'llvm-objdump'), '-d', '--disassemble-zeroes',
                                            '--no-show-raw-insn', str(path)], text=True)
        (args.output / (path.name + '.asm')).write_text(assembly)
        instructions = re.findall(r'^[ \t]*[0-9a-f]+:[ \t]+(\S+)[ \t]*(.*)$', assembly, re.M)
        executable = sum(len(raw) for _, (entry, raw) in sections.items() if entry[2] & 4)
        assert len(instructions) * 4 == executable, (len(instructions), executable)
        bad = [(mnemonic, operands) for mnemonic, operands in instructions if forbidden(mnemonic, operands)]
        assert not bad, bad[:10]
        if info['info'].get('offset_mode') == 'static' and args.layout:
            artifact_gate.inspect_layout(args.layout, info, sections)
        results.append({'artifact': path.name, 'sha256': info['sha256'], 'imports': imports,
                        'instructions': len(instructions), 'executable_bytes': executable,
                        'fp_simd_sve_x18': 0, 'undecoded': 0, 'result': 'PASS'})
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer full executable-section decode and KP export check; not independent audit or device execution',
        'results': results}, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
