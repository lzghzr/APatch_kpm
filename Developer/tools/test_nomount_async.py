#!/usr/bin/env python3
"""Selected async retirement: current production topology plus unchanged rule Oracle."""
import argparse
import json
from pathlib import Path
import sys
import test_nomount_failure_scope as scope
from test_nomount_perf import TOPOLOGY

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--symbols', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    sys.argv = ['scope', '--symbols', str(a.symbols), '--output', str(a.output / 'oracle')]
    scope.main()
    original = (a.output / 'oracle/publication.c').read_text()
    source = original.replace('int main(void)', 'static int original_scope_main(void)', 1)
    # Preserve the complete async tests from the three-path experiment. Its inode/hint
    # assertions remain in test_nomount_perf.py for replay on that frozen candidate.
    helpers, tests = TOPOLOGY.split('int main(void)', 1)
    retirement = tests[tests.index(' const char*p='):]
    retirement = retirement.replace('PASS hints: current snapshot/name/shift/miss; retirement:', 'PASS retirement:')
    source += helpers + 'int main(void) {\n assert(!original_scope_main());fail_stage=0;\n' + retirement
    out = a.output / 'async'
    out.with_suffix('.c').write_text(source)
    scope.execute(['/usr/bin/clang', '-Werror', '-Wno-unused-function', '-Wno-unused-variable',
                   '-I', str(ROOT / 'nomount'), '-fsanitize=address,undefined', '-g',
                   str(out.with_suffix('.c')), '-o', str(out)], out.with_suffix('.compile.log'))
    print(scope.execute([str(out.resolve())], out.with_suffix('.run.log')))
    receipt = {'scope': 'Developer host production topology with native API stubs; no device/performance conclusion',
               'rule_oracle': 'unchanged, PASS', 'async_assertions': 'retained from three-path experiment, PASS',
               'cases': ['reverse completion', 're-add survives old jobs', 'CLEAR', 'allocation failure',
                         'native inline execution', 'synchronous fallback', 'reference balance'],
               'excluded_features': 'inode cache and child hint intentionally withdrawn; original experiment assertions retained'}
    (a.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
