#!/usr/bin/env python3
"""Run the retained hosts contracts and DEV-062 cases against current production C."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def migrate_oracle(original):
    start = original.index('\nstruct open_flags;\n')
    end = original.index('\nint main(void)', start)
    fixture = original[:start] + '\n/* PRODUCTION */\n' + original[end:]
    before = 'assert(set_hosts(""));assert(!strcmp(hosts_target,"/data/adb/hosts/"));'
    after = 'assert(!set_hosts(""));assert(!memcmp(snapshot,hosts_target,64));'
    if fixture.count(before) != 1:
        raise ValueError('expected exactly the authorized empty-name assertion pair')
    return fixture.replace(before, after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, help='optional immutable historical contract.c for exact migration verification')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    tools = module / 'tools'
    fixture = (tools / 'contract_fixture.c').read_text()
    if args.oracle and migrate_oracle(args.oracle.read_text()) != fixture:
        raise ValueError('fixture differs beyond production extraction and the authorized two assertions')
    prelude, original_main = fixture.split('/* PRODUCTION */')
    original_main = original_main.replace('int main(void) {', 'static int original_contract(void) {', 1)
    production = (module / 'hosts_redirect.c').read_text()
    production = re.sub(r'^#include .*\n|^KPM_.*\n', '', production, flags=re.M)
    logger = (tools / 'dev062_fixture.c').read_text()
    added = (tools / 'dev062_tests.c').read_text()
    source = args.output / 'contracts.c'
    source.write_text(prelude + logger + production + original_main + added)
    binary = args.output / 'contracts'
    command = ['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-parameter',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source), '-o', str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    run.check_returncode()
    if run.stderr:
        raise RuntimeError(run.stderr)
    receipt = {
        'scope': 'Developer Tier-3 current production C in host fixtures; not native VFS, concurrent updates or device proof',
        'authorization': '87c8c68', 'authorized_assertions_migrated': 2,
        'historical_assertions_retained': len(re.findall(r'\bassert\s*\(', fixture)),
        'added_assert_sites': len(re.findall(r'\bassert\s*\(', added)),
        'historical_oracle_exactly_checked': bool(args.oracle),
        'old_path_cases': 224, 'old_ctl0_buffer_cases': 56,
        'new_rejected_cases': 380, 'new_valid_name_cases': 9,
        'stdout': run.stdout, 'result': 'PASS',
    }
    (args.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(run.stdout, end='')


if __name__ == '__main__':
    main()
